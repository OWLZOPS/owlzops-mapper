use crate::coverage;
use crate::models::{ContainerInfo, DanglingImageInfo, TopologyInfo};
use bollard::Docker;
use bollard::container::ListContainersOptions;
use bollard::image::ListImagesOptions;
use bollard::volume::ListVolumesOptions;
use std::collections::HashMap;
use std::default::Default;
use std::fs;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing::warn;

// ── Runtime socket identification ───────────────────────────────────────

/// Container-runtime control sockets. Mounting ANY of these into a container is
/// a full host-takeover primitive (it grants the ability to start a privileged
/// container on the host), not merely a "sensitive path". containerd/CRI-O are
/// included even though we cannot *scan* them (gRPC): classification is
/// independent of whether we can talk to the runtime.
const RUNTIME_SOCKET_PATHS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/podman/podman.sock",
    "/var/run/podman/podman.sock",
    "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/var/run/crio/crio.sock",
];

fn is_runtime_socket(source: &str) -> bool {
    RUNTIME_SOCKET_PATHS.contains(&source)
        // Rootless Podman lives under a per-UID runtime dir:
        // /run/user/<uid>/podman/podman.sock
        || source.ends_with("/podman/podman.sock")
}

/// Classify a host-side bind-mount source into a sensitive-mount label, if any.
/// `writable`: from inspect Mount.rw (defaults to true = conservative when unknown).
fn classify_mount(source: &str, writable: bool) -> Option<String> {
    // The label is kept as the historical wire constant `DOCKER_SOCKET` so that
    // scoring.rs, existing snapshots and drift comparisons stay stable. It means
    // "container runtime control socket", regardless of which runtime.
    if is_runtime_socket(source) {
        return Some("DOCKER_SOCKET".to_string());
    }
    if source == "/" {
        return Some("HOST_ROOT".to_string());
    }
    const SENSITIVE: &[&str] = &[
        "/etc",
        "/root",
        "/boot",
        "/proc",
        "/sys",
        "/var/run",
        "/run",
        "/var/lib/docker",
        "/var/lib/containers", // Podman / CRI-O rootful image + layer store
        "/var/lib/containerd",
    ];
    // Zero-alloc prefix test. Rootless Podman/Buildah store lives under $HOME,
    // so no absolute prefix works — we scan for the distinctive path component.
    let hit = SENSITIVE
        .iter()
        .copied()
        .find(|p| source == *p || source.strip_prefix(p).is_some_and(|r| r.starts_with('/')))
        .or_else(|| {
            source
                .contains("/.local/share/containers")
                .then_some("~/.local/share/containers")
        })?;
    if writable {
        Some(format!("{hit} (rw)"))
    } else {
        Some(format!("{hit} (ro)"))
    }
}

/// Detect active container runtime by probing well‑known Unix sockets.
/// Supports Docker and Podman (both speak the Docker Engine API).
/// Containerd/CRI‑O sockets are deliberately skipped – they require gRPC.
pub async fn gather_runtime_topology() -> TopologyInfo {
    let mut endpoints: Vec<(&str, String)> = vec![
        ("Docker", "/var/run/docker.sock".to_string()),
        ("Podman", "/run/podman/podman.sock".to_string()),
    ];
    // Rootless Podman: socket lives in a per-UID runtime dir. Enumerate instead
    // of guessing the UID (XDG_RUNTIME_DIR is cleared by sudo's env_reset).
    if let Ok(entries) = fs::read_dir("/run/user") {
        for e in entries.flatten() {
            let p = e.path().join("podman/podman.sock");
            if p.exists()
                && let Some(s) = p.to_str()
            {
                endpoints.push(("Podman (rootless)", s.to_string()));
            }
        }
    }

    let mut active_client = None;
    let mut runtime_name = String::new();
    let mut also_live: Vec<&str> = Vec::new();

    for (name, path) in &endpoints {
        if !std::path::Path::new(path).exists() {
            continue; // socket absent → runtime genuinely not installed, not a gap
        }
        let client = match Docker::connect_with_unix(path, 120, bollard::API_DEFAULT_VERSION) {
            Ok(c) => c,
            Err(e) => {
                coverage::record(format!(
                    "runtime: {name} socket {path} present but unusable ({e}) — \
                     container audit (DOCK-*) SKIPPED for this runtime"
                ));
                continue;
            }
        };
        // Explicit deadline: bollard's own 120 s would stall the whole host scan
        // on a wedged daemon, and we now probe more than one endpoint.
        match tokio::time::timeout(Duration::from_secs(5), client.ping()).await {
            Ok(Ok(_)) => {
                if active_client.is_none() {
                    runtime_name = name.to_string();
                    active_client = Some(client);
                } else {
                    also_live.push(name);
                }
            }
            Ok(Err(e)) => coverage::record(format!(
                "runtime: {name} socket {path} exists but ping failed ({e}) — likely \
                 EACCES (non-root scan) or dead daemon; container audit SKIPPED"
            )),
            Err(_) => coverage::record(format!(
                "runtime: {name} ping on {path} timed out after 5s — daemon wedged; \
                 container audit SKIPPED"
            )),
        }
    }

    // Raw Truth: a second live runtime is real state, not noise.
    if !also_live.is_empty() {
        coverage::record(format!(
            "runtime: {} additional live runtime(s) NOT audited ({}) — only {runtime_name} \
             was scanned; containers under the others are absent from this report",
            also_live.len(),
            also_live.join(", ")
        ));
    }

    let docker = match active_client {
        Some(d) => d,
        None => {
            return TopologyInfo {
                runtime_active: false,
                runtime_name: String::new(),
                ..Default::default()
            };
        }
    };

    let mut container_list = Vec::new();
    let mut images_count = 0;
    let mut dangling_images_count = 0;
    let mut total_images_size_mb = 0;
    let mut total_dangling_size_mb = 0;
    let mut dangling_images = Vec::new();

    // list_images with 10s timeout
    let images_result = tokio::time::timeout(
        Duration::from_secs(10),
        docker.list_images(Some(ListImagesOptions::<String> {
            all: true,
            ..Default::default()
        })),
    )
    .await;

    if let Ok(Ok(images)) = images_result {
        for img in images {
            images_count += 1;

            let size_mb = (img.size.max(0) / (1024 * 1024)) as u64;

            total_images_size_mb += size_mb;

            if img.repo_tags.is_empty() || img.repo_tags.contains(&"<none>:<none>".to_string()) {
                dangling_images_count += 1;
                total_dangling_size_mb += size_mb;
                let raw_id = img.id.replace("sha256:", "");
                let short_id = if raw_id.len() > 12 {
                    raw_id[..12].to_string()
                } else {
                    raw_id
                };
                dangling_images.push(DanglingImageInfo {
                    id: short_id,
                    size_mb,
                });
            }
        }
    } else {
        warn!("{} list_images timed out or failed", runtime_name);
    }

    dangling_images.sort_by_key(|b| std::cmp::Reverse(b.size_mb));

    // list_containers with 10s timeout
    let containers_result = tokio::time::timeout(
        Duration::from_secs(10),
        docker.list_containers(Some(ListContainersOptions::<String> {
            all: true,
            size: true,
            ..Default::default()
        })),
    )
    .await;

    let containers = match containers_result {
        Ok(Ok(ctrs)) => ctrs,
        _ => {
            warn!("{} list_containers timed out or failed", runtime_name);
            vec![]
        }
    };

    if !containers.is_empty() {
        // Spawn inspect tasks with individual 5s timeouts
        let mut join_set: JoinSet<(
            bollard::models::ContainerSummary,
            Option<bollard::models::ContainerInspectResponse>,
        )> = JoinSet::new();

        for c in &containers {
            if let Some(id) = c.id.as_deref() {
                let docker = docker.clone();
                let id = id.to_string();
                let c = c.clone();
                join_set.spawn(async move {
                    let inspect = tokio::time::timeout(
                        Duration::from_secs(5),
                        docker.inspect_container(&id, None),
                    )
                    .await
                    .ok()
                    .and_then(|r| r.ok());
                    (c, inspect)
                });
            }
        }

        // Gather results with warnings for failures
        let mut inspects: HashMap<String, _> = HashMap::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((c, Some(inspect))) => {
                    let id = c.id.clone().unwrap_or_default();
                    inspects.insert(id, (c, inspect));
                }
                Ok((c, None)) => {
                    let name = c
                        .names
                        .as_ref()
                        .and_then(|n| n.first())
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    warn!(
                        container = name,
                        "{} inspect returned no data", runtime_name
                    );
                }
                Err(e) => {
                    warn!(error = %e, "{} inspect task failed", runtime_name);
                }
            }
        }

        // Consume inspects to avoid cloning
        for (_, (container, inspect)) in inspects {
            let name = container
                .names
                .map(|mut n| {
                    n.pop()
                        .map(|s| s.trim_start_matches('/').to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .unwrap_or_else(|| "unknown".to_string());

            // ports
            let mut ports_vec = Vec::new();
            if let Some(ports) = &container.ports {
                for p in ports {
                    let public = p.public_port.map(|pp| pp.to_string()).unwrap_or_default();
                    let private = p.private_port.to_string();
                    let ip = p.ip.clone().unwrap_or_default();
                    let typ = p
                        .typ
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "tcp".to_string());
                    if !public.is_empty() && !ip.is_empty() {
                        ports_vec.push(format!("{}:{}->{}/{}", ip, public, private, typ));
                    } else {
                        ports_vec.push(format!("{}/{}", private, typ));
                    }
                }
            }

            // Mounts, log size, security checks
            let mut mounts_vec = Vec::new();
            let mut sensitive_mounts = Vec::new();
            let mut log_size_mb = 0;
            let mut privileged = false;
            let mut memory_limit_mb = None;
            let mut cpu_limit = None;
            let mut cap_add = Vec::new();

            if let Some(mounts) = &inspect.mounts {
                for m in mounts {
                    if let (Some(src), Some(dst)) = (m.source.clone(), m.destination.clone()) {
                        mounts_vec.push(format!("{} -> {}", src, dst));
                        let writable = m.rw.unwrap_or(true);
                        if let Some(label) = classify_mount(&src, writable) {
                            sensitive_mounts.push(label);
                        }
                    }
                }
            }
            if let Some(log_path) = &inspect.log_path
                && let Ok(meta) = fs::metadata(log_path)
            {
                log_size_mb = meta.len() / (1024 * 1024);
            }
            if let Some(host_config) = &inspect.host_config {
                privileged = host_config.privileged.unwrap_or(false);
                if let Some(mem) = host_config.memory
                    && mem > 0
                {
                    memory_limit_mb = Some((mem / 1024 / 1024) as u64);
                }
                if let Some(quota) = host_config.cpu_quota
                    && quota > 0
                {
                    let period = host_config.cpu_period.unwrap_or(100_000);
                    cpu_limit = Some(quota as f64 / period as f64);
                }
                cap_add = host_config.cap_add.clone().unwrap_or_default();
            }

            // --- Reliability signals (new) ---
            let restart_count = inspect
                .restart_count
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(0);

            let (oom_killed, health_status) = inspect
                .state
                .as_ref()
                .map(|s| {
                    use bollard::models::HealthStatusEnum as H;
                    let oom = s.oom_killed.unwrap_or(false);
                    let health = s.health.as_ref().and_then(|h| match h.status {
                        Some(H::STARTING) => Some("starting".to_string()),
                        Some(H::HEALTHY) => Some("healthy".to_string()),
                        Some(H::UNHEALTHY) => Some("unhealthy".to_string()),
                        _ => None, // NONE / EMPTY / absent → healthcheck not configured
                    });
                    (oom, health)
                })
                .unwrap_or((false, None));

            // --- Runtime ground truth for DOCK-010 ---
            let runtime_bounding_caps = inspect
                .state
                .as_ref()
                .and_then(|s| s.pid)
                .filter(|&pid| pid > 0)
                .and_then(|pid| {
                    let path = format!("/proc/{pid}/status");
                    crate::safe_io::read_file_capped(&path, 16 * 1024)
                        .ok()
                        .and_then(|(content, _)| {
                            crate::scanners::capabilities::parse_status(&content)
                        })
                        .map(|st| st.caps.bounding)
                });

            let rw_size_mb = (container.size_rw.unwrap_or(0).max(0) as u64) / (1024 * 1024);
            let size_mb = (container.size_rw.unwrap_or(0) + container.size_root_fs.unwrap_or(0))
                as u64
                / (1024 * 1024);
            let status = container.status.unwrap_or_else(|| "unknown".to_string());

            container_list.push(ContainerInfo {
                name,
                image: container.image.unwrap_or_else(|| "unknown".to_string()),
                state: container.state.unwrap_or_else(|| "unknown".to_string()),
                status,
                size_mb,
                log_size_mb,
                ports: ports_vec,
                mounts: mounts_vec,
                privileged,
                memory_limit_mb,
                cpu_limit,
                cap_add,
                restart_count,
                oom_killed,
                health_status,
                sensitive_mounts,
                rw_size_mb,
                runtime_bounding_caps,
            });
        }
    }

    // Deterministic order for report stability
    container_list.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    let mut dangling_volumes_count = 0;
    let mut filter = HashMap::new();
    filter.insert("dangling".to_string(), vec!["true".to_string()]);
    if let Ok(Ok(volumes_resp)) = tokio::time::timeout(
        Duration::from_secs(10),
        docker.list_volumes(Some(ListVolumesOptions { filters: filter })),
    )
    .await
        && let Some(vols) = volumes_resp.volumes
    {
        dangling_volumes_count = vols.len();
    }

    // Fetch reclaimable space via system_info_df
    let mut images_reclaimable_mb = 0u64;
    let mut build_cache_reclaimable_mb = 0u64;

    if let Ok(Ok(df)) = tokio::time::timeout(Duration::from_secs(10), docker.df()).await {
        if let Some(layers) = df.layers_size {
            total_images_size_mb = (layers.max(0) / (1024 * 1024)) as u64;
        }

        if let Some(images) = df.images {
            let mut reclaim_bytes = 0i64;
            for img in images {
                if img.containers == 0 {
                    reclaim_bytes += img.size.max(0).saturating_sub(img.shared_size.max(0));
                }
            }
            images_reclaimable_mb = (reclaim_bytes / (1024 * 1024)) as u64;
        }

        if let Some(build_cache) = df.build_cache {
            let mut reclaim_bytes = 0i64;
            for cache in build_cache {
                if cache.in_use == Some(false) {
                    reclaim_bytes += cache.size.unwrap_or(0);
                }
            }
            build_cache_reclaimable_mb = (reclaim_bytes / (1024 * 1024)) as u64;
        }
    }

    TopologyInfo {
        runtime_active: true,
        runtime_name,
        images_count,
        dangling_images_count,
        total_images_size_mb,
        total_dangling_size_mb,
        dangling_volumes_count,
        dangling_images,
        containers: container_list,
        images_reclaimable_mb,
        build_cache_reclaimable_mb,
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;

    #[test]
    fn podman_socket_is_a_takeover_primitive_not_a_sensitive_path() {
        for p in [
            "/run/podman/podman.sock",
            "/run/user/1000/podman/podman.sock",
            "/run/containerd/containerd.sock",
            "/var/run/crio/crio.sock",
        ] {
            assert_eq!(
                classify_mount(p, true).as_deref(),
                Some("DOCKER_SOCKET"),
                "{p} must classify as a runtime control socket"
            );
        }
    }

    #[test]
    fn docker_socket_classification_unchanged() {
        assert_eq!(
            classify_mount("/var/run/docker.sock", true).as_deref(),
            Some("DOCKER_SOCKET")
        );
        assert_eq!(
            classify_mount("/run/docker.sock", false).as_deref(),
            Some("DOCKER_SOCKET")
        );
        assert_eq!(classify_mount("/", true).as_deref(), Some("HOST_ROOT"));
    }

    #[test]
    fn podman_and_containerd_stores_are_sensitive() {
        assert_eq!(
            classify_mount("/var/lib/containers/storage", true).as_deref(),
            Some("/var/lib/containers (rw)")
        );
        assert_eq!(
            classify_mount("/var/lib/containerd", false).as_deref(),
            Some("/var/lib/containerd (ro)")
        );
        assert_eq!(
            classify_mount("/home/dev/.local/share/containers/storage", true).as_deref(),
            Some("~/.local/share/containers (rw)")
        );
    }

    #[test]
    fn prefix_match_does_not_overreach() {
        assert!(classify_mount("/etcetera", true).is_none());
        assert!(classify_mount("/var/lib/dockerfiles", true).is_none());
        assert_eq!(
            classify_mount("/etc/passwd", false).as_deref(),
            Some("/etc (ro)")
        );
    }
}
