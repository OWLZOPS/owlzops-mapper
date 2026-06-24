use crate::models::{ContainerInfo, DanglingImageInfo, TopologyInfo};
use bollard::Docker;
use bollard::container::ListContainersOptions;
use bollard::image::ListImagesOptions;
use bollard::volume::ListVolumesOptions;
use std::default::Default;
use std::fs;

pub async fn gather_docker_topology() -> TopologyInfo {
    match Docker::connect_with_local_defaults() {
        Ok(docker) => {
            let mut container_list = Vec::new();
            let mut images_count = 0;
            let mut dangling_images_count = 0;
            let mut total_images_size_mb = 0;
            let mut total_dangling_size_mb = 0;
            let mut dangling_images = Vec::new();

            if let Ok(images) = docker
                .list_images(Some(ListImagesOptions::<String> {
                    all: true,
                    ..Default::default()
                }))
                .await
            {
                for img in images {
                    images_count += 1;
                    let size_mb = (img.size / (1024 * 1024)) as u64;
                    total_images_size_mb += size_mb;

                    if img.repo_tags.is_empty()
                        || img.repo_tags.contains(&"<none>:<none>".to_string())
                    {
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
            }
            dangling_images.sort_by_key(|b| std::cmp::Reverse(b.size_mb));

            if let Ok(containers) = docker
                .list_containers(Some(ListContainersOptions::<String> {
                    all: true,
                    size: true,
                    ..Default::default()
                }))
                .await
            {
                for c in containers {
                    let name = c
                        .names
                        .and_then(|mut n| n.pop())
                        .map(|n| n.trim_start_matches('/').to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    let mut ports_vec = Vec::new();
                    if let Some(ports) = c.ports {
                        for p in ports {
                            let public = p
                                .public_port
                                .map(|port| port.to_string())
                                .unwrap_or_default();
                            let private = p.private_port.to_string();
                            let ip = p.ip.unwrap_or_else(|| "".to_string());
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

                    // Use a single inspect call per container: mounts, log_path, and
                    // security-related host config are obtained from the same response,
                    // avoiding extra round trips to the Docker daemon.
                    let mut mounts_vec = Vec::new();
                    let mut log_size_mb = 0;
                    let mut privileged = false;
                    let mut memory_limit_mb = None;
                    let mut cpu_limit = None;
                    let mut cap_add = Vec::new();

                    if let Ok(inspect) = docker.inspect_container(&name, None).await {
                        // Mounts
                        if let Some(mounts) = inspect.mounts {
                            for m in mounts {
                                if let (Some(src), Some(dst)) = (m.source, m.destination) {
                                    mounts_vec.push(format!("{} -> {}", src, dst));
                                }
                            }
                        }
                        // Log size
                        if let Some(log_path) = inspect.log_path
                            && let Ok(meta) = fs::metadata(&log_path)
                        {
                            log_size_mb = meta.len() / (1024 * 1024);
                        }

                        // Docker security checks (collapsed ifs)
                        if let Some(host_config) = inspect.host_config {
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
                            cap_add = host_config.cap_add.unwrap_or_default();
                        }
                    }

                    let size_mb = (c.size_rw.unwrap_or(0) + c.size_root_fs.unwrap_or(0)) as u64
                        / (1024 * 1024);

                    let status = c.status.unwrap_or_else(|| "unknown".to_string());

                    container_list.push(ContainerInfo {
                        name,
                        image: c.image.unwrap_or_else(|| "unknown".to_string()),
                        state: c.state.unwrap_or_else(|| "unknown".to_string()),
                        status,
                        size_mb,
                        log_size_mb,
                        ports: ports_vec,
                        mounts: mounts_vec,
                        privileged,
                        memory_limit_mb,
                        cpu_limit,
                        cap_add,
                    });
                }
            }
            let mut dangling_volumes_count = 0;
            let mut filter = std::collections::HashMap::new();
            filter.insert("dangling".to_string(), vec!["true".to_string()]);
            if let Ok(volumes_resp) = docker
                .list_volumes(Some(ListVolumesOptions { filters: filter }))
                .await
                && let Some(vols) = volumes_resp.volumes
            {
                dangling_volumes_count = vols.len();
            }
            TopologyInfo {
                docker_active: true,
                images_count,
                dangling_images_count,
                total_images_size_mb,
                total_dangling_size_mb,
                dangling_volumes_count,
                dangling_images,
                containers: container_list,
            }
        }
        Err(_) => TopologyInfo {
            docker_active: false,
            images_count: 0,
            dangling_images_count: 0,
            total_images_size_mb: 0,
            total_dangling_size_mb: 0,
            dangling_volumes_count: 0,
            dangling_images: vec![],
            containers: vec![],
        },
    }
}
