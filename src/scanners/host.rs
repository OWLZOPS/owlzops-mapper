use crate::models::{CronJob, CronSeverity, DatabaseInfo, HostInfo, ProcessInfo, ZombieInfo};
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use sysinfo::{ProcessStatus, System};

// ── helpers ────────────────────────────────────────────────

/// Get directory size in MB using `du` with a 60‑second timeout.
fn get_dir_size_mb(path: &str) -> u64 {
    if let Some(stdout) = crate::utils::run_with_timeout("du", &["-sxm", path], 60)
        && let Some(first_val) = stdout.split_whitespace().next()
    {
        return first_val.parse::<u64>().unwrap_or(0);
    }
    0
}

/// Returns `true` when a line looks like a cron environment variable
/// assignment (`NAME=value` with no space), but not a `@reboot`‑like shortcut.
fn is_cron_env(line: &str) -> bool {
    if line.starts_with('@') {
        return false;
    }
    line.contains('=') && !line.contains(' ')
}

// ── Cron classification patterns ──────────────────────────

/// Patterns that indicate a clear compromise (reverse shells, downloads, etc.).
const CRITICAL_CRON_PATTERNS: &[&str] = &[
    "base64 -d",
    "curl ",
    "wget ",
    "nc ",
    "ncat ",
    "bash -c",
    "sh -c",
    "/dev/shm/",
    "/tmp/",
];

/// Patterns that may be legitimate but should be reviewed.
const WARNING_CRON_PATTERNS: &[&str] = &["/home/", "/opt/", "/var/www/"];

/// Determine the severity of a single cron line.
fn classify_cron(command: &str) -> CronSeverity {
    let lower = command.to_lowercase();
    if CRITICAL_CRON_PATTERNS.iter().any(|p| lower.contains(p)) {
        CronSeverity::Critical
    } else if WARNING_CRON_PATTERNS.iter().any(|p| lower.contains(p)) {
        CronSeverity::Warning
    } else {
        CronSeverity::Ok
    }
}

// ── structure for basic OS facts (replaces 12-tuple) ──────
struct SystemBasics {
    hostname: String,
    external_ipv4: String,
    hosting_provider: String,
    os_version: String,
    kernel: String,
    uptime_days: u64,
    cpu_cores: usize,
    total_ram_mb: u64,
    swap_total_mb: u64,
    swap_used_mb: u64,
    load_average: (f64, f64, f64),
    os_install_date: String,
}

// ── database detection (unchanged) ─────────────────────────

pub fn gather_databases_info() -> Vec<DatabaseInfo> {
    let mut dbs = Vec::new();

    let pg_ver = crate::utils::run_with_timeout("psql", &["-V"], 5)
        .map(|s| s.lines().next().unwrap_or("").to_string())
        .unwrap_or_default();
    let pg_dir = "/var/lib/postgresql";
    if !pg_ver.is_empty() || Path::new(pg_dir).exists() {
        dbs.push(DatabaseInfo {
            engine: "PostgreSQL".to_string(),
            version: if pg_ver.is_empty() {
                "Unknown/Inactive".to_string()
            } else {
                pg_ver
            },
            data_dir: pg_dir.to_string(),
            size_mb: get_dir_size_mb(pg_dir),
        });
    }

    let mysql_ver = crate::utils::run_with_timeout("mysql", &["-V"], 5)
        .map(|s| s.lines().next().unwrap_or("").to_string())
        .unwrap_or_default();
    let mysql_dir = "/var/lib/mysql";
    if !mysql_ver.is_empty() || Path::new(mysql_dir).exists() {
        dbs.push(DatabaseInfo {
            engine: "MySQL/MariaDB".to_string(),
            version: if mysql_ver.is_empty() {
                "Unknown/Inactive".to_string()
            } else {
                mysql_ver
            },
            data_dir: mysql_dir.to_string(),
            size_mb: get_dir_size_mb(mysql_dir),
        });
    }

    let redis_ver = crate::utils::run_with_timeout("redis-server", &["-v"], 5)
        .map(|s| s.lines().next().unwrap_or("").to_string())
        .unwrap_or_default();
    let redis_dir = "/var/lib/redis";
    if !redis_ver.is_empty() || Path::new(redis_dir).exists() {
        dbs.push(DatabaseInfo {
            engine: "Redis".to_string(),
            version: if redis_ver.is_empty() {
                "Unknown/Inactive".to_string()
            } else {
                redis_ver
            },
            data_dir: redis_dir.to_string(),
            size_mb: get_dir_size_mb(redis_dir),
        });
    }

    let mongo_ver = crate::utils::run_with_timeout("mongod", &["--version"], 5)
        .map(|s| s.lines().next().unwrap_or("").to_string())
        .unwrap_or_default();
    let mongo_dir = "/var/lib/mongodb";
    if !mongo_ver.is_empty() || Path::new(mongo_dir).exists() {
        dbs.push(DatabaseInfo {
            engine: "MongoDB".to_string(),
            version: if mongo_ver.is_empty() {
                "Unknown/Inactive".to_string()
            } else {
                mongo_ver
            },
            data_dir: mongo_dir.to_string(),
            size_mb: get_dir_size_mb(mongo_dir),
        });
    }

    dbs
}

// ── sub‑collectors for gather_host_info ────────────────────

fn gather_system_basics_values(sys: &System, fetch_external_ip: bool) -> SystemBasics {
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let os_version = System::long_os_version().unwrap_or_else(|| "unknown".to_string());
    let kernel = System::kernel_version().unwrap_or_else(|| "unknown".to_string());
    let uptime_days = System::uptime() / 86400;

    let cpu_cores = sys.cpus().len();
    let total_ram_mb = sys.total_memory() / (1024 * 1024);
    let swap_total_mb = sys.total_swap() / (1024 * 1024);
    let swap_used_mb = sys.used_swap() / (1024 * 1024);
    let load = System::load_average();

    let mut external_ipv4 = "unknown (use --external-ip to detect)".to_string();
    if fetch_external_ip {
        external_ipv4 = "unknown".to_string();
        if let Some(stdout) = crate::utils::run_with_timeout(
            "curl",
            &["-s", "-4", "--max-time", "5", "https://ifconfig.me"],
            6,
        ) {
            let candidate = stdout.trim().to_string();
            if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
                external_ipv4 = candidate;
            }
        }
    }

    let mut hosting_provider = fs::read_to_string("/sys/class/dmi/id/sys_vendor")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    if (hosting_provider == "unknown" || hosting_provider == "QEMU" || hosting_provider.is_empty())
        && let Ok(product) = fs::read_to_string("/sys/class/dmi/id/product_name")
    {
        hosting_provider = product.trim().to_string();
    }

    let mut os_install_date = crate::utils::run_with_timeout("stat", &["-c", "%w", "/"], 3)
        .map(|s| s.trim().to_string())
        .filter(|s| s != "-" && !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    if os_install_date == "unknown" || os_install_date == "-" {
        os_install_date =
            crate::utils::run_with_timeout("stat", &["-c", "%y", "/etc/machine-id"], 3)
                .map(|s| s.trim().to_string())
                .filter(|s| s != "-" && !s.is_empty())
                .unwrap_or_else(|| "unknown".to_string());
    }

    SystemBasics {
        hostname,
        external_ipv4,
        hosting_provider,
        os_version,
        kernel,
        uptime_days,
        cpu_cores,
        total_ram_mb,
        swap_total_mb,
        swap_used_mb,
        load_average: (load.one, load.five, load.fifteen),
        os_install_date,
    }
}

fn gather_process_and_tech(
    sys: &System,
) -> (Vec<ProcessInfo>, usize, Vec<String>, Vec<ZombieInfo>) {
    let prefix_targets: &[(&str, &str)] = &[
        ("dockerd", "Docker"),
        ("docker-proxy", "Docker"),
        ("containerd", "containerd"),
        ("kubelet", "Kubernetes"),
        ("kube-apiserver", "Kubernetes"),
        ("k3s", "K3s"),
        ("k0s", "k0s"),
        ("postgres", "PostgreSQL"),
        ("mysqld", "MySQL"),
        ("redis-server", "Redis"),
        ("mongod", "MongoDB"),
        ("mongos", "MongoDB"),
        ("python", "Python"),
        ("ruby", "Ruby"),
        ("php-fpm", "PHP"),
        ("nginx", "Nginx"),
        ("apache2", "Apache"),
        ("httpd", "Apache"),
        ("etcd", "Etcd"),
        ("memcached", "Memcached"),
    ];
    let exact_targets: &[(&str, &str)] = &[
        ("go", "Go Binary"),
        ("node", "Node.js"),
        ("java", "Java"),
        ("rust", "Rust Binary"),
    ];

    let mut aggregated: HashMap<String, (u64, u32, u32)> = HashMap::new();
    let mut zombie_processes = 0;
    let mut found_tech: HashSet<&'static str> = HashSet::new();
    let mut tech_stack = Vec::new();

    let mut pid_info: HashMap<u32, (String, u32)> = HashMap::new();
    let mut zombie_details: Vec<ZombieInfo> = Vec::new();

    // Get PID of this mapper process to skip its own zombies
    let my_pid = std::process::id() as u32;

    for (pid, proc) in sys.processes() {
        let pid_u32 = pid.as_u32();
        let name = proc.name().to_string();
        let ppid = proc.parent().map_or(0, |p| p.as_u32());
        pid_info.insert(pid_u32, (name.clone(), ppid));

        if proc.status() == ProcessStatus::Zombie {
            // Skip zombies that are children of the mapper itself
            if ppid == my_pid {
                continue;
            }

            zombie_processes += 1;
            if zombie_details.len() < 10 {
                zombie_details.push(ZombieInfo {
                    pid: pid_u32,
                    name: name.clone(),
                    ppid,
                    parent_name: String::new(),
                });
            }
        }

        let name_lower = name.to_ascii_lowercase();
        for &(prefix, display) in prefix_targets {
            if name_lower.starts_with(prefix) && found_tech.insert(display) {
                tech_stack.push(display.to_string());
            }
        }
        for &(exact, display) in exact_targets {
            if name_lower == exact && found_tech.insert(display) {
                tech_stack.push(display.to_string());
            }
        }

        let mem = proc.memory() / (1024 * 1024);
        let entry = aggregated.entry(name.clone()).or_insert((0, pid_u32, 0));
        if mem > entry.0 {
            entry.0 = mem;
            entry.1 = pid_u32;
        }
        entry.2 += 1;
    }

    for z in &mut zombie_details {
        if let Some((parent_name, _)) = pid_info.get(&z.ppid) {
            z.parent_name = parent_name.clone();
        } else {
            z.parent_name = "unknown".to_string();
        }
    }

    if (Path::new("/var/lib/rabbitmq").exists() || Path::new("/etc/rabbitmq").exists())
        && found_tech.insert("RabbitMQ")
    {
        tech_stack.push("RabbitMQ".to_string());
    }
    tech_stack.sort();

    let mut heap: BinaryHeap<std::cmp::Reverse<(u64, u32, String, u32)>> =
        BinaryHeap::with_capacity(6);
    for (name, (max_rss, max_pid, count)) in aggregated {
        heap.push(std::cmp::Reverse((max_rss, max_pid, name, count)));
        if heap.len() > 5 {
            heap.pop();
        }
    }

    let process_list: Vec<ProcessInfo> = heap
        .into_sorted_vec()
        .into_iter()
        .map(|std::cmp::Reverse((mem, pid, name, count))| ProcessInfo {
            name,
            pid,
            memory_mb: mem,
            instances: count,
        })
        .collect();

    (process_list, zombie_processes, tech_stack, zombie_details)
}

// R33-QW-2: `/proc/vmstat` `oom_kill` (kernel ≥ 4.13): exact, monotonic since
// boot. The dmesg grep undercounts once the ring wraps and overcounts on
// kernels that log both the invocation and the kill.
fn parse_oom_kill(vmstat: &str) -> Option<usize> {
    vmstat
        .lines()
        .find_map(|l| l.strip_prefix("oom_kill "))
        .and_then(|n| n.trim().parse().ok())
}

fn oom_kills_from_vmstat() -> Option<usize> {
    let (v, _) = crate::safe_io::read_procfs_capped("/proc/vmstat", 64 * 1024).ok()?;
    parse_oom_kill(&v)
}

/// Ring is log_buf_len (≤ a few MiB), records ~100 B: this bounds memory.
const MAX_KMSG_RECORDS: usize = 32_768;

/// One /dev/kmsg record → "[secs.usec] message". Format:
/// "<prio>,<seq>,<ts_us>,<flags>;<message>\n SUBSYSTEM=…\n DEVICE=…"
fn kmsg_record_to_line(rec: &str) -> Option<String> {
    let (prefix, body) = rec.split_once(';').unwrap_or(("", rec));
    let ts_us: u64 = prefix
        .split(',')
        .nth(2)
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0);
    let msg = body.lines().next()?.trim();
    (!msg.is_empty()).then(|| format!("[{:>5}.{:06}] {msg}", ts_us / 1_000_000, ts_us % 1_000_000))
}

/// The same source dmesg reads. O_NONBLOCK: every read(2) returns exactly one
/// record, EAGAIN at the end, EPIPE when the ring overran our cursor (skip on).
/// Needs CAP_SYSLOG or dmesg_restrict=0 — EACCES goes back to the caller as
/// a coverage fact.
#[cfg(target_os = "linux")]
fn read_kmsg(max_records: usize) -> std::io::Result<Vec<String>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    // CAPPED_IO_OK: kernel character device, record-sized reads, bounded by max_records.
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open("/dev/kmsg")?;
    let mut out = Vec::new();
    // LOG_LINE_MAX + prefix + dictionary; a shorter buffer is refused with EINVAL.
    let mut buf = vec![0u8; 8192];
    while out.len() < max_records {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Some(line) = kmsg_record_to_line(&String::from_utf8_lossy(&buf[..n])) {
                    out.push(line);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}
#[cfg(not(target_os = "linux"))]
fn read_kmsg(_max_records: usize) -> std::io::Result<Vec<String>> {
    Ok(Vec::new())
}

fn gather_kernel_and_hardware() -> (String, usize, Vec<String>, Vec<String>, Vec<String>) {
    let open_files_limit = std::fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Max open files"))
                .and_then(|l| l.split_whitespace().nth(3).map(|s| s.to_string()))
        })
        .unwrap_or_else(|| "unknown".to_string());

    // R33-QW-2: dmesg_errors and the pre-4.13 OOM fallback come from /dev/kmsg,
    // the same source `dmesg` reads, without the exec.
    let kmsg = match read_kmsg(MAX_KMSG_RECORDS) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            crate::coverage::record(
                "/dev/kmsg unreadable (EACCES: dmesg_restrict=1 or no CAP_SYSLOG) — \
                 dmesg_errors NOT collected"
                    .to_string(),
            );
            Vec::new()
        }
        Err(e) => {
            crate::coverage::record(format!(
                "/dev/kmsg unreadable ({}) — dmesg_errors NOT collected",
                e.kind()
            ));
            Vec::new()
        }
    };

    // Exact counter first; the grep is the pre-4.13 fallback only.
    let oom_kills = oom_kills_from_vmstat().unwrap_or_else(|| {
        kmsg.iter()
            .filter(|l| l.to_lowercase().contains("killed process"))
            .count()
    });

    let dmesg_errors: Vec<String> = kmsg
        .iter()
        .map(String::as_str)
        .filter(|l| {
            let lower = l.to_lowercase();
            lower.contains("error")
                || lower.contains("critical")
                || lower.contains("fail")
                || lower.contains("segfault")
        })
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .take(5)
        .rev()
        .collect();

    let gpu_devices = crate::utils::run_with_timeout("lspci", &[], 5)
        .map(|s| {
            s.lines()
                .filter(|l| {
                    let l = l.to_lowercase();
                    (l.contains("vga") || l.contains("3d controller"))
                        && (l.contains("nvidia") || l.contains("amd") || l.contains("intel"))
                })
                .filter_map(|l| l.split(": ").nth(1).map(|s| s.trim().to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut security_modules = Vec::new();
    if let Ok(lsm) = fs::read_to_string("/sys/kernel/security/lsm") {
        for name in lsm.trim().split(',') {
            let name = name.trim();
            if !name.is_empty() && name != "capability" && name != "yama" {
                security_modules.push(name.to_string());
            }
        }
    }
    if security_modules.is_empty() && Path::new("/sys/fs/selinux").exists() {
        security_modules.push("selinux".to_string());
    }

    (
        open_files_limit,
        oom_kills,
        dmesg_errors,
        gpu_devices,
        security_modules,
    )
}

/// Read a host-controlled cron file using the capped regular-file API.
/// Records explicit coverage for truncation, non-regular objects, and I/O errors.
/// Returns `None` if the file should not be parsed.
fn read_cron_source(path: &str, label: &str) -> Option<String> {
    match crate::safe_io::read_file_capped_regular(path, CRON_FILE_CAP) {
        Ok((content, truncated)) => {
            if truncated {
                crate::coverage::record(format!("{label} exceeded cap — cron inventory PARTIAL"));
            }
            Some(content)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            crate::coverage::record(format!(
                "{label} is NOT a regular file (fifo/device) — cron parse refused; \
                 treat as tampering. Persistence audit INCOMPLETE"
            ));
            None
        }
        Err(e) => {
            crate::coverage::record(format!(
                "{label} unreadable ({}) — cron inventory INCOMPLETE",
                e.kind()
            ));
            None
        }
    }
}

/// Cron files are small; 1 MiB is generous and bounds a /dev/zero swap.
const CRON_FILE_CAP: usize = 1024 * 1024;

/// Collects running services, failed services, cron jobs (classified), and systemd timers.
fn gather_services() -> (Vec<String>, Vec<String>, Vec<CronJob>, Vec<String>) {
    // running native services
    let native_services = crate::utils::run_with_timeout(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend",
        ],
        10,
    )
    .map(|s| {
        s.lines()
            .filter_map(|l| {
                l.split_whitespace()
                    .next()
                    .map(|n| n.replace(".service", ""))
            })
            .filter(|n| {
                !n.starts_with("systemd-") && !n.starts_with("dbus") && !n.starts_with("polkit")
            })
            .collect()
    })
    .unwrap_or_default();

    // failed services
    let failed_services = crate::utils::run_with_timeout(
        "systemctl",
        &["--failed", "--no-pager", "--no-legend", "--plain"],
        10,
    )
    .map(|s| {
        s.lines()
            .filter_map(|l| {
                let trimmed = l.trim();
                if trimmed.is_empty() {
                    return None;
                }
                trimmed.split_whitespace().next().map(|s| s.to_string())
            })
            .collect()
    })
    .unwrap_or_default();

    // cron jobs (all sources) – now classified
    let mut raw_lines = Vec::new();

    // R26-37: /etc/crontab is host-controlled; a FIFO here hangs gather_services.
    if let Some(ct) = read_cron_source("/etc/crontab", "/etc/crontab") {
        for l in ct.lines() {
            let l = l.trim();
            if !l.is_empty() && !l.starts_with('#') && !is_cron_env(l) {
                raw_lines.push(format!("/etc/crontab: {}", l));
            }
        }
    }

    if let Ok(dir) = fs::read_dir("/etc/cron.d") {
        for entry in dir.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name() else {
                continue;
            };
            let name = name.to_string_lossy();
            if name.ends_with('~')
                || name.ends_with(".bak")
                || name.ends_with(".rpmnew")
                || name.ends_with(".rpmsave")
            {
                continue;
            }
            let label = format!("/etc/cron.d/{name}");
            if let Some(contents) = read_cron_source(&path.to_string_lossy(), &label) {
                for l in contents.lines() {
                    let l = l.trim();
                    if !l.is_empty() && !l.starts_with('#') && !is_cron_env(l) {
                        raw_lines.push(format!("{label}: {}", l));
                    }
                }
            }
        }
    }

    if let Ok(spool) = fs::read_dir("/var/spool/cron/crontabs") {
        for entry in spool.flatten() {
            let user = entry.file_name().to_string_lossy().to_string();
            let label = format!("/var/spool/cron/crontabs/{user}");
            if let Some(contents) = read_cron_source(&entry.path().to_string_lossy(), &label) {
                for l in contents.lines() {
                    let l = l.trim();
                    if !l.is_empty() && !l.starts_with('#') && !is_cron_env(l) {
                        raw_lines.push(format!("user {}: {}", user, l));
                    }
                }
            }
        }
    }

    if let Ok(spool) = fs::read_dir("/var/spool/cron") {
        for entry in spool.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let user = entry.file_name().to_string_lossy().to_string();
            let label = format!("/var/spool/cron/{user}");
            if let Some(contents) = read_cron_source(&path.to_string_lossy(), &label) {
                for l in contents.lines() {
                    let l = l.trim();
                    if !l.is_empty() && !l.starts_with('#') && !is_cron_env(l) {
                        raw_lines.push(format!("user {}: {}", user, l));
                    }
                }
            }
        }
    }

    if let Some(anacron) = read_cron_source("/etc/anacrontab", "/etc/anacrontab") {
        for l in anacron.lines() {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') || is_cron_env(l) {
                continue;
            }
            raw_lines.push(format!("/etc/anacrontab: {}", l));
        }
    }

    let cron_jobs: Vec<CronJob> = raw_lines
        .into_iter()
        .map(|line| CronJob {
            severity: classify_cron(&line),
            command: line,
        })
        .collect();

    // systemd timers
    let systemd_timers = crate::utils::run_with_timeout(
        "systemctl",
        &["list-timers", "--all", "--no-pager", "--no-legend"],
        10,
    )
    .map(|s| {
        let mut timers: Vec<String> = s
            .lines()
            .flat_map(|l| l.split_whitespace().map(|w| w.to_string()))
            .filter(|w| w.ends_with(".timer"))
            .collect();
        timers.sort();
        timers.dedup();
        timers
    })
    .unwrap_or_default();

    (native_services, failed_services, cron_jobs, systemd_timers)
}

/// Detect backup tools using local evidence only.
/// R26-03/R26-04: previous implementation forked `which` and executed
/// `restic snapshots`/`borg list` under an env_clear() environment, which
/// made successful tool detection structurally impossible. Now we rely on
/// binary resolution via resolve_tool and local configuration/scheduling
/// evidence instead of network or repository access.
fn gather_backup_info(
    cron_jobs: &[CronJob],
    systemd_timers: &[String],
) -> (Vec<String>, Option<String>) {
    let mut tools = Vec::new();

    // R26-25: previous implementation always returned None after repository
    // query removal. Use local cache mtime as activity evidence, not a
    // snapshot confirmation.
    let last_restic = last_backup_run_utc();

    for &tool in &["restic", "borg", "duplicati"] {
        let binary_found = crate::utils::resolve_tool(tool).is_some();
        if !binary_found {
            continue;
        }

        let configured = match tool {
            "restic" => {
                Path::new("/etc/restic").exists()
                    || Path::new("/etc/default/restic").exists()
                    || Path::new("/var/lib/restic").exists()
                    || Path::new("/root/.restic").exists()
            }
            "borg" => {
                Path::new("/etc/borg").exists()
                    || Path::new("/etc/borgmatic").exists()
                    || Path::new("/var/lib/borg").exists()
                    || Path::new("/root/.borg").exists()
            }
            "duplicati" => {
                Path::new("/root/.duplicati").exists()
                    || Path::new("/var/lib/duplicati").exists()
                    || Path::new("/opt/duplicati").exists()
            }
            _ => false,
        };

        let scheduled = cron_jobs.iter().any(|job| {
            let l = job.command.to_lowercase();
            l.contains(tool)
        }) || systemd_timers.iter().any(|t| {
            let l = t.to_lowercase();
            l.contains(tool)
        });

        if configured || scheduled {
            tools.push(tool.to_string());
        } else {
            // Binary present but no evidence of use — record as UNVERIFIED.
            crate::coverage::record(format!(
                "backup: '{tool}' binary present but no unit/timer/cron/config found — \
                 backup posture UNVERIFIED for this tool"
            ));
        }
    }

    // Keep the legacy synthetic markers for scheduled backups that reference
    // backup tools but whose binaries are absent.
    let backup_in_cron = cron_jobs.iter().any(|job| {
        let l = job.command.to_lowercase();
        l.contains("restic") || l.contains("borg") || l.contains("rsync") || l.contains("backup")
    });

    let backup_in_timer = systemd_timers.iter().any(|t| {
        let l = t.to_lowercase();
        l.contains("restic") || l.contains("borg")
    });

    if (backup_in_cron || backup_in_timer) && tools.is_empty() {
        tools.push(
            if backup_in_timer {
                "systemd-timer (restic/borg)"
            } else {
                "cron (rsync/backup)"
            }
            .to_string(),
        );
    }

    (tools, last_restic)
}

/// Freshness from the local cache mtime. Never contacts the repository:
/// a read-only audit must not authenticate to a backup target (R26-25).
fn last_backup_run_utc() -> Option<String> {
    ["/root/.cache/restic", "/root/.cache/borg"]
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok()?.modified().ok())
        .max()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
}

// R33-QW-1: kernel time-sync state. Every NTP client (timesyncd, chrony, ntpd)
// drives the kernel PLL: STA_UNSYNC stays set until the first successful
// sync, `offset` is the residual error. One read-only syscall, no privilege,
// replaces timedatectl ×2 / chronyc / ntpq whose formats differ per distro.
// Constants are local: libc's TIME_*/STA_* coverage differs between gnu and
// musl targets; the ABI values are stable (linux/timex.h).
#[cfg(target_os = "linux")]
const STA_UNSYNC: libc::c_int = 0x0040;
#[cfg(target_os = "linux")]
const STA_NANO: libc::c_int = 0x2000;
#[cfg(target_os = "linux")]
const TIME_ERROR: libc::c_int = 5;

#[cfg(target_os = "linux")]
fn kernel_time_sync() -> Option<(bool, Option<f64>)> {
    // SAFETY: `timex` is plain data; with modes == 0 the kernel only fills it
    // in. The pointer is valid for the duration of the call.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    let state = unsafe { libc::clock_adjtime(libc::CLOCK_REALTIME, &mut tx) };
    if state < 0 {
        return None;
    }
    let synced = state != TIME_ERROR && tx.status & STA_UNSYNC == 0;
    // `offset` is microseconds, or nanoseconds when STA_NANO is set.
    let per_ms = if tx.status & STA_NANO != 0 {
        1_000_000.0
    } else {
        1_000.0
    };
    Some((synced, Some((tx.offset as f64 / per_ms).abs())))
}

#[cfg(not(target_os = "linux"))]
fn kernel_time_sync() -> Option<(bool, Option<f64>)> {
    None
}

fn gather_ntp_info() -> (bool, Option<f64>) {
    match kernel_time_sync() {
        Some(v) => v,
        None => {
            crate::coverage::record(
                "clock_adjtime(2) failed — kernel time-sync state UNKNOWN; \
                 reported as NOT synchronized"
                    .to_string(),
            );
            (false, None)
        }
    }
}

// ── main host info collector ───────────────────────────────

pub fn gather_host_info(sys: &System, fetch_external_ip: bool) -> HostInfo {
    let reboot_required = Path::new("/var/run/reboot-required").exists();
    let mut reboot_required_pkgs = Vec::new();
    if reboot_required {
        // R26-02: host-controlled path MUST use read_file_capped_regular.
        match crate::safe_io::read_file_capped_regular("/var/run/reboot-required.pkgs", 16 * 1024) {
            Ok((content, _truncated)) => {
                let mut seen = std::collections::HashSet::new();
                for line in content.lines() {
                    let pkg = line.trim().to_string();
                    if !pkg.is_empty() && seen.insert(pkg.clone()) {
                        reboot_required_pkgs.push(pkg);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                crate::coverage::record(
                    "/var/run/reboot-required.pkgs is NOT a regular file (fifo/device) — \
                     package list refused; treat as tampering"
                        .to_string(),
                );
            }
            Err(_) => {}
        }
    }

    let basics = gather_system_basics_values(sys, fetch_external_ip);

    let (top_memory_processes, zombie_processes, tech_stack, zombie_details) =
        gather_process_and_tech(sys);

    let (open_files_limit, oom_kills, dmesg_errors, gpu_devices, security_modules) =
        gather_kernel_and_hardware();

    let (native_services, failed_services, cron_jobs, systemd_timers) = gather_services();

    let (backup_tools, last_restic_snapshot) = gather_backup_info(&cron_jobs, &systemd_timers);
    let (ntp_synchronized, time_offset_ms) = gather_ntp_info();

    HostInfo {
        hostname: basics.hostname,
        external_ipv4: basics.external_ipv4,
        hosting_provider: basics.hosting_provider,
        os_install_date: basics.os_install_date,
        os_version: basics.os_version,
        kernel: basics.kernel,
        uptime_days: basics.uptime_days,
        reboot_required,
        cpu_cores: basics.cpu_cores,
        total_ram_mb: basics.total_ram_mb,
        swap_total_mb: basics.swap_total_mb,
        swap_used_mb: basics.swap_used_mb,
        load_average: basics.load_average,
        open_files_limit,
        oom_kills,
        zombie_processes,
        security_modules,
        dmesg_errors,
        gpu_devices,
        native_services,
        cron_jobs,
        systemd_timers,
        tech_stack,
        top_memory_processes,
        failed_services,
        backup_tools,
        last_restic_snapshot,
        ntp_synchronized,
        time_offset_ms,
        reboot_required_pkgs,
        zombie_details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn clock_adjtime_is_readable_without_privilege() {
        // Shape contract only: the value depends on the host.
        let (_synced, offset) = kernel_time_sync().expect("clock_adjtime(modes=0) never fails");
        assert!(offset.is_some_and(|ms| ms >= 0.0));
    }

    #[test]
    fn vmstat_oom_kill_is_parsed_exactly() {
        assert_eq!(
            parse_oom_kill("nr_free_pages 1\noom_kill 7\npgfault 2\n"),
            Some(7)
        );
        assert_eq!(
            parse_oom_kill("oom_kill_x 7\n"),
            None,
            "prefix must be a whole key"
        );
        assert_eq!(parse_oom_kill(""), None);
    }

    #[test]
    fn kmsg_record_keeps_message_and_timestamp() {
        let rec = "6,1234,5000123,-;Out of memory: Killed process 42 (x)\n SUBSYSTEM=mm\n";
        assert_eq!(
            kmsg_record_to_line(rec).as_deref(),
            Some("[    5.000123] Out of memory: Killed process 42 (x)")
        );
        assert_eq!(
            kmsg_record_to_line("6,1,2,-;\n"),
            None,
            "empty message is dropped"
        );
    }
}
