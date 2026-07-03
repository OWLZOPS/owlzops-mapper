use crate::models::{DatabaseInfo, HostInfo, ProcessInfo};
use std::collections::{BinaryHeap, HashSet};
use std::fs;
use std::path::Path;
use sysinfo::{ProcessStatus, System};

// ── helpers ────────────────────────────────────────────────

/// Get directory size in MB using `du` with a 10‑second timeout.
fn get_dir_size_mb(path: &str) -> u64 {
    if let Some(stdout) = crate::utils::run_with_timeout("du", &["-sm", path], 10)
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

/// Basic OS / hardware facts that don't require iterating over processes.
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
            let ip = stdout.trim().to_string();
            if !ip.is_empty() {
                external_ipv4 = ip;
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

/// Returns top‑5 memory processes, zombie count, and detected tech stack.
fn gather_process_and_tech(sys: &System) -> (Vec<ProcessInfo>, usize, Vec<String>) {
    let prefix_targets: &[(&str, &str)] = &[
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

    let mut top5: BinaryHeap<std::cmp::Reverse<(u64, u32, String)>> = BinaryHeap::with_capacity(6);
    let mut zombie_processes = 0;
    let mut found_tech: HashSet<&'static str> = HashSet::new();
    let mut tech_stack = Vec::new();

    for (pid, proc) in sys.processes() {
        if proc.status() == ProcessStatus::Zombie {
            zombie_processes += 1;
        }
        let name = proc.name();
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
        top5.push(std::cmp::Reverse((
            mem,
            pid.as_u32(),
            proc.name().to_string(),
        )));
        if top5.len() > 5 {
            top5.pop();
        }
    }

    if (Path::new("/var/lib/rabbitmq").exists() || Path::new("/etc/rabbitmq").exists())
        && found_tech.insert("RabbitMQ")
    {
        tech_stack.push("RabbitMQ".to_string());
    }
    tech_stack.sort();

    let process_list: Vec<ProcessInfo> = top5
        .into_sorted_vec()
        .into_iter()
        .map(|std::cmp::Reverse((mem, pid, name))| ProcessInfo {
            name,
            pid,
            memory_mb: mem,
        })
        .collect();

    (process_list, zombie_processes, tech_stack)
}

/// Reads `/proc/self/limits`, dmesg, lspci, and security modules.
#[allow(clippy::type_complexity)]
fn gather_kernel_and_hardware() -> (String, usize, Vec<String>, Vec<String>, Vec<String>) {
    let open_files_limit = std::fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Max open files"))
                .and_then(|l| l.split_whitespace().nth(3).map(|s| s.to_string()))
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Single dmesg call reused for both OOM kills and error detection
    let dmesg_raw = crate::utils::run_with_timeout("dmesg", &["--ctime"], 5)
        .or_else(|| crate::utils::run_with_timeout("dmesg", &["-T"], 5))
        .unwrap_or_default();

    let oom_kills = dmesg_raw
        .lines()
        .filter(|l| l.to_lowercase().contains("killed process"))
        .count();

    let dmesg_errors: Vec<String> = dmesg_raw
        .lines()
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

/// Collects running services, failed services, cron jobs, and systemd timers.
#[allow(clippy::type_complexity)]
fn gather_services() -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
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

    // cron jobs (all sources)
    let mut cron_jobs = Vec::new();
    if let Ok(ct) = fs::read_to_string("/etc/crontab") {
        for l in ct.lines() {
            let l = l.trim();
            if !l.is_empty() && !l.starts_with('#') && !is_cron_env(l) {
                cron_jobs.push(format!("/etc/crontab: {}", l));
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
            if let Ok(contents) = fs::read_to_string(&path) {
                for l in contents.lines() {
                    let l = l.trim();
                    if !l.is_empty() && !l.starts_with('#') && !is_cron_env(l) {
                        cron_jobs.push(format!("/etc/cron.d/{}: {}", name, l));
                    }
                }
            }
        }
    }
    if let Ok(spool) = fs::read_dir("/var/spool/cron/crontabs") {
        for entry in spool.flatten() {
            let user = entry.file_name().to_string_lossy().to_string();
            if let Ok(contents) = fs::read_to_string(entry.path()) {
                for l in contents.lines() {
                    let l = l.trim();
                    if !l.is_empty() && !l.starts_with('#') && !is_cron_env(l) {
                        cron_jobs.push(format!("user {}: {}", user, l));
                    }
                }
            }
        }
    }
    // RHEL/CentOS/Fedora user crontabs (without 'crontabs' subdirectory)
    if let Ok(spool) = fs::read_dir("/var/spool/cron") {
        for entry in spool.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue; // skip subdirectory crontabs/ (already handled above)
            }
            let user = entry.file_name().to_string_lossy().to_string();
            if let Ok(contents) = fs::read_to_string(&path) {
                for l in contents.lines() {
                    let l = l.trim();
                    if !l.is_empty() && !l.starts_with('#') && !is_cron_env(l) {
                        cron_jobs.push(format!("user {}: {}", user, l));
                    }
                }
            }
        }
    }
    if let Ok(anacron) = fs::read_to_string("/etc/anacrontab") {
        for l in anacron.lines() {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') || is_cron_env(l) {
                continue;
            }
            cron_jobs.push(format!("/etc/anacrontab: {}", l));
        }
    }

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

/// Detect backup tools and last Restic snapshot.
fn gather_backup_info(
    cron_jobs: &[String],
    systemd_timers: &[String],
) -> (Vec<String>, Option<String>) {
    let mut tools = Vec::new();
    let mut last_restic = None;

    for &tool in &["restic", "borg", "duplicati"] {
        let binary_found = crate::utils::run_with_timeout("which", &[tool], 2)
            .map(|stdout| !stdout.trim().is_empty())
            .unwrap_or(false);

        if !binary_found {
            continue;
        }

        let has_data = match tool {
            "restic" => {
                let snapshot_out = crate::utils::run_with_timeout(
                    "restic",
                    &["snapshots", "--no-cache", "--json", "--last", "1"],
                    5,
                );
                let snapshots_val = snapshot_out
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
                let snap_arr = snapshots_val
                    .as_ref()
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.as_slice())
                    .unwrap_or(&[]);

                if !snap_arr.is_empty() {
                    last_restic = snap_arr
                        .first()
                        .and_then(|s| s.get("time"))
                        .and_then(|t| t.as_str())
                        .map(|s| s.to_string());
                }

                !snap_arr.is_empty()
                    || Path::new("/root/.restic").exists()
                    || Path::new("/var/lib/restic").exists()
            }
            "borg" => {
                let has_borg_data = crate::utils::run_with_timeout("borg", &["list", "::"], 5)
                    .map(|stdout| !stdout.trim().is_empty())
                    .unwrap_or(false);

                has_borg_data
                    || Path::new("/root/.borg").exists()
                    || Path::new("/var/lib/borg").exists()
            }
            "duplicati" => ["/root/.duplicati", "/var/lib/duplicati", "/opt/duplicati"]
                .iter()
                .any(|dir| Path::new(dir).exists()),
            _ => false,
        };

        if has_data {
            tools.push(tool.to_string());
        }
    }

    let backup_in_cron = cron_jobs.iter().any(|job| {
        let l = job.to_lowercase();
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

/// Determine NTP synchronization status and time offset.
/// Handles containers without systemd gracefully.
fn gather_ntp_info() -> (bool, Option<f64>) {
    // 1. timedatectl
    if let Some(td_out) = crate::utils::run_with_timeout("timedatectl", &["status"], 5) {
        let synchronized = td_out.lines().any(|l| {
            (l.contains("synchronized:") || l.contains("NTP synchronized:")) && l.contains("yes")
        });
        let mut offset = None;
        for line in td_out.lines() {
            if let Some(rest) = line.strip_prefix("NTP offset:")
                && let Some(ms) = rest.trim().strip_suffix("ms")
                && let Ok(val) = ms.trim().parse::<f64>()
            {
                offset = Some(val.abs());
                break;
            }
        }
        if synchronized {
            return (true, offset);
        }
    }

    // 2. chronyc tracking
    if let Some(chrony_out) = crate::utils::run_with_timeout("chronyc", &["tracking"], 5) {
        let synced = chrony_out
            .lines()
            .find_map(|l| l.strip_prefix("Leap status"))
            .map(|v| v.trim_start_matches(':').trim() == "Normal")
            .unwrap_or(false);
        let mut offset = None;
        for line in chrony_out.lines() {
            if line.contains("System time") {
                offset = line
                    .split_whitespace()
                    .nth(3)
                    .and_then(|s| s.parse::<f64>().ok())
                    .map(|v| v.abs() * 1000.0);
                break;
            }
        }
        return (synced, offset);
    }

    // 3. ntpq
    if let Some(ntpq_out) = crate::utils::run_with_timeout("ntpq", &["-p", "-n"], 5) {
        for line in ntpq_out.lines() {
            if line.starts_with('*') {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 9
                    && let Ok(offset) = cols[8].parse::<f64>()
                {
                    return (true, Some(offset.abs()));
                }
            }
        }
        return (false, None);
    }

    // No NTP tools available: assume unsynchronized (conservative default)
    (false, None)
}

// ── main host info collector ───────────────────────────────

pub fn gather_host_info(sys: &mut System, fetch_external_ip: bool) -> HostInfo {
    sys.refresh_all();
    let reboot_required = Path::new("/var/run/reboot-required").exists();

    let basics = gather_system_basics_values(sys, fetch_external_ip);

    let (top_memory_processes, zombie_processes, tech_stack) = gather_process_and_tech(sys);

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
    }
}
