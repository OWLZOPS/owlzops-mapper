use crate::models::{DatabaseInfo, HostInfo, ProcessInfo};
use std::collections::BinaryHeap;
use std::fs;
use std::path::Path;
use sysinfo::{ProcessStatus, System};

/// Get directory size in MB using `du` with a 10-second timeout.
fn get_dir_size_mb(path: &str) -> u64 {
    if let Some(stdout) = crate::utils::run_with_timeout("du", &["-sm", path], 10)
        && let Some(first_val) = stdout.split_whitespace().next()
    {
        return first_val.parse::<u64>().unwrap_or(0);
    }
    0
}

/// Gather database engine information.
pub fn gather_databases_info() -> Vec<DatabaseInfo> {
    let mut dbs = Vec::new();

    // PostgreSQL
    let pg_ver = if let Some(stdout) = crate::utils::run_with_timeout("psql", &["-V"], 5) {
        stdout.lines().next().unwrap_or("").to_string()
    } else {
        String::new()
    };
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

    // MySQL / MariaDB
    let mysql_ver = if let Some(stdout) = crate::utils::run_with_timeout("mysql", &["-V"], 5) {
        stdout.lines().next().unwrap_or("").to_string()
    } else {
        String::new()
    };
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

    // Redis
    let redis_ver = if let Some(stdout) = crate::utils::run_with_timeout("redis-server", &["-v"], 5)
    {
        stdout.lines().next().unwrap_or("").to_string()
    } else {
        String::new()
    };
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

    // MongoDB
    let mongo_ver =
        if let Some(stdout) = crate::utils::run_with_timeout("mongod", &["--version"], 5) {
            stdout.lines().next().unwrap_or("").to_string()
        } else {
            String::new()
        };
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

/// Retrieve list of failed systemd services with a 10-second timeout.
fn get_failed_systemd_services() -> Vec<String> {
    let out = crate::utils::run_with_timeout(
        "systemctl",
        &["--failed", "--no-pager", "--no-legend", "--plain"],
        10,
    );
    if let Some(text) = out {
        let mut services = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if !parts.is_empty() {
                services.push(parts[0].to_string());
            }
        }
        return services;
    }
    Vec::new()
}

/// Detect backup tools and last Restic snapshot.
fn gather_backup_info(cron_jobs: &[String]) -> (Vec<String>, Option<String>) {
    let mut tools = Vec::new();
    let mut last_restic = None;

    for &tool in &["restic", "borg", "duplicati"] {
        if crate::utils::run_with_timeout("which", &[tool], 2).is_some() {
            tools.push(tool.to_string());
        }
    }

    let backup_in_cron = cron_jobs.iter().any(|job| {
        let l = job.to_lowercase();
        l.contains("restic") || l.contains("borg") || l.contains("rsync") || l.contains("backup")
    });

    if tools.contains(&"restic".to_string())
        && let Some(stdout) = crate::utils::run_with_timeout(
            "restic",
            &["snapshots", "--json", "--last", "1", "--no-cache"],
            5,
        )
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout)
        && let Some(snapshots) = json.as_array()
        && let Some(snap) = snapshots.first()
    {
        last_restic = snap
            .get("time")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());
    }

    if backup_in_cron && tools.is_empty() {
        tools.push("cron (rsync/backup)".to_string());
    }

    (tools, last_restic)
}

/// Determine NTP synchronization status and time offset.
/// Handles containers without systemd gracefully.
fn gather_ntp_info() -> (bool, Option<f64>) {
    let in_container = Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/comm")
            .map(|s| s.trim() != "systemd")
            .unwrap_or(false);

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
            .any(|l| l.contains("Reference ID") && !l.contains("7F000001"));
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

    // No NTP tools available: container → unknown (false), else assume OK
    (!in_container, None)
}

/// Gather comprehensive host information.
pub fn gather_host_info(sys: &mut System, fetch_external_ip: bool) -> HostInfo {
    sys.refresh_all();
    let reboot_required = Path::new("/var/run/reboot-required").exists();

    // External IP
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

    // Open files limit
    let open_files_limit = crate::utils::run_with_timeout("sh", &["-c", "ulimit -n"], 3)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // OOM kills
    let oom_kills = crate::utils::run_with_timeout(
        "sh",
        &["-c", "dmesg 2>/dev/null | grep -i 'killed process' | wc -l"],
        5,
    )
    .map(|s| s.trim().parse::<usize>().unwrap_or(0))
    .unwrap_or(0);

    // Dmesg errors (last 5)
    let dmesg_errors = crate::utils::run_with_timeout(
        "sh",
        &[
            "-c",
            "dmesg -T 2>/dev/null | grep -iE 'error|critical|fail|segfault' | tail -n 5",
        ],
        5,
    )
    .map(|s| {
        s.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    })
    .unwrap_or_default();

    // GPU devices via lspci
    let gpu_devices = crate::utils::run_with_timeout("lspci", &[], 5)
        .map(|s| {
            s.lines()
                .filter(|line| {
                    let lower = line.to_lowercase();
                    (lower.contains("vga") || lower.contains("3d controller"))
                        && (lower.contains("nvidia")
                            || lower.contains("amd")
                            || lower.contains("intel"))
                })
                .filter_map(|line| line.split(": ").nth(1).map(|s| s.trim().to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Running native services (systemd)
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
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                parts.first().map(|n| n.replace(".service", ""))
            })
            .filter(|n| {
                !n.starts_with("systemd-") && !n.starts_with("dbus") && !n.starts_with("polkit")
            })
            .collect()
    })
    .unwrap_or_default();

    // Hosting provider from DMI
    let mut hosting_provider = fs::read_to_string("/sys/class/dmi/id/sys_vendor")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    if (hosting_provider == "unknown" || hosting_provider == "QEMU" || hosting_provider.is_empty())
        && let Ok(product) = fs::read_to_string("/sys/class/dmi/id/product_name")
    {
        hosting_provider = product.trim().to_string();
    }

    // OS install date
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

    // Cron jobs
    let mut cron_jobs = Vec::new();
    if let Ok(crontab) = fs::read_to_string("/etc/crontab") {
        for line in crontab.lines() {
            let l = line.trim();
            if !l.is_empty() && !l.starts_with('#') {
                cron_jobs.push(format!("/etc/crontab: {}", l));
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/var/spool/cron/crontabs") {
        for entry in entries.flatten() {
            let user = entry.file_name().to_string_lossy().to_string();
            if let Ok(contents) = fs::read_to_string(entry.path()) {
                for line in contents.lines() {
                    let l = line.trim();
                    if !l.is_empty() && !l.starts_with('#') {
                        cron_jobs.push(format!("user {}: {}", user, l));
                    }
                }
            }
        }
    }

    // Systemd timers
    let systemd_timers = crate::utils::run_with_timeout(
        "systemctl",
        &["list-timers", "--all", "--no-pager", "--no-legend"],
        10,
    )
    .map(|s| {
        let mut timers: Vec<String> = s
            .lines()
            .flat_map(|line| line.split_whitespace().map(|w| w.to_string()))
            .filter(|w| w.ends_with(".timer"))
            .collect();
        timers.sort();
        timers.dedup();
        timers
    })
    .unwrap_or_default();

    // Security modules
    let mut security_modules = Vec::new();
    if let Ok(lsm) = fs::read_to_string("/sys/kernel/security/lsm") {
        for mod_name in lsm.trim().split(',') {
            let name = mod_name.trim();
            if !name.is_empty() && name != "capability" && name != "yama" {
                security_modules.push(name.to_string());
            }
        }
    }
    if security_modules.is_empty() && Path::new("/sys/fs/selinux").exists() {
        security_modules.push("selinux".to_string());
    }

    // Tech stack detection and top memory processes
    let mut tech_stack = Vec::new();
    let mut found_tech: std::collections::HashSet<&'static str> = std::collections::HashSet::new();

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

    for (pid, proc) in sys.processes() {
        if proc.status() == ProcessStatus::Zombie {
            zombie_processes += 1;
        }

        let name = proc.name().to_lowercase();
        for &(process_name, display_name) in prefix_targets {
            if name.starts_with(process_name) && found_tech.insert(display_name) {
                tech_stack.push(display_name.to_string());
            }
        }
        for &(process_name, display_name) in exact_targets {
            if name == process_name && found_tech.insert(display_name) {
                tech_stack.push(display_name.to_string());
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

    // RabbitMQ detection by directory presence
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

    let load = System::load_average();
    let failed_services = get_failed_systemd_services();
    let (backup_tools, last_restic_snapshot) = gather_backup_info(&cron_jobs);
    let (ntp_synchronized, time_offset_ms) = gather_ntp_info();

    HostInfo {
        hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
        external_ipv4,
        hosting_provider,
        os_install_date,
        os_version: System::long_os_version().unwrap_or_else(|| "unknown".to_string()),
        kernel: System::kernel_version().unwrap_or_else(|| "unknown".to_string()),
        uptime_days: System::uptime() / 86400,
        reboot_required,
        cpu_cores: sys.cpus().len(),
        total_ram_mb: sys.total_memory() / (1024 * 1024),
        swap_total_mb: sys.total_swap() / (1024 * 1024),
        swap_used_mb: sys.used_swap() / (1024 * 1024),
        load_average: (load.one, load.five, load.fifteen),
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
        top_memory_processes: process_list,
        failed_services,
        backup_tools,
        last_restic_snapshot,
        ntp_synchronized,
        time_offset_ms,
    }
}
