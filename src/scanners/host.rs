use crate::models::{DatabaseInfo, HostInfo, ProcessInfo};
use std::collections::BinaryHeap;
use std::fs;
use std::process::Command;
use sysinfo::{ProcessStatus, System};

fn get_dir_size_mb(path: &str) -> u64 {
    if let Ok(output) = Command::new("timeout")
        .args(["10s", "du", "-sm", path])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(first_val) = stdout.split_whitespace().next() {
            return first_val.parse::<u64>().unwrap_or(0);
        }
    }
    0
}

pub fn gather_databases_info() -> Vec<DatabaseInfo> {
    let mut dbs = Vec::new();

    let mut pg_ver = String::new();
    if let Ok(out) = Command::new("psql").arg("-V").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        if s.contains("PostgreSQL") {
            pg_ver = s.lines().next().unwrap_or("").to_string();
        }
    }
    let pg_dir = "/var/lib/postgresql";
    if !pg_ver.is_empty() || std::path::Path::new(pg_dir).exists() {
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

    let mut mysql_ver = String::new();
    if let Ok(out) = Command::new("mysql").arg("-V").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        if s.contains("Ver") {
            mysql_ver = s.lines().next().unwrap_or("").to_string();
        }
    }
    let mysql_dir = "/var/lib/mysql";
    if !mysql_ver.is_empty() || std::path::Path::new(mysql_dir).exists() {
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

    let mut redis_ver = String::new();
    if let Ok(out) = Command::new("redis-server").arg("-v").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        if s.contains("Redis") {
            redis_ver = s.lines().next().unwrap_or("").to_string();
        }
    }
    let redis_dir = "/var/lib/redis";
    if !redis_ver.is_empty() || std::path::Path::new(redis_dir).exists() {
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

    let mut mongo_ver = String::new();
    if let Ok(out) = Command::new("mongod").arg("--version").output() {
        let s = String::from_utf8_lossy(&out.stdout);
        if s.contains("db version") {
            mongo_ver = s.lines().next().unwrap_or("").to_string();
        }
    }
    let mongo_dir = "/var/lib/mongodb";
    if !mongo_ver.is_empty() || std::path::Path::new(mongo_dir).exists() {
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

fn get_failed_systemd_services() -> Vec<String> {
    let output = Command::new("systemctl")
        .args(["--failed", "--no-pager", "--no-legend", "--plain"])
        .output();
    if let Ok(out) = output
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
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

fn gather_backup_info(cron_jobs: &[String]) -> (Vec<String>, Option<String>) {
    let mut tools = Vec::new();
    let mut last_restic = None;

    for &tool in &["restic", "borg", "duplicati"] {
        if Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            tools.push(tool.to_string());
        }
    }

    let backup_in_cron = cron_jobs.iter().any(|job| {
        let l = job.to_lowercase();
        l.contains("restic") || l.contains("borg") || l.contains("rsync") || l.contains("backup")
    });

    if tools.contains(&"restic".to_string())
        && let Ok(output) = Command::new("timeout")
            .args([
                "5s",
                "restic",
                "snapshots",
                "--json",
                "--last",
                "1",
                "--no-cache",
            ])
            .output()
        && output.status.success()
        && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
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

fn gather_ntp_info() -> (bool, Option<f64>) {
    let Ok(td_out) = Command::new("timedatectl").arg("status").output() else {
        return (true, None);
    };
    if !td_out.status.success() {
        return (true, None);
    }

    let text = String::from_utf8_lossy(&td_out.stdout);
    let synchronized = text.lines().any(|l| {
        (l.contains("synchronized:") || l.contains("NTP synchronized:")) && l.contains("yes")
    });

    if let Ok(out) = Command::new("chronyc").arg("tracking").output()
        && out.status.success()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if line.contains("System time")
                && let Some(after) = line.split_once(':').map(|x| x.1)
                && let Some(num_str) = after.split_whitespace().next()
                && let Ok(secs) = num_str.parse::<f64>()
            {
                return (synchronized, Some(secs.abs() * 1000.0));
            }
        }
    }

    if let Ok(out) = Command::new("ntpq").args(["-p", "-n"]).output()
        && out.status.success()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if line.starts_with('*') {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 9
                    && let Ok(offset_ms) = cols[8].parse::<f64>()
                {
                    return (synchronized, Some(offset_ms.abs()));
                }
            }
        }
    }

    (synchronized, None)
}

pub fn gather_host_info(sys: &mut System, fetch_external_ip: bool) -> HostInfo {
    sys.refresh_all();
    let reboot_required = std::path::Path::new("/var/run/reboot-required").exists();

    let mut external_ipv4 = "unknown (use --external-ip to detect)".to_string();
    if fetch_external_ip {
        external_ipv4 = "unknown".to_string();
        if let Ok(output) = Command::new("curl")
            .args(["-s", "-4", "--max-time", "5", "https://ifconfig.me"])
            .output()
        {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !ip.is_empty() {
                external_ipv4 = ip;
            }
        }
    }

    let mut open_files_limit = "unknown".to_string();
    if let Ok(output) = Command::new("sh").arg("-c").arg("ulimit -n").output() {
        let limit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !limit.is_empty() {
            open_files_limit = limit;
        }
    }

    let mut oom_kills = 0;
    if let Ok(output) = Command::new("sh")
        .arg("-c")
        .arg("dmesg 2>/dev/null | grep -i 'killed process' | wc -l")
        .output()
    {
        oom_kills = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<usize>()
            .unwrap_or(0);
    }

    let mut dmesg_errors = Vec::new();
    if let Ok(output) = Command::new("sh")
        .arg("-c")
        .arg("dmesg -T 2>/dev/null | grep -iE 'error|critical|fail|segfault' | tail -n 5")
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let clean = line.trim();
            if !clean.is_empty() {
                dmesg_errors.push(clean.to_string());
            }
        }
    }

    let mut gpu_devices = Vec::new();
    if let Ok(output) = Command::new("lspci").output() {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let lower = line.to_lowercase();
            if (lower.contains("vga") || lower.contains("3d controller"))
                && (lower.contains("nvidia") || lower.contains("amd") || lower.contains("intel"))
            {
                let parts: Vec<&str> = line.split(": ").collect();
                if parts.len() > 1 {
                    gpu_devices.push(parts[1].trim().to_string());
                }
            }
        }
    }

    let mut native_services = Vec::new();
    if let Ok(output) = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend",
        ])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let s_name = parts[0].replace(".service", "");
                if !s_name.starts_with("systemd-")
                    && !s_name.starts_with("dbus")
                    && !s_name.starts_with("polkit")
                {
                    native_services.push(s_name);
                }
            }
        }
    }

    let mut hosting_provider = "unknown".to_string();
    if let Ok(vendor) = fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
        hosting_provider = vendor.trim().to_string();
    }
    if (hosting_provider == "unknown" || hosting_provider == "QEMU" || hosting_provider.is_empty())
        && let Ok(product) = fs::read_to_string("/sys/class/dmi/id/product_name")
    {
        hosting_provider = product.trim().to_string();
    }

    let mut os_install_date = "unknown".to_string();
    if let Ok(output) = Command::new("stat").arg("-c").arg("%w").arg("/").output() {
        let date = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !date.is_empty() && date != "-" {
            os_install_date = date;
        }
    }
    if (os_install_date == "unknown" || os_install_date == "-")
        && let Ok(output) = Command::new("stat")
            .arg("-c")
            .arg("%y")
            .arg("/etc/machine-id")
            .output()
    {
        let date = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !date.is_empty() && date != "-" {
            os_install_date = date;
        }
    }

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

    let mut systemd_timers = Vec::new();
    if let Ok(output) = Command::new("systemctl")
        .args(["list-timers", "--all", "--no-pager", "--no-legend"])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            for p in line.split_whitespace() {
                if p.ends_with(".timer") {
                    systemd_timers.push(p.to_string());
                }
            }
        }
    }
    systemd_timers.sort();
    systemd_timers.dedup();

    let mut security_modules = Vec::new();
    if let Ok(lsm) = fs::read_to_string("/sys/kernel/security/lsm") {
        for mod_name in lsm.trim().split(',') {
            if !mod_name.is_empty() && mod_name != "capability" && mod_name != "yama" {
                security_modules.push(mod_name.to_string());
            }
        }
    }
    if security_modules.is_empty() && std::path::Path::new("/sys/fs/selinux").exists() {
        security_modules.push("selinux".to_string());
    }

    // -----------------------------------------------------------------
    // Tech stack detection with precise matching
    // -----------------------------------------------------------------
    let mut tech_stack = Vec::new();

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

    // H-7: use BinaryHeap for top-5 memory consumers
    let mut top5: BinaryHeap<std::cmp::Reverse<(u64, u32, String)>> = BinaryHeap::with_capacity(6);
    let mut zombie_processes = 0;

    for (pid, proc) in sys.processes() {
        if proc.status() == ProcessStatus::Zombie {
            zombie_processes += 1;
        }

        let name = proc.name().to_lowercase();
        for &(process_name, display_name) in prefix_targets {
            if name.starts_with(process_name) && !tech_stack.contains(&display_name.to_string()) {
                tech_stack.push(display_name.to_string());
            }
        }
        for &(process_name, display_name) in exact_targets {
            if name == process_name && !tech_stack.contains(&display_name.to_string()) {
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

    let process_list: Vec<ProcessInfo> = top5
        .into_sorted_vec()
        .into_iter()
        .map(|std::cmp::Reverse((mem, pid, name))| ProcessInfo {
            name,
            pid,
            memory_mb: mem,
        })
        .collect();

    // RabbitMQ runs under beam.smp; detect by known data directory
    if (std::path::Path::new("/var/lib/rabbitmq").exists()
        || std::path::Path::new("/etc/rabbitmq").exists())
        && !tech_stack.contains(&"RabbitMQ".to_string())
    {
        tech_stack.push("RabbitMQ".to_string());
    }

    tech_stack.sort();

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
