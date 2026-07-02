# owlzops-mapper JSON schema reference
This document describes every field in the `AgentReport` JSON structure.
Use it to build integrations, dashboards, or alerting rules.

---

## Top-level

| Field | Type | Description |
|-------|------|-------------|
| `scan_id` | string | UUID v4 unique per scan |
| `timestamp` | string | ISO-8601 timestamp (UTC) |
| `version` | string | owlzops-mapper version |
| `duration_secs` | float | Wall-clock time of the scan |
| `risk_score` | integer | 0–100 calculated risk |
| `is_root_execution` | boolean | Whether the scan ran as root |

---

## `host`

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | Hostname of the scanned machine |
| `external_ipv4` | string | Public IP (or "unknown") |
| `hosting_provider` | string | Provider from DMI (or "unknown") |
| `os_install_date` | string | Date OS was installed (or "unknown") |
| `os_version` | string | Long OS version string |
| `kernel` | string | Kernel release string |
| `uptime_days` | integer | System uptime in days |
| `reboot_required` | boolean | `/var/run/reboot-required` present |
| `cpu_cores` | integer | Number of CPU cores |
| `total_ram_mb` | integer | Total RAM in MB |
| `swap_total_mb` | integer | Total swap in MB |
| `swap_used_mb` | integer | Used swap in MB |
| `load_average` | array of 3 floats | 1, 5, 15 min load averages |
| `open_files_limit` | string | Max open files (or "unknown") |
| `oom_kills` | integer | OOM kill count from dmesg |
| `zombie_processes` | integer | Number of zombie processes |
| `security_modules` | array of strings | Active Linux Security Modules (e.g., "apparmor") |
| `dmesg_errors` | array of strings | Last 5 critical dmesg lines |
| `gpu_devices` | array of strings | GPU names from lspci |
| `native_services` | array of strings | Running systemd services without `.service` suffix |
| `cron_jobs` | array of strings | All discovered cron jobs (crontab, cron.d, anacrontab) |
| `systemd_timers` | array of strings | Active systemd timer units |
| `tech_stack` | array of strings | Detected technologies (e.g., "Nginx", "PostgreSQL") |
| `top_memory_processes` | array of objects | Top 5 processes by RAM |
| `top_memory_processes[].name` | string | Process name |
| `top_memory_processes[].pid` | integer | PID |
| `top_memory_processes[].memory_mb` | integer | RAM used in MB |
| `failed_services` | array of strings | Failed systemd units |
| `backup_tools` | array of strings | Detected backup tools (or "None (CRITICAL)") |
| `last_restic_snapshot` | string \| null | ISO‑8601 timestamp of last Restic snapshot |
| `ntp_synchronized` | boolean | Whether time is synchronized |
| `time_offset_ms` | float \| null | Offset from NTP in milliseconds |

---

## `databases`

An array of objects, one per detected database engine.

| Field | Type | Description |
|-------|------|-------------|
| `engine` | string | "PostgreSQL", "MySQL/MariaDB", "Redis", "MongoDB" |
| `version` | string | Version string (or "Unknown/Inactive") |
| `data_dir` | string | Path to data directory |
| `size_mb` | integer | Directory size in MB |

---

## `network`

| Field | Type | Description |
|-------|------|-------------|
| `firewall_active` | boolean | Whether a host firewall is enabled |
| `dns_resolvers` | array of strings | DNS servers from `/etc/resolv.conf` |
| `custom_host_overrides` | array of strings | Custom `/etc/hosts` entries |
| `ssl_certificates` | array of objects | Let’s Encrypt certificates found |
| `ssl_certificates[].domain` | string | Domain name |
| `ssl_certificates[].expiry_date` | string | Expiry date string |
| `ssl_certificates[].days_remaining` | integer \| null | Days until expiry |
| `ssl_certificates[].is_critical` | boolean | Less than 7 days remaining |
| `ssl_certificates[].is_warning` | boolean | 7–30 days remaining |
| `listening_ports` | array of objects | Open TCP/UDP ports |
| `listening_ports[].protocol` | string | "tcp" or "udp" |
| `listening_ports[].port` | string | Port number |
| `listening_ports[].process` | string | Process name (or "unknown") |
| `listening_ports[].bind_address` | string | IP address the port is bound to |

---

## `storage`

| Field | Type | Description |
|-------|------|-------------|
| `disks` | array of objects | Mounted filesystems |
| `disks[].mount_point` | string | Mount point path |
| `disks[].total_gb` | integer | Total size in GB |
| `disks[].used_gb` | integer | Used space in GB |
| `disks[].inode_usage_percent` | string \| null | Inode usage percentage |

---

## `topology` (Docker)

| Field | Type | Description |
|-------|------|-------------|
| `docker_active` | boolean | Docker daemon reachable |
| `images_count` | integer | Total number of images |
| `dangling_images_count` | integer | Images without tags |
| `total_images_size_mb` | integer | Total size of all images in MB |
| `total_dangling_size_mb` | integer | Size of dangling images in MB |
| `dangling_volumes_count` | integer | Number of dangling volumes |
| `dangling_images` | array of objects | Top dangling images |
| `dangling_images[].id` | string | Short image ID |
| `dangling_images[].size_mb` | integer | Image size in MB |
| `containers` | array of objects | All containers |
| `containers[].name` | string | Container name |
| `containers[].image` | string | Image name |
| `containers[].state` | string | "running", "exited", etc. |
| `containers[].status` | string | Human‑readable status |
| `containers[].size_mb` | integer | Container writable layer size in MB |
| `containers[].log_size_mb` | integer | Container log file size in MB |
| `containers[].ports` | array of strings | Exposed ports |
| `containers[].mounts` | array of strings | Bind mounts (host -> container) |
| `containers[].privileged` | boolean | Privileged flag |
| `containers[].memory_limit_mb` | integer \| null | Memory limit in MB |
| `containers[].cpu_limit` | float \| null | CPU limit in cores |
| `containers[].cap_add` | array of strings | Added capabilities |

---

## `security`

| Field | Type | Description |
|-------|------|-------------|
| `ssh_password_auth_enabled` | boolean | Password authentication allowed |
| `ssh_root_login_enabled` | boolean | Root login allowed |
| `ssh_config_source` | string | Source of SSH configuration |
| `shell_users` | array of objects | Users with valid shells |
| `shell_users[].username` | string | Username |
| `shell_users[].last_login` | string | Last login entry (or "No login records found") |
| `shell_users[].last_ssh_login` | string | Last remote SSH login (or "No remote SSH login found") |
| `shell_users[].authorized_keys_count` | integer | Number of authorized keys |
| `fail2ban_active` | boolean | fail2ban service active |
| `auditd_active` | boolean | auditd service active |
| `sudo_nopasswd_entries` | array of strings | NOPASSWD sudo lines |
| `sudoers_mode` | integer \| null | Octal permissions of `/etc/sudoers` |
| `sysctl_issues` | array of strings | Non‑compliant sysctl settings |

---

## `packages`

| Field | Type | Description |
|-------|------|-------------|
| `manager` | string | Package manager enum: "Apt", "Dnf", "Yum", "Pacman", "Zypper", "Unknown" |
| `installed_count` | integer | Number of installed packages |
| `upgradable` | array of objects | Upgradable packages |
| `upgradable[].name` | string | Package name |
| `upgradable[].current_version` | string | Installed version |
| `upgradable[].new_version` | string | Available version |
| `upgradable[].is_security` | boolean | Whether the update is security‑related |
| `cache_refreshed` | boolean | Whether package cache was refreshed before scan |