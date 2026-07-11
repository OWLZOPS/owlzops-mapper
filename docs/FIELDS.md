# owlzops-mapper JSON schema reference
This document describes every field in the `AgentReport` JSON structure.
Use it to build integrations, dashboards, or alerting rules.

---

## Top-level

| Field | Type | Description |
|-------|------|-------------|
| `scan_id` | string | UUID v4 unique per scan |
| `timestamp` | string | ISO‑8601 timestamp (UTC) |
| `version` | string | owlzops‑mapper version |
| `duration_secs` | float | Wall‑clock time of the scan |
| `risk_score` | integer | 0–100 calculated risk |
| `is_root_execution` | boolean | Whether the scan ran as root |
| `scan_warnings` | array of strings | Warnings about scan failures or incomplete data |
| `coverage_warnings` | array of strings | Coverage warnings (truncated files, unreadable /proc entries, etc.) |
| `scoring_version` | integer | Internal scoring engine version (used for drift comparison) |

---

## `host`

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | Hostname of the scanned machine |
| `external_ipv4` | string | Public IP (or `"unknown"`) |
| `hosting_provider` | string | Provider from DMI (or `"unknown"`) |
| `os_install_date` | string | Date OS was installed (or `"unknown"`) |
| `os_version` | string | Long OS version string |
| `kernel` | string | Kernel release string |
| `uptime_days` | integer | System uptime in days |
| `reboot_required` | boolean | `/var/run/reboot-required` present |
| `cpu_cores` | integer | Number of CPU cores |
| `total_ram_mb` | integer | Total RAM in MB |
| `swap_total_mb` | integer | Total swap in MB |
| `swap_used_mb` | integer | Used swap in MB |
| `load_average` | array of 3 floats | 1, 5, 15 min load averages |
| `open_files_limit` | string | Max open files (or `"unknown"`) |
| `oom_kills` | integer | OOM kill count from dmesg |
| `zombie_processes` | integer | Number of zombie processes |
| `zombie_details` | array of objects | Details about zombie processes (up to 10) |
| `zombie_details[].pid` | integer | Zombie PID |
| `zombie_details[].name` | string | Zombie process name |
| `zombie_details[].ppid` | integer | Parent PID |
| `zombie_details[].parent_name` | string | Parent process name |
| `security_modules` | array of strings | Active Linux Security Modules (e.g., `"apparmor"`) |
| `dmesg_errors` | array of strings | Last 5 critical dmesg lines |
| `gpu_devices` | array of strings | GPU names from lspci |
| `native_services` | array of strings | Running systemd services without `.service` suffix |
| `cron_jobs` | array of objects | All discovered cron jobs with severity classification |
| `cron_jobs[].command` | string | Cron job command line |
| `cron_jobs[].severity` | string | Severity: `"Ok"`, `"Warning"`, or `"Critical"` |
| `systemd_timers` | array of strings | Active systemd timer units |
| `tech_stack` | array of strings | Detected technologies (e.g., `"Nginx"`, `"PostgreSQL"`) |
| `top_memory_processes` | array of objects | Top 5 processes by RAM |
| `top_memory_processes[].name` | string | Process name |
| `top_memory_processes[].pid` | integer | PID |
| `top_memory_processes[].memory_mb` | integer | RAM used in MB |
| `top_memory_processes[].instances` | integer | Number of instances with this name |
| `failed_services` | array of strings | Failed systemd units |
| `backup_tools` | array of strings | Detected backup tools |
| `last_restic_snapshot` | string \| null | ISO‑8601 timestamp of last Restic snapshot |
| `ntp_synchronized` | boolean | Whether time is synchronized |
| `time_offset_ms` | float \| null | Offset from NTP in milliseconds |
| `reboot_required_pkgs` | array of strings | Packages that triggered reboot requirement |

---

## `databases`

An array of objects, one per detected database engine.

| Field | Type | Description |
|-------|------|-------------|
| `engine` | string | `"PostgreSQL"`, `"MySQL/MariaDB"`, `"Redis"`, `"MongoDB"` |
| `version` | string | Version string (or `"Unknown/Inactive"`) |
| `data_dir` | string | Path to data directory |
| `size_mb` | integer | Directory size in MB |

---

## `network`

| Field | Type | Description |
|-------|------|-------------|
| `firewall_active` | boolean | Whether a host firewall is enabled |
| `dns_resolvers` | array of strings | DNS servers from `/etc/resolv.conf` |
| `dns_upstreams` | array of strings | Real upstream DNS servers (when systemd‑resolved stub is detected) |
| `custom_host_overrides` | array of strings | Custom `/etc/hosts` entries |
| `ssl_certificates` | array of objects | SSL certificates found |
| `ssl_certificates[].domain` | string | Domain name |
| `ssl_certificates[].expiry_date` | string | Expiry date string |
| `ssl_certificates[].days_remaining` | integer \| null | Days until expiry |
| `ssl_certificates[].is_critical` | boolean | Less than 7 days remaining |
| `ssl_certificates[].is_warning` | boolean | 7–30 days remaining |
| `listening_ports` | array of objects | Open TCP/UDP ports |
| `listening_ports[].protocol` | string | `"tcp"` or `"udp"` |
| `listening_ports[].port` | string | Port number |
| `listening_ports[].process` | string | Process name (or `"unknown"`) |
| `listening_ports[].bind_address` | string | IP address the port is bound to |
| `listening_ports[].pid` | integer \| null | PID of the listening process (requires root) |
| `listening_ports[].exe_path` | string \| null | Full path to the executable (requires root) |

---

## `storage`

| Field | Type | Description |
|-------|------|-------------|
| `disks` | array of objects | Mounted filesystems |
| `disks[].mount_point` | string | Mount point path |
| `disks[].total_mb` | integer | Total size in MB |
| `disks[].used_mb` | integer | Used space in MB |
| `disks[].usage_pct` | float | Usage percentage |
| `disks[].inode_usage_percent` | string \| null | Inode usage percentage |

---

## `topology` (Docker)

| Field | Type | Description |
|-------|------|-------------|
| `docker_active` | boolean | Docker daemon reachable |
| `images_count` | integer | Total number of images |
| `dangling_images_count` | integer | Images without tags |
| `total_images_size_mb` | integer | Real disk size of all images in MB |
| `total_dangling_size_mb` | integer | Virtual size of dangling images in MB |
| `images_reclaimable_mb` | integer | Space reclaimable by `docker image prune` |
| `build_cache_reclaimable_mb` | integer | Space reclaimable by `docker buildx prune` |
| `dangling_volumes_count` | integer | Number of dangling volumes |
| `dangling_images` | array of objects | Top dangling images |
| `dangling_images[].id` | string | Short image ID |
| `dangling_images[].size_mb` | integer | Virtual image size in MB |
| `containers` | array of objects | All containers |
| `containers[].name` | string | Container name |
| `containers[].image` | string | Image name |
| `containers[].state` | string | `"running"`, `"exited"`, etc. |
| `containers[].status` | string | Human‑readable status |
| `containers[].size_mb` | integer | Container writable layer size in MB |
| `containers[].rw_size_mb` | integer | Writable layer size in MB |
| `containers[].log_size_mb` | integer | Container log file size in MB |
| `containers[].ports` | array of strings | Exposed ports |
| `containers[].mounts` | array of strings | Bind mounts (host → container) |
| `containers[].sensitive_mounts` | array of strings | Sensitive mounts detected (e.g., `"DOCKER_SOCKET"`, `"HOST_ROOT"`) |
| `containers[].privileged` | boolean | Privileged flag |
| `containers[].memory_limit_mb` | integer \| null | Memory limit in MB |
| `containers[].cpu_limit` | float \| null | CPU limit in cores |
| `containers[].cap_add` | array of strings | Added capabilities |
| `containers[].restart_count` | integer | Number of restarts |
| `containers[].oom_killed` | boolean | Whether the container was OOM‑killed |
| `containers[].health_status` | string \| null | Healthcheck status |

---

## `security`

| Field | Type | Description |
|-------|------|-------------|
| `ssh_password_auth_enabled` | boolean | Password authentication allowed |
| `ssh_root_login_enabled` | boolean | Root login allowed |
| `ssh_permit_root_login_detail` | string \| null | Raw PermitRootLogin value |
| `ssh_config_source` | string | Source of SSH configuration |
| `shell_users` | array of objects | Users with valid shells |
| `shell_users[].username` | string | Username |
| `shell_users[].last_login` | string | Last login entry (or `"No login records found"`) |
| `shell_users[].last_ssh_login` | string | Last remote SSH login (or `"No remote SSH login found"`) |
| `shell_users[].authorized_keys_count` | integer | Number of authorized keys |
| `fail2ban_active` | boolean | fail2ban service active |
| `auditd_active` | boolean | auditd service active |
| `sudo_nopasswd_entries` | array of strings | NOPASSWD sudo lines |
| `sudoers_mode` | integer \| null | Octal permissions of `/etc/sudoers` |
| `sysctl_issues` | array of strings | Non‑compliant sysctl settings |
| `access_alignment` | object | IAM & access audit results |
| `access_alignment.keys` | array of objects | Audited SSH keys |
| `access_alignment.keys[].user` | string | Username |
| `access_alignment.keys[].algorithm` | string | Key algorithm (e.g., `"ssh-rsa"`) |
| `access_alignment.keys[].bits` | integer | Key bit length |
| `access_alignment.keys[].comment` | string | Key comment |
| `access_alignment.keys[].compliant` | boolean | Whether the key meets policy |
| `access_alignment.keys[].reason` | string \| null | Reason if non‑compliant |
| `access_alignment.sudoers_nopasswd_all` | array of objects | Sudoers entries with NOPASSWD: ALL |
| `access_alignment.sudoers_nopasswd_all[].principal` | string | User or group |
| `access_alignment.sudoers_nopasswd_all[].source_file` | string | Sudoers file path |
| `access_alignment.sudoers_nopasswd_all[].scope` | string | Command scope |
| `access_alignment.coverage_warnings` | array of strings | Warnings from access audit |
| `secret_hygiene` | array of objects | Detected secret leaks in process memory |
| `secret_hygiene[].pid` | integer | PID of the process |
| `secret_hygiene[].process` | string | Process name |
| `secret_hygiene[].source` | string | Source (e.g., `"environ"`, `"cmdline"`) |
| `secret_hygiene[].matched_key` | string | Type of secret found (e.g., `"DATABASE_URL"`) |
| `capability_audit` | array of objects | Non‑root processes with critical capabilities |
| `capability_audit[].pid` | integer | PID |
| `capability_audit[].comm` | string | Process comm name |
| `capability_audit[].euid` | integer | Effective UID |
| `capability_audit[].effective` | integer | Effective capability mask (hex) |
| `capability_audit[].permitted` | integer | Permitted capability mask (hex) |
| `capability_audit[].inheritable` | integer | Inheritable capability mask (hex) |
| `capability_audit[].bounding` | integer | Bounding capability mask (hex) |
| `capability_audit[].ambient` | integer | Ambient capability mask (hex) |
| `capability_audit[].no_new_privs` | boolean \| null | NoNewPrivs flag |
| `capability_audit[].seccomp` | integer \| null | Seccomp mode (0=disabled, 1=strict, 2=filter) |
| `capability_audit[].critical_caps` | array of strings | Names of critical capabilities held |
| `suspicious_processes` | array of objects | Processes flagged by malware/heuristic detection |
| `suspicious_processes[].pid` | integer | PID |
| `suspicious_processes[].name` | string | Process comm name |
| `suspicious_processes[].exe_path` | string \| null | Resolved executable path |
| `suspicious_processes[].is_deleted` | boolean | Whether the executable was deleted from an ephemeral path or is a memfd‑based implant |
| `suspicious_processes[].euid` | integer | Effective UID of the process |
| `suspicious_processes[].is_mimic` | boolean | Kernel-thread name with userspace cmdline (masquerading) |
| `mount_masking` | array of objects | Bind‑mount / overlay masking attempts (SEC‑021) |
| `mount_masking[].target_path` | string | Mount point being masked (e.g. `/proc/<pid>`) |
| `mount_masking[].mount_source` | string | Mount source (e.g. `tmpfs`, `/dev/sda1`) |
| `mount_masking[].fstype` | string | Filesystem type (e.g. `tmpfs`, `ext4`) |
| `mount_masking[].reason` | string | Why this was flagged (evidence hiding, process masking) |
| `reverse_shells` | array of objects | Reverse shell / C2 connections detected (SEC‑022) |
| `reverse_shells[].pid` | integer | PID of the interpreter process |
| `reverse_shells[].process` | string | Process comm (interpreter name) |
| `reverse_shells[].exe_path` | string \| null | Resolved executable path |
| `reverse_shells[].remote_address` | string | Remote endpoint `ip:port` |
| `reverse_shells[].stdio_fd` | integer \| null | Which stdio fd (0,1,2) carries the socket, or null if non‑stdio |
| `library_injections` | array of objects | Userspace rootkit / library injection from ephemeral paths (SEC‑023) |
| `library_injections[].pid` | integer | PID of the injected process |
| `library_injections[].process` | string | Process comm |
| `library_injections[].object_path` | string | The offending .so or LD_* value |
| `library_injections[].source` | string | Where it was observed: `"LD_PRELOAD"`, `"LD_LIBRARY_PATH"`, or `"maps"` |
| `library_injections[].is_deleted` | boolean | Whether the mapped object is marked `(deleted)` (stronger IoC) |
| `ghost_pids` | array of objects | PIDs hidden from `/proc` listing by an LKM rootkit (SEC‑024/025) |
| `ghost_pids[].pid` | integer | The hidden PID |
| `ghost_pids[].state` | string \| null | Process state (`"R"`, `"S"`, `"D"`, `"Z"`, …) if readable |
| `ghost_pids[].age_secs` | integer \| null | Age of the process in seconds, if computable |
| `ghost_pids[].confirmed_via` | string | How existence was confirmed: `"stat-path"`, `"kill"`, or `"stat-path+kill"` |
| `ghost_pids[].confirmed_ioc` | boolean | `true` if this is a hard IoC (meets all criteria); `false` if downgraded |
| `ghost_pids[].holds_socket` | boolean | Whether the hidden PID also owns a network socket (corroboration) |

---

## `packages`

| Field | Type | Description |
|-------|------|-------------|
| `manager` | string | Package manager: `"Apt"`, `"Dnf"`, `"Yum"`, `"Pacman"`, `"Zypper"`, `"Unknown"` |
| `installed_count` | integer | Number of installed packages |
| `upgradable` | array of objects | Upgradable packages |
| `upgradable[].name` | string | Package name |
| `upgradable[].current_version` | string | Installed version |
| `upgradable[].new_version` | string | Available version |
| `upgradable[].is_security` | boolean | Whether the update is security‑related |
| `cache_refreshed` | boolean | Whether package cache was refreshed before scan |