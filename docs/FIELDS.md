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

## `topology` (Docker / Podman)

| Field | Type | Description |
|-------|------|-------------|
| `runtime_active` | boolean | Container runtime reachable |
| `runtime_name` | string | Name of the container runtime (e.g. "Docker") |
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
| `library_injections[].region_addr` | string \| null | VMA start‑end address (`"7f3c0000‑7f3d0000"`) |
| `library_injections[].deep_forensics` | object \| null | Deep memory forensics payload (only with `--deep`) |
| `ghost_pids` | array of objects | PIDs hidden from `/proc` listing by an LKM rootkit (SEC‑024/025) |
| `ghost_pids[].pid` | integer | The hidden PID |
| `ghost_pids[].state` | string \| null | Process state (`"R"`, `"S"`, `"D"`, `"Z"`, …) if readable |
| `ghost_pids[].age_secs` | integer \| null | Age of the process in seconds, if computable |
| `ghost_pids[].confirmed_via` | string | How existence was confirmed: `"stat-path"`, `"kill"`, or `"stat-path+kill"` |
| `ghost_pids[].confirmed_ioc` | boolean | `true` if this is a hard IoC (meets all criteria); `false` if downgraded |
| `ghost_pids[].holds_socket` | boolean | Whether the hidden PID also owns a network socket (corroboration) |
| `file_capabilities` | array of objects | Files with persistent capabilities (setcap) |
| `file_capabilities[].path` | string | Absolute path of the file |
| `file_capabilities[].capabilities` | array of strings | Human‑readable capability names |
| `file_capabilities[].reason` | string \| null | Why this file was flagged |
| `file_capabilities[].permitted` | integer | Permitted capability mask (raw) |
| `file_capabilities[].inheritable` | integer | Inheritable capability mask (raw) |
| `file_capabilities[].effective` | boolean | Effective bit |
| `file_capabilities[].revision` | integer | Capability revision |
| `file_capabilities[].rootid` | integer \| null | Root user namespace ID |
| `file_capabilities[].package` | string \| null | Owning package, if resolved |
| `ebpf_inventory` | object | Loaded eBPF programs, maps, and pinned objects |
| `ebpf_inventory.programs` | array of objects | Loaded BPF programs |
| `ebpf_inventory.programs[].prog_id` | integer | Program ID |
| `ebpf_inventory.programs[].prog_type` | string | Program type |
| `ebpf_inventory.programs[].prog_name` | string \| null | Program name |
| `ebpf_inventory.programs[].prog_tag` | string | Program tag |
| `ebpf_inventory.programs[].pid` | integer | PID of the process that loaded the program |
| `ebpf_inventory.programs[].comm` | string | Comm of the process |
| `ebpf_inventory.maps` | array of objects | Loaded BPF maps |
| `ebpf_inventory.maps[].map_id` | integer | Map ID |
| `ebpf_inventory.maps[].map_type` | string | Map type |
| `ebpf_inventory.maps[].pid` | integer | PID of the process that created the map |
| `ebpf_inventory.maps[].comm` | string | Comm of the process |
| `ebpf_inventory.links` | array of objects | Active BPF links |
| `ebpf_inventory.links[].link_id` | integer | Link ID |
| `ebpf_inventory.links[].prog_id` | integer | Program ID |
| `ebpf_inventory.links[].attach_type` | string | Attach type |
| `ebpf_inventory.links[].pid` | integer | PID of the process that created the link |
| `ebpf_inventory.links[].comm` | string | Comm of the process |
| `ebpf_inventory.pins` | array of objects | Pinned BPF objects in /sys/fs/bpf |
| `ebpf_inventory.pins[].path` | string | Path in /sys/fs/bpf |
| `ebpf_inventory.pins[].obj_type` | string | `"prog"`, `"map"`, or `"link"` |
| `ebpf_inventory.pins[].obj_id` | integer | Object ID |
| `ebpf_inventory.prog_tags` | array of strings | Stable set of program tags for drift detection |
| `setuid_files` | array of objects | Setuid/setgid files found in common binary directories |
| `setuid_files[].path` | string | Absolute path |
| `setuid_files[].setuid` | boolean | Has setuid bit |
| `setuid_files[].setgid` | boolean | Has setgid bit |
| `setuid_files[].root_owner` | boolean | File is owned by root |
| `setuid_files[].package` | string \| null | Owning package, if resolved |
| `provenance_source` | string | Which package database was used for attribution: `"dpkg"`, `"apk"`, `"rpm"`, or `"unavailable"` |
| `kernel_taint` | object | Decoded /proc/sys/kernel/tainted |
| `kernel_taint.raw` | integer | Raw taint value |
| `kernel_taint.flags` | array of objects | Decoded taint flags |
| `kernel_taint.flags[].bit` | integer | Bit position |
| `kernel_taint.flags[].code` | string | Kernel letter (e.g. `"E"`) |
| `kernel_taint.flags[].name` | string | Human description |
| `kernel_taint.flags[].security_relevant` | boolean | Whether the flag is security‑relevant |
| `kernel_taint.unavailable` | boolean | True if the file was unreadable |
| `confinement` | object | LSM confinement state |
| `confinement.lsms` | array of strings | Active LSMs |
| `confinement.selinux_permissive` | boolean | SELinux is loaded but in permissive mode |
| `confinement.complain_profiles` | array of objects | AppArmor profiles in complain mode |
| `confinement.complain_profiles[].pid` | integer | PID |
| `confinement.complain_profiles[].comm` | string | Process comm |
| `confinement.complain_profiles[].profile` | string | Profile name |
| `confinement.attr_read_incomplete` | boolean | True when per‑process attr/current could not be fully read (non‑root) |
| `kernel_modules` | object | Kernel module inventory |
| `kernel_modules.proc_modules` | array of strings | Module names from /proc/modules |
| `kernel_modules.sysfs_modules` | array of strings | Live loadable modules from /sys/module |
| `kernel_modules.hidden_candidates` | array of objects | Modules live in sysfs/kallsyms but absent from /proc/modules |
| `kernel_modules.hidden_candidates[].name` | string | Module name |
| `kernel_modules.hidden_candidates[].seen_in` | array of strings | Interfaces that still expose it (e.g. `"sysfs"`, `"kallsyms"`) |
| `kernel_modules.kallsyms_checked` | boolean | False when /proc/kallsyms was empty/unreadable |
| `ftrace_hooks` | object | ftrace/kprobe hook surface |
| `ftrace_hooks.unattributed_syscall_hooks` | array of objects | Syscall‑entry functions with an ftrace_ops from no legitimate source |
| `ftrace_hooks.unattributed_syscall_hooks[].function` | string | Function name |
| `ftrace_hooks.unattributed_syscall_hooks[].ops_count` | integer | Number of ftrace_ops on the function |
| `ftrace_hooks.unattributed_syscall_hooks[].callback` | string | `"module:<name>"` or `"unresolved"` |
| `ftrace_hooks.syscall_kprobes` | array of objects | Kprobes on syscall functions |
| `ftrace_hooks.syscall_kprobes[].kind` | string | `"p"` (kprobe) or `"r"` (kretprobe) |
| `ftrace_hooks.syscall_kprobes[].group_name` | string | Kprobe group name |
| `ftrace_hooks.syscall_kprobes[].symbol` | string | Symbol name |
| `ftrace_hooks.attributed_hook_count` | integer | Number of syscall hooks attributed to a known source |
| `ftrace_hooks.live_tracer_active` | boolean | A live function tracer was running |
| `ftrace_hooks.attribution_degraded` | boolean | kptr_restrict hid callback symbols |
| `ftrace_hooks.tracefs_available` | boolean | tracefs was mounted & readable |
| `preload_injections` | array of objects | Entries found in /etc/ld.so.preload (SEC‑042/049/050) |
| `preload_injections[].path` | string | Path to the preloaded shared object |
| `preload_injections[].volatile` | boolean | True when the path resides on a volatile filesystem |
| `preload_injections[].package` | string \| null | Resolved package name, if the file belongs to a known package |
| `preload_injections[].mapped_by_pids` | integer \| null | Number of processes that have this object mapped; `null` = unknown |
| `exec_start_injections` | array of objects | ExecStart provenance for systemd units and cron (SEC‑043/045/046/047/048) |
| `exec_start_injections[].source` | string | `"systemd:<unit>"` or `"cron:/etc/crontab"` etc. |
| `exec_start_injections[].unit_name` | string | Name of the unit or cron file |
| `exec_start_injections[].unit_path` | string | Absolute path of the unit/cron file that declared this entry |
| `exec_start_injections[].unit_package` | string \| null | Package owning the unit file itself |
| `exec_start_injections[].exec_path` | string | The executable path extracted (first token after stripping prefixes) |
| `exec_start_injections[].volatile` | boolean | True if the path is on a volatile filesystem |
| `exec_start_injections[].writability` | string | `"root_only"`, `"non_root_writable"`, `"missing"`, or `"unknown"` |
| `exec_start_injections[].package` | string \| null | Package that owns the file, if any (only with `--deep`) |
| `exec_start_injections[].runs_as_root` | boolean | True when the unit does NOT set `User=` (i.e. runs as root). Defaults to `true` for legacy snapshots. |
| `core_pattern` | string \| null | `/proc/sys/kernel/core_pattern`; `null` = unreadable (SEC‑044) |
| `modules_disabled` | boolean \| null | `/proc/sys/kernel/modules_disabled`; `null` = unreadable (SEC‑044) |
| `lockdown` | string \| null | Kernel lockdown state; `null` = unavailable (SEC‑044) |
| `ld_so_conf_injections` | array of objects | Directories from ld.so.conf / ld.so.conf.d that allow unprivileged library injection (SEC‑051) |
| `ld_so_conf_injections[].path` | string | Absolute path as written in the config file |
| `ld_so_conf_injections[].volatile` | boolean | True if the filesystem is volatile (tmpfs, devtmpfs, …) |
| `ld_so_conf_injections[].writable_by_non_root` | boolean | True if the directory is writable by a non‑root principal. **Independent** from `volatile`: either axis alone triggers the finding. |
| `ld_so_conf_injections[].mode` | integer \| null | POSIX mode bits in octal (e.g. 0o755). `null` if the directory does not exist — in that case `uid`/`gid`/`writable_by_non_root` refer to the **parent** directory |
| `ld_so_conf_injections[].uid` | integer | Owner UID of the directory (or of the parent if `mode` is null) |
| `ld_so_conf_injections[].gid` | integer | Owner GID of the directory (or of the parent if `mode` is null) |
| `pam_injections` | array of objects | PAM stack injection findings (SEC‑055/056/057) |
| `pam_injections[].services` | array of strings | PAM service files referencing this target (e.g. `"sshd (auth sufficient)"`) |
| `pam_injections[].module` | object | PAM module entry (flattened) |
| `pam_injections[].module.module_path` | string | Resolved path of the module or script |
| `pam_injections[].target_kind` | string | `"Module"` for `.so` files, `"ExecScript"` for scripts executed by pam_exec |
| `pam_injections[].declared_as` | string \| null | Path as written in the config, if different from `module_path` (e.g. contains `..`). `null` when identical |
| `pam_injections[].writability` | string | `"root_only"`, `"non_root_writable"`, `"missing"`, or `"unknown"` |
| `pam_injections[].volatile` | boolean | True if the target is on a volatile filesystem |
| `pam_injections[].package` | string \| null | Owning package, if any |
| `pam_injections[].uid` | integer | Owner UID of the target file |
| `pam_injections[].gid` | integer | Owner GID of the target file |
| `pam_injections[].parent_takeable` | boolean | Whether a non‑root user can take over the parent directory (relevant for `missing` targets) |

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