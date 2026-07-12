# owlzops-mapper
[![CI](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/OWLZOPS/owlzops-mapper?include_prereleases&style=flat)](https://github.com/OWLZOPS/owlzops-mapper/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0%20with%20Commons%20Clause-blue.svg)](LICENSE)

> One binary. Zero dependencies. Sub-second host scanning. Identify active compromises, container escapes, and compliance gaps without deploying heavy agents.

`owlzops-mapper` is a surgical, self-contained Rust binary designed for rapid forensics, infrastructure hardening and drift monitoring. It performs a deep-state Linux and Docker audit in seconds, securely extracting IoCs (Indicators of Compromise), capability abuses, and misconfigurations — exporting directly to JSONL, Excel, or terminal for SIEM integration. No internet required. No data leaves the server.

**Who is this for?**
* **For DevSecOps & Incident Responders:** Instant threat hunting. Detect fileless malware, hidden mounts, reverse shells, and Docker runtime escapes.
* **For CISOs & CTOs:** Instant Compromise Assessment and SOC 2 / ISO 27001 compliance readiness. Answer the question *"Are we breached right now?"* in seconds.
* **For Infrastructure Engineers:** Snapshot diffing, drift monitoring, and strict security hygiene without overhead.

## Why does this exist?

Most EDR solutions and security scanners require heavy agents, Python runtimes, kernel modules (eBPF), or open firewall ports — causing performance degradation and deployment friction on production servers.

This one doesn't. Built with pure Rust, zero-copy parsing, and defensive I/O constraints, `owlzops-mapper` treats the scanned host as untrusted. You drop it via SSH, get a precise security and risk baseline, and it exits cleanly without leaving a trace or zombie processes. I built it because incident response and infrastructure hardening shouldn't require weeks of agent deployment approvals — you need answers *now*.

---

## Quick Start

**Option 1 – direct download:**
```bash
curl -L https://github.com/OWLZOPS/owlzops-mapper/releases/latest/download/owlzops-mapper-linux-x86_64.tar.gz | tar xz
sudo ./owlzops-mapper audit
```

**Option 2 – install script (verifies SHA256 + GPG):**

```bash
curl -sSL https://raw.githubusercontent.com/OWLZOPS/owlzops-mapper/main/install.sh | sh
sudo ./owlzops-mapper audit
```

---

## Core Features (Agentless EDR-lite)

* **Active Compromise & Threat Hunting (IoC)** – Sweeps memory (`/memfd`), deleted executables, ephemeral paths (`/dev/shm`, `/tmp`), and network state to detect hidden rootkits, reverse shells, library injection, and fileless malware in milliseconds.
* **Deep Container Forensics & Escape Detection** – Analyzes Docker/containerd runtimes for privileged container abuses, sensitive host mounts (`/var/run/docker.sock`), capability leakage, and missing resource limits. All mapped to CIS benchmarks.
* **Agentless Fleet Orchestration** – Drop the binary via SSH, scan dozens of servers in parallel, and clean up automatically. Supports both passwordless sudo and **password‑based sudo** (`--ask-sudo-pass`). Zero permanent footprint.
* **Snapshot Diffing & Drift Monitoring** – Capture server state as JSON snapshots, compare any two, and get color‑coded Excel/terminal diffs of exactly what changed (new open ports, changed capabilities, added cronjobs).
* **Context‑aware Risk Score** – Findings are evaluated with awareness of the environment (e.g., Docker/kubelet hosts are not penalized for `ip_forward=1`). Sub‑scores for Security, Reliability, and Hygiene prevent score saturation.
* **CIS Benchmark Mapping** – Every security finding includes a strict reference to the corresponding CIS Benchmark rule (e.g., `CIS 5.2.10`), ready for compliance audits.
* **Air‑gapped & SIEM-ready** – A single static binary with no runtime dependencies. `--offline` mode guarantees zero outbound calls. Exports rich Excel dashboards or flat JSONL for immediate SIEM ingestion.

---

## Highlights v0.5.12

**New Active Compromise Detectors (SEC‑021 – SEC‑025)**

* **SEC‑021 – Bind‑mount / overlay masking** – detects `/proc/<pid>` overlays (process hiding) and tmpfs/bind overlays over log paths (`/var/log`, `/var/lib/docker/containers`). Parses `mountinfo` correctly across shared‑subtree hosts. Weight: 60, exit code 3.
* **SEC‑022 – Reverse shell / C2 connection** – correlates `ESTABLISHED` TCP sockets from `/proc/net/tcp` with `/proc/<pid>/fd` and flags interpreters (bash, python, nc, socat...) connected to a public remote address on a stdio fd. Internal targets are intentionally excluded to keep near‑zero false positives. Weight: 60, exit code 3.
* **SEC‑023 – Userspace rootkit / library injection** – scans `/proc/<pid>/environ` (`LD_PRELOAD` / `LD_LIBRARY_PATH`) and `/proc/<pid>/maps` for shared objects loaded from ephemeral paths (`/tmp`, `/dev/shm`, …). Treats `(deleted)` mapped objects as stronger IoC. Weight: 60, exit code 3.
* **SEC‑024 – True Ghost PID (LKM rootkit – Diamorphine class)** – detects PIDs hidden from `readdir("/proc")` by a getdents64‑hooking rootkit. Brute‑force `stat("/proc/<pid>")` bypasses the hook; `kill(pid, 0)` acts as an independent arbiter. Candidates must survive 3 stability cycles, have a live state, and be older than 2 s. Weight: 60, exit code 3. Young/racy candidates are downgraded to **SEC‑025** (weight 20, no exit code).
* **SEC‑025 – Downgraded ghost PID suspicion** – reports transient visibility mismatches that did not meet the full IoC criteria, for manual triage.

**R10 Reliability & Hardening (all verified)**

* `russh` path now removes the uploaded binary and performs a clean SSH disconnect (parity with legacy SSH).
* JSONL streaming writer tracks I/O errors and flushes explicitly; degraded output returns exit code 2 instead of silent success.
* Malformed JSON from remote hosts is no longer silently dropped – a preview is logged for diagnostics.
* Tool resolution (`resolve_tool`) is poison‑tolerant and no longer shells out to `which`.
* `run_with_timeout_inner` uses capped reads and guarantees child process reaping in every exit path.
* Terminal output sanitises bidi‑override and zero‑width characters.
* Legacy SSH children are registered and sent `SIGTERM` on graceful shutdown.
* PID and EUID columns in Excel reports render as integers.
* TCP_NODELAY is enabled on russh sockets for lower upload latency.

**Infrastructure & UX Improvements**

* **Unified russh remote path** – the system `ssh`/`scp` fallback has been removed; all remote scans now use the pure‑Rust `russh` engine, eliminating terminal capture issues and dependency on external binaries.
* **Optional sudo** – `sudo_pass` is now optional in `run_remote_scan_russh`. When no password is supplied (e.g., passwordless sudo or root‑key setups), the remote command executes directly without `sudo`, keeping the UX clean.
* **False zombie fix** – transient zombies created by the mapper's own child processes are now filtered out, ensuring accurate zombie counts in reports.
* **Clean progress UI** – `MultiProgress` coordinates the upload progress bar and the scan spinner. Bars are automatically cleared from the terminal (`finish_and_clear()`) once they finish, leaving the final report uncluttered. The spinner only appears after any sudo password prompt, preventing TTY interference.

**Performance & Infrastructure**

* Ghost PID scanner bounds its search to `ns_last_pid` with an optional wrap‑tail heuristic, avoiding brute‑force over 4 M PIDs. Single‑threaded, with micro‑yield throttling.
* All new scanners respect `MAX_FINDINGS` caps and defensive I/O budgets.

**UI, Excel & JSON Completeness**

* Terminal dashboard and Excel exports include dedicated sections for every new finding (SEC‑021–025).
* `docs/FIELDS.md` fully documents `mount_masking`, `reverse_shells`, `library_injections`, and `ghost_pids`.

---

## Usage

### Local audit & Forensics

```bash
# Terminal dashboard (default, fully offline)
sudo ./owlzops-mapper audit

# Export to Excel (with Executive Summary as first sheet)
sudo ./owlzops-mapper audit --format excel --output report.xlsx
```

```bash
# JSON for programmatic use / SIEM ingestion
sudo ./owlzops-mapper audit --format json > snapshot.json

# Detect external IP (opt-in outbound request)
sudo ./owlzops-mapper audit --external-ip

# Refresh package cache before checking updates
sudo ./owlzops-mapper audit --refresh-packages

# Air-gapped / restricted network — guarantees zero outbound calls
sudo ./owlzops-mapper audit --offline
```

### Remote audit (via SSH)

```bash
# Scan a single remote host (binary must be present at /tmp/owlzops-mapper;
# the remote user needs passwordless sudo permission for the binary path).
sudo ./owlzops-mapper audit --host 192.168.1.10 --ssh-user operator
```

```bash
# Scan multiple comma-separated hosts
sudo ./owlzops-mapper audit --host 192.168.1.10,192.168.1.11 --ssh-user operator

# Automatically copy the local static binary to the remote host first.
# Release binaries are static (musl), so --copy-binary works out of the box.
sudo ./owlzops-mapper audit --host 192.168.1.10 --ssh-user operator --copy-binary

# If you built your own binary (e.g. debug build), point to the musl release:
sudo ./owlzops-mapper audit --host 192.168.1.10 --ssh-user operator --copy-binary \
  --local-binary target/x86_64-unknown-linux-musl/release/owlzops-mapper

# Scan multiple hosts from a file (one per line)
sudo ./owlzops-mapper audit --hosts hosts.txt --ssh-user operator --copy-binary

# Multi-host Excel report with one sheet per host
sudo ./owlzops-mapper audit --hosts hosts.txt --ssh-user operator --format excel --output fleet-audit.xlsx
```

### Fleet scan: 20+ VPS in one command

1. Create a `hosts.txt` file (one host per line):
```
10.0.0.1
10.0.0.2
...
10.0.0.20
```

2. **Authentication – choose the method that fits your environment:**
   **Option A (passwordless, legacy)**
   Bake this line into cloud‑init / Terraform once per host:
```bash
echo "ubuntu ALL=(ALL) NOPASSWD: /tmp/owlzops-mapper" | sudo tee /etc/sudoers.d/owlzops
```
Then run the fleet scan **without** `--ask-sudo-pass`.
**Option B (interactive password, new in v0.5.2)**
No sudoers changes needed – you only need regular `sudo` access.
The mapper will ask for your password once and forward it securely over
the SSH channel (`sudo -S`).  Just add `--ask-sudo-pass` to the command
below.
3. Run the audit from your local machine – the binary copies itself,
   scans all 20 servers in parallel, and cleans up automatically:
```bash
sudo ./owlzops-mapper audit \
  --hosts hosts.txt \
  --ssh-user ubuntu \
  --copy-binary \
  --ask-sudo-pass \
  --format excel \
  --output fleet-report.xlsx
```

Under the hood, `owlzops-mapper` connects to every server via SSH,
uploads itself to `/tmp/owlzops-mapper`, executes the audit, collects
the JSON results, removes the binary from each host, and produces a
single multi‑sheet Excel report.  No agent installation, no open ports
beyond SSH.

*Note: the mapper now uses the `russh` library exclusively for all SSH operations – no external `ssh` or `scp` binaries are required, ensuring consistent behaviour regardless of the local `~/.ssh/config`.*

### Snapshotting & drift monitoring

```bash
# Save a timestamped JSON snapshot (default directory: ~/.owlzops/snapshots/<hostname>/)
sudo ./owlzops-mapper snapshot

# Specify custom output directory
sudo ./owlzops-mapper snapshot --output-dir /var/lib/owlzops

# Compare the two most recent snapshots for a host
./owlzops-mapper dir-compare ~/.owlzops/snapshots/ubuntu

# Export that comparison to Excel
./owlzops-mapper dir-compare --format excel --output drift.xlsx ~/.owlzops/snapshots/ubuntu
```

### Comparing snapshots (diff)

*Demo: a before/after comparison with metadata header showing host, timestamps, binary version, and time span.*

```bash
# Compare two JSON snapshots in terminal (colored table)
./owlzops-mapper compare before.json after.json

# Output includes metadata header:
#   host:    owl1.owlzops.com
#   before: 2026-07-05 17:41 UTC  (v0.5.0, risk 55)
#   after:  2026-07-05 17:42 UTC  (v0.5.0, risk 45)
#   span:   1m

# Export diff to JSON
./owlzops-mapper compare before.json after.json --format json > diff.json

# Export diff to Excel (color-coded: green=improved, red=degraded, yellow=changed)
./owlzops-mapper compare before.json after.json --format excel --output diff.xlsx

# Multi‑host comparison: both files must be arrays of host reports (e.g., from a fleet scan)
./owlzops-mapper compare --multi-host fleet_before.json fleet_after.json
```

---

## Command-Line Options

| Flag | Description |
| --- | --- |
| `-f, --format` | Output format: `text` (default), `json`, `xlsx` (or `excel`) |
| `-o, --output` | Output file for Excel reports (default: `owlzops-report-<hostname>-YYYY-MM-DD_HH-MM-SS.xlsx`) |
| `--external-ip` | Fetch public IP via outbound request (off by default) |
| `--refresh-packages` | Update package cache before scanning (off by default) |
| `--offline` | Disable **all** network calls. Overrides other flags if combined |
| `--host <HOST>` | Single hostname/IP (or comma‑separated list) for remote scanning |
| `--hosts <FILE>` | File with one hostname/IP per line for remote scanning |
| `--ssh-user <USER>` | SSH user for remote connections (default: `root`; prefer a non‑root user with passwordless sudo) |
| `--ssh-key <PATH>` | Path to SSH private key (default: `~/.ssh/id_rsa`) |
| `--copy-binary` | Copy the local binary to remote hosts before scanning. The binary **must** be statically linked (musl). GitHub release binaries are static, so you can safely use this flag with them. |
| `--local-binary <PATH>` | When using `--copy-binary`, path to a local static (musl) binary to copy instead of the currently running one. Useful if you're running a debug build locally but have a release build for remote hosts. |
| `--remote-path <PATH>` | Path where the binary is placed on remote hosts (default: `/tmp/owlzops-mapper`) |
| `--remote-timeout-secs <SECS>` | Maximum time to wait for remote scan (default: 120 seconds) |
| `--ask-sudo-pass` | Prompt for a sudo password and forward it securely over the SSH channel (removes the NOPASSWD requirement) |
| `--keep-binary` | Skip cleanup — leave the binary on the remote host after the scan |
| `--max-concurrent <N>` | Maximum number of simultaneous SSH sessions (default: 50) |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

### Subcommands

| Command | Description |
| --- | --- |
| `audit` | Run an audit scan (local or remote) |
| `snapshot` | Run an audit and save the JSON snapshot to disk |
| `compare <before> <after>` | Compare two JSON snapshots and show drift |
| `dir-compare <dir>` | Compare the two most recent snapshots in a directory |

---

## Exit Codes

| Code | Single Host | Multi-Host (Fleet) |
| --- | --- | --- |
| `0` | No critical issues found | All hosts clean |
| `1` | One or more critical findings (firewall disabled, SSH root login permitted, pending security updates, SSL certificate about to expire, failed services, missing backups, NTP not synced, sudo NOPASSWD entries, sysctl issues ≥ 3) | Any host has critical issues |
| `2` | Not running as root, scan warnings present, **or fleet scan produced zero reports** | Any host not running as root, **or all remote hosts failed** |
| `3` | **Active compromise detected** (IoC findings SEC‑015…SEC‑024, DOCK‑010) | **Any host shows active compromise** |

> **Scoring version guard:** when comparing snapshots taken with different scoring engine versions, `risk_score` changes are marked as `~ Changed` rather than `↑ Improved` or `↓ Degraded`.

You can use these codes directly in CI/CD pipelines:

```bash
sudo ./owlzops-mapper audit || echo "Security scan failed – check the report"
```

---

## Risk Score

The dashboard and Excel report include a **Risk Score (0–100)** calculated
from real findings. The score is split into three sub‑scores:

| Category | Cap | Examples |
| --- | --- | --- |
| **Security** | 60 | Firewall, SSH config, security updates, Docker risks, sysctl hardening, malware & intrusion detection |
| **Reliability** | 30 | Failed services, missing backups, OOM kills, container health |
| **Hygiene** | 10 | NTP synchronization |

Lower scores are better. Each finding is tagged with a CIS Benchmark reference where applicable.

Colour legend: **green** < 40, **yellow** 40–69, **red** ≥ 70.

| Finding | Penalty |
| --- | --- |
| Firewall inactive | +30 |
| SSH root login allowed | +25 (`prohibit-password` reduces weight) |
| Pending security updates | +20 (stepped: 10/15/20 depending on count) |
| SSL certificate expires within 7 days | +15 (max) |
| Failed systemd services | +10 |
| SSH password authentication enabled | +10 |
| OOM kills present | +10 |
| No backup tools detected | +20 |
| NTP not synchronized | +10 |
| Sudo NOPASSWD entries found | +5 (restricted commands) / +15 (ALL) |
| Sudoers permissions not 0440 | +5 |
| Sysctl security issues | +5 per issue (context‑sensitive) |
| Docker: containers without memory limits | +5 |
| Docker: containers without CPU limits | +3 |
| Docker: privileged containers | +10 |
| Docker: dangerous capabilities | +10 |
| Root login with password (combo) | +5 |
| Container mounts Docker socket or host root | +15 |
| Container mounts sensitive host path (writable) | +10 |
| Docker: containers killed by OOM | +10 |
| Docker: containers in restart loop | +5 |
| Docker: unhealthy containers (failing healthcheck) | +10 |
| **SEC‑015 – Privileged non‑root implant on network** | **+60** |
| **SEC‑016 – Known malicious process (by name)** | **+60** |
| **SEC‑017 – Fileless malware (deleted executable / memfd)** | **+60** |
| **SEC‑018 – Suspicious cron job (persistence)** | **+20** |
| **SEC‑019 – Fileless malware with critical kernel caps** | **+60** |
| **SEC‑020 – Kernel‑thread masquerading process** | **+60** |
| **SEC‑021 – Bind‑mount / overlay masking** | **+60** |
| **SEC‑022 – Reverse shell / C2 connection** | **+60** |
| **SEC‑023 – Userspace rootkit / library injection** | **+60** |
| **SEC‑024 – True Ghost PID (LKM rootkit)** | **+60** |
| **SEC‑025 – Downgraded PID visibility mismatch** | **+20** (no exit code escalation) |
| **DOCK‑010 – Container runtime capability tampering** | **+60** |
| **CAP‑001 (dynamic) – Non‑root with critical capabilities** | **+8 (loopback) / +20 (wildcard exposure)** |

---

## What It Scans

| Category | Details |
| --- | --- |
| System | OS, kernel, uptime, CPU, RAM, load average, LSM modules |
| Security | SSH config (effective and fallback), root login, password auth, users, authorized keys, login history, fail2ban & auditd presence, **sudo NOPASSWD entries, sudoers permissions, sysctl security audit, malware/intrusion detection** |
| Network | Listening ports with bind address (red = exposed on 0.0.0.0/::), firewall (ufw, firewalld, nftables, iptables), DNS, SSL certificates with expiry |
| Storage | Disk usage, inode usage per mount |
| Docker | Images, dangling layers, containers, mounts, log sizes, privileged flag, memory/CPU limits, dangerous capabilities, **sensitive host mounts, OOM kills, restart loops, health status** |
| Packages | Installed count, upgradable, security updates (apt/dnf/yum/pacman/zypper) |
| Databases | PostgreSQL, MySQL, Redis, MongoDB — versions and data sizes |
| Internals | Cron jobs (with severity classification), systemd timers, /etc/hosts overrides, kernel errors, failed systemd units |
| Backups | Detection of restic, borg, duplicati, rsync/backup in cron |
| NTP | Time synchronization status and offset |
| **Malware & Intrusion** | **Full /proc sweep for known malicious processes, fileless executables, memfd implants, bind‑mount masking, reverse shells, library injection, hidden PIDs (LKM rootkit), container runtime capability tampering** |

---

## Infrastructure Services & Remediation

Owlzops provides high-tier engineering and security consulting to remediate the architectural vulnerabilities discovered by this scanner. We don't just find the holes; we close them.

| Finding Category | Business Impact | Our Service |
| --- | --- | --- |
| **Active compromise detected (SEC‑015…024)** | Evidence of a rootkit, backdoor, or fileless malware. Immediate incident response is required to isolate and expel the threat. | **Compromise Assessment:** Deep forensic analysis to answer "Who is in our servers right now?" and secure the perimeter. |
| **Risk Score ≥ 70 / Firewall disabled / Socket Mounts** | The infrastructure has systemic architectural flaws exposing you to automated exploitation or container escapes. | **Infrastructure Hardening:** We rebuild your VPCs, implement strict firewall policies, and deploy secure rootless container environments. |
| **Pending updates / CIS Benchmark gaps** | You are accumulating technical debt and will fail compliance audits. | **Compliance Readiness:** Engineering consultation to align your infrastructure with strict SOC 2 and ISO 27001 requirements before the official auditor arrives. |

If `owlzops-mapper` flagged critical issues on your production fleet, we can review your JSON report and provide a concrete remediation plan.

→ [Book a free Compromise Assessment consultation](https://owlzops.com/contact?utm_source=github&utm_medium=readme&utm_campaign=mapper_table)

We review your scan before the call. No pitch — just engineering facts.

---

## Why Rust?

Single static binary. No runtime, no Python, no dependencies to install on
the target server. Copy it, run it, done.

---

## Building from Source

```bash
git clone https://github.com/OWLZOPS/owlzops-mapper
cd owlzops-mapper
cargo build --release
sudo ./target/release/owlzops-mapper audit
```

For static musl build (recommended for remote scanning):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Requires: Rust 1.85+, Linux target.

Our CI pipeline pins all GitHub Actions by commit SHA, includes `cargo audit`, `cargo deny`, and generates an SBOM on every release – see the [workflows](.github/workflows) for details.

---

## Verifying Releases

All release artifacts are GPG-signed and SHA256 checksums are published.
The project public key is [`gpg-public-key.asc`](gpg-public-key.asc).
To verify:

```bash
gpg --import gpg-public-key.asc
gpg --verify owlzops-mapper-linux-x86_64.tar.gz.asc owlzops-mapper-linux-x86_64.tar.gz
```

The install script (`install.sh`) now performs GPG verification automatically if `gpg` is available.

---

## License

**Apache-2.0 with Commons Clause** - free to use, not to resell.

**Is it free for my company?**
Yes. You are 100% free to use owlzops-mapper for commercial purposes, corporate infrastructure audits and internal security checks.

The Commons Clause simply prevents third parties from taking this codebase and directly reselling it as their own commercial software or SaaS product.
See [LICENSE](LICENSE) for details.

---

## Previous Releases

<details>
<summary>Click to expand changelog</summary>

### v0.5.11 (2026-07-10)

**Indicators of Compromise (IoC) Detection Pipeline**

* **SEC‑015 – Privileged non‑root implant on network** – flags processes holding critical kernel capabilities, listening on a wildcard address, and running from an ephemeral path (`/tmp`, `/dev/shm`, `/home`, `/var/tmp`). Weight: 60.
* **SEC‑016 – Known malicious process names** – full `/proc` sweep against a compile‑time blocklist (`xmrig`, `kinsing`, `kdevtmpfsi`, `sysupdate`, `networkservice`). Explicit names are flagged unconditionally; ambiguous names (e.g., `networkservice`) require ephemeral‑path corroboration. Weight: 60.
* **SEC‑017 – Fileless malware detection** – detects processes whose on‑disk executable has been deleted or that never touched the disk (`memfd_create`). FP‑protection excludes system‑path deletions (e.g., `apt upgrade`). Evidence differentiates “deleted from …” from “executing in‑memory (memfd)”. Weight: 60.
* **SEC‑018 – Suspicious cron jobs** – cron entries are classified into `Ok`, `Warning`, `Critical` tiers during collection. Critical patterns (reverse shells, downloads) raise a finding. Weight: 20. JSON export includes severity per cron job.

**Scoring & Predicate Hardening**

* **CAP‑001 dynamic weight** – escalates from 8 to 20 when a privileged non‑root process listens on a wildcard address, aligning severity with SEC‑013.
* **Unified network & path predicates** – `is_wildcard_bind`, `is_loopback_bind` (now covers full `127.0.0.0/8` and `::ffff:…`), and `is_ephemeral_exec_path` (includes `/memfd:`) extracted to `utils.rs`; all modules share a single source of truth.
* **Exposure escalation guard** – compare logic now correctly ignores dual‑stack configurations where a wildcard was already present, preventing false drift alerts.
* **Scoring version guard** – `SCORING_VERSION` bumped to **7** so fleet‑compare marks score changes from the expanded predicate coverage as `~ Changed` instead of false degradations.

**UI & Export Improvements**

* **Categorised Risk Breakdown** – findings are displayed in separate tables (🛡 Security, ⚙ Reliability, 🧹 Hygiene) for instant visual triage.
* **Dynamic table widths** – all long‑content tables (Cron, Docker, Capabilities) use `ContentArrangement::Dynamic` with a safe fallback; borders never break in piped SSH sessions.
* **Cron job classification in UI** – each cron entry is colour‑coded by severity (OK / Review / Suspicious!).
* **Non‑root capability table** – replaced plain‑text listing with a structured table showing process, PID/EUID, capabilities, and security flags.

### v0.5.10 (2026-07-09)

**Observability & Correctness**

* Coverage warnings (truncated files, inaccessible /proc entries) are now displayed in both terminal and Excel reports.
* Port attribution failures due to permission errors are now aggregated and reported as a coverage warning.
* Binary upload via the russh channel now waits for the remote command to finish and checks its exit status. Failures (disk full, permissions) are surfaced as `UploadFailed` errors.

**Fleet Orchestration**

* JSONL writer uses a conditional 2‑second timeout only during shutdown.
* `SIGINT` / `SIGTERM` immediately abort in‑flight SSH sessions via `tokio::sync::Notify` + `JoinSet::abort_all()`. Fixed lost‑signal edge case by switching from `notify_waiters` to `notify_one`.

**Security & Platform Support**

* Sudoers file filtering now follows `sudoers(5)` rules exactly (files containing `.` or ending with `~` are ignored). Read errors are logged as coverage warnings.
* TOFU trust store fails closed when `$HOME` is unset (no `/tmp` fallback).
* Legacy SSH path (`run_remote_scan`) now uses `split_host_port` and passes ports explicitly to `ssh`/`scp`. IPv6 addresses are correctly bracketed for SCP.

**UX Improvements**

* DNS upstreams: when `systemd-resolved` stub is detected, real upstream servers are shown alongside the stub.
* Reboot reason: the packages triggering a reboot request are listed.
* DLP context: secret leak findings now include the PID and process name.
* Cronjobs: renamed to “System & Custom Cronjobs”; suspicious entries are highlighted, ordinary system cron is no longer marked as dangerous.
* Risk Score: switched to penalty notation (e.g. `Security −60`) with a verbal health label (Healthy / At Risk / Critical).

**Docker Metrics Migration**

* Reclaimable Space: uses `docker system df` (bollard `df()`) to report real reclaimable space instead of summing virtual sizes.
* Image sizes: total size now uses `df.layers_size` (real disk usage), dangling images show their virtual size for context, and container sizes include `SizeRw` (writable layer).
* UI/Excel: headers updated to “Real Disk Size (Images)” and “Dangling Virtual Size (GB)”.

**Container Runtime & Orchestrator Detection**

* Added recognition of `dockerd`, `containerd`, and Kubernetes‑related processes in host scanning.

### v0.5.9 (2026-07-08)

**Observability**

* Coverage warnings (truncated files, inaccessible /proc entries) are now displayed in both terminal and Excel reports.
* Port attribution failures due to permission errors are now aggregated and reported as a coverage warning.

**Reliability & Compatibility**

* Fixed a lost‑signal edge case in graceful shutdown by switching from `notify_waiters` to `notify_one`.
* Replaced `unwrap()` on output file paths with `to_string_lossy()` to prevent panics on non‑UTF‑8 paths.
* `PackageManager` deserialization now maps unknown future variants to `Unknown` for forward compatibility.

**Hygiene**

* Removed ineffective `debug = "limited"` from the release profile.
* Unified timeout budget calculation (`host_budget_secs`) shared between fleet orchestrator and russh engine.

### v0.5.8 (2026-07-08)

**Observability & Correctness**

* R9-01: Coverage warnings (truncated files, inaccessible /proc entries) are now reported in the audit output (`coverage_warnings` field).
* R9-02: Binary upload via the russh channel now waits for the remote command to finish and checks its exit status. Failures (disk full, permissions) are surfaced as `UploadFailed` errors.
* R9-05: Sudoers file filtering now follows `sudoers(5)` rules exactly (files containing `.` or ending with `~` are ignored). Read errors are logged as coverage warnings.

**Fleet Orchestration**

* R9-03: The JSONL writer is no longer subject to a hard 2‑second timeout on success; it drains completely. The timeout is only applied during graceful shutdown.
* R9-04: `SIGINT` / `SIGTERM` now immediately aborts in‑flight SSH sessions via `tokio::sync::Notify` and `JoinSet::abort_all()`, instead of waiting for a task to complete.

**Security & Platform Support**

* R9-06: The legacy SSH path (`run_remote_scan`) now uses `split_host_port` and passes ports explicitly to `ssh`/`scp`. IPv6 addresses are correctly bracketed for SCP.
* R9-07: The TOFU trust store no longer falls back to `/tmp` when `$HOME` is unset. The mapper fails with a clear error instead of using a world‑writable directory.
* DLP scanner now reuses a single `String` buffer for path construction, reducing per‑process allocations.

### v0.5.7 (2026-07-08)

**Security**

* R8-01: Cap remote stdout/stderr in russh path to prevent OOM from untrusted hosts.
* R8-02: Fix false `HostKeyChanged` when multiple key types exist in known_hosts.
* R8-05: Include exact known_hosts file path in host key error messages.
* R8-07: Set `stdin(Stdio::null())` on child processes to prevent terminal hijacking.
* R8-08: Handle SIGTERM and improve SIGINT with graceful shutdown, abort active SSH sessions immediately.

**Stability & Compatibility**

* R8-03: Cap child stderr at 1 MiB in legacy SSH path.
* R8-04: Support IPv6 addresses (bare and `[::1]:port`) in `split_host_port`.
* R8-06: Add `#[serde(default)]` to `HostInfo` for forward compatibility with older snapshots.

**Performance & Hygiene**

* Replace external SCP/SSH upload with internal russh channel – real-time progress bar, no dependency on system `scp`.
* N8-1: Avoid extra UTF-8 allocation in `read_file_capped`.
* N8-2: Replace `Vec<&str>` collection in `/proc/net` parser with an iterator.
* N8-3: Deduplicate listening ports using a `HashSet`.
* N8-5: Include accurate hostname in `RemoteError::Ssh` errors.
* N8-6: Use `safe_io` for `/proc/<pid>/comm` reads in DLP scanner.
* N8-7: Progress bar for file upload replaced with animated spinner (legacy) or real-time progress (russh).

### v0.5.6 (2026-07-08)

*(identical to 0.5.7 except for the SCP replacement and abort_all improvements)*

### v0.5.5 (2026-07-07)

### Security

* R7-05: Implement TOFU + HMAC-SHA1 verification for russh host keys. Store newly accepted keys in `~/.owlzops/known_hosts`. Detect changed keys (`HostKeyChanged`).
* R7-09: Enable keepalive in russh client config to prevent long scans from timing out.
* PIVOT-1: Sanitize terminal output to prevent escape sequence injection.
* PIVOT-2: Prevent XLSX formula injection by prefixing `'` to strings starting with `=`, `+`, `-`, `@`.
* Hardened child process environment: clear environment (`env_clear`), fixed `PATH`, resolve tools to absolute paths to block `LD_PRELOAD`/`PATH` hijacking.

### Stability

* Capped reads for `/proc`, `/proc/*/environ`, and child stdout/stderr to prevent OOM on untrusted inputs. Truncation events are reported as scan warnings.
* Docker scanner: moved synchronous `fs::metadata` out of async runtime into `spawn_blocking` to avoid blocking Tokio executor.

### v0.5.4 (production reliability)

* **Scanner isolation restored** – `panic = "abort"` removed; individual scanner panics now degrade gracefully instead of aborting the whole scan.
* **UDP listeners detected** – `/proc/net` parser fixed; UDP ports now appear in `listening_ports`.
* **Clean machine‑readable output** – tracing logs now go to stderr; stdout always contains valid JSON.
* **Fleet‑drift with streaming** – `compare --multi-host` now reads JSONL files produced by fleet scans.
* **Input validation for russh** – host, user, and remote path are now validated before use.
* **Miscellaneous hardening** – timeout budgets unified, keepalive added to russh, panic‑free path handling, deterministic process attribution.

### v0.5.3 (IAM, Process Attribution, DLP)

* **IAM & Access Alignment** – audit SSH keys for algorithm, bit length, and policy compliance; detect `NOPASSWD: ALL` in sudoers. Both findings include CIS references.
* **Process Attribution (Zero‑Setup)** – replaced the `ss` utility with direct `/proc/net` parsing; every listening port now shows the exact binary path and PID. Suspicious listeners (Shadow IT) are flagged as critical.
* **DLP / Secret Hygiene** – scans process memory (`/proc/*/environ`, `cmdline`) for exposed credentials (AWS keys, GitHub tokens, database URLs). Detected leaks are reported without saving secret values.
* **Fleet Orchestration** – `--max-concurrent` controls parallelism; global per‑host timeouts prevent stuck tasks from blocking the queue; optional JSONL streaming output for massive fleets without memory bloat.
* **Local hosts in fleet mode** – localhost is now included in multi‑host terminal, XLSX, and JSONL reports.

### v0.5.2 (async SSH + Docker audit)

* **Async SSH engine (`russh`)** – fleet scans now support `--ask-sudo-pass` to authenticate via password without pre‑configuring `NOPASSWD` on every host. Known‑hosts TOFU verification with warnings.
* **Progress bar for `--copy-binary**` – binary uploads show a real‑time progress bar with file size and ETA, in both legacy and async SSH paths.
* **Docker reliability findings** – OOM‑killed containers, restart loops, and unhealthy healthchecks are now detected and scored under the Reliability category (`DOCK‑007…DOCK‑009`).
* **Sensitive mount detection** – containers mounting the Docker socket, host root, or writable sensitive directories are flagged as high‑risk (`DOCK‑005`, `DOCK‑006`) with CIS references.
* **Scoring version guard** – `risk_score` differences caused by formula updates are now marked as `Changed` instead of false improvements/degradations, preserving drift accuracy in `compare`.
* **Compare v2** – metadata header with hostname, timestamps, binary version and time span; deterministic diff order; multi‑host summary with Added/Removed/Compared statuses.
* **UX polish** – `--keep-binary` flag to skip cleanup after remote scan; emojis and ANSI colours are automatically disabled when stdout is piped; `--max-concurrent` controls fleet parallelism; file descriptor limit raised automatically.

### v0.5.1 (compare v2)

* **Rich diff metadata** – terminal and Excel diffs now show hostname, timestamps, binary version, and time span between snapshots.
* **Scoring version guard** – `risk_score` changes across different scoring engine versions are marked as `Changed`, preventing false drift.
* **Deterministic diff order** – byte‑identical reports for the same snapshots, safe for version control.
* **Multi‑host summary** – fleet diffs show summary line and status tags (`[+ added]`, `[− removed]`).
* **Extended SSL tracking** – warning‑level expiry and newly added certificates are detected.
* **Port diff optimization** – zero‑copy O(n) comparison.

### v0.5.0

* **Context‑aware scoring** – `ip_forward` and `suid_dumpable` are no longer flagged on Docker/kubelet hosts or when systemd‑coredump is active.
* **Graduated weights** – SSH `PermitRootLogin` differentiates `prohibit‑password`; security updates are tiered; sudo `NOPASSWD` distinguishes `ALL` from restricted commands.
* **Docker security findings** – containers missing memory/CPU limits, privileged mode, and dangerous capabilities now directly affect Risk Score.
* **CIS Benchmark references** – every finding includes a CIS reference (e.g., `CIS 5.2.10`) for immediate audit compliance mapping.
* **Sub‑scores** – Security, Reliability, and Hygiene now have individual caps (60/30/10), preventing score saturation and enabling drift visibility.
* **Transparent Breakdown** – the terminal dashboard now shows the exact active findings with weights and CIS tags.

</details>
```