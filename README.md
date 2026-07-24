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


**Option 3 – macOS orchestrator (remote-only):**

```bash
# Install the orchestrator (auto-detects macOS)
curl -sSL https://raw.githubusercontent.com/OWLZOPS/owlzops-mapper/main/install.sh | sh
```
```bash
# Download the Linux agent SEPARATELY and rename it to avoid overwriting the orchestrator
curl -L https://github.com/OWLZOPS/owlzops-mapper/releases/latest/download/owlzops-mapper-linux-x86_64.tar.gz | tar xz
mv owlzops-mapper owlzops-agent-linux
```
```bash
# Run a remote audit – you MUST pass --local-binary so the Linux agent is uploaded
./owlzops-mapper audit --deep \
  --host 192.168.1.10 \
  --ssh-user operator \
  --ssh-key ~/.ssh/id_rsa \
  --remote-path /tmp/owlzops-mapper \
  --copy-binary \
  --local-binary ./owlzops-agent-linux \
  --ask-sudo-pass
  ```
> **Important for macOS users:** The macOS orchestrator cannot perform local scans.  
> Always download the Linux agent separately and rename it (`owlzops-agent-linux`).  
> If you do not rename it, the Linux binary will overwrite the macOS orchestrator,  
> resulting in a «cannot execute binary file» error.  
> Use `--local-binary` to point to the Linux agent when scanning remote hosts.

## Core Features (Agentless EDR-lite)

* **Active Compromise & Threat Hunting (IoC)** – Sweeps memory (`/memfd`), deleted executables, ephemeral paths (`/dev/shm`, `/tmp`), and network state to detect hidden rootkits, reverse shells, library injection, and fileless malware in milliseconds.
* **Deep Memory Forensics** – When invoked with `--deep`, the mapper reads process memory via `process_vm_readv`, resolves pointers, calculates Shannon entropy, detects binary prologues and image headers. Untrusted executable payloads escalate directly to **SEC‑028** (Critical).
* **Trust‑but‑Verify Policy** – A content‑bound verdict cache replaces static allowlists. Memory that cannot be positively attributed as legitimate JIT code is flagged as **SEC‑029** (Provisional Trust), visible to the operator and auditable.
* **Container‑aware Structural Provenance** – Mount namespace detection and secure `/proc/pid/exe` resolution prevent false positives for containerised JIT processes (node, next-server). Container‑root binaries are capped at provisional trust.
* **Deep Container Forensics & Escape Detection** – Analyzes Docker/containerd runtimes for privileged container abuses, sensitive host mounts (`/var/run/docker.sock`), capability leakage, and missing resource limits. All mapped to CIS benchmarks.
* **Agentless Fleet Orchestration** – Drop the binary via SSH, scan dozens of servers in parallel, and clean up automatically. Supports both passwordless sudo and **password‑based sudo** (`--ask-sudo-pass`). Zero permanent footprint.
* **Snapshot Diffing & Drift Monitoring** – Capture server state as JSON snapshots, compare any two, and get color‑coded Excel/terminal diffs of exactly what changed (new open ports, changed capabilities, added cronjobs).
* **Context‑aware Risk Score** – Findings are evaluated with awareness of the environment (e.g., Docker/kubelet hosts are not penalized for `ip_forward=1`). Sub‑scores for Security, Reliability, and Hygiene prevent score saturation.
* **CIS Benchmark Mapping** – Every security finding includes a strict reference to the corresponding CIS Benchmark rule (e.g., `CIS 5.2.10`), ready for compliance audits.
* **Air‑gapped & SIEM-ready** – A single static binary with no runtime dependencies. `--offline` mode guarantees zero outbound calls. Exports rich Excel dashboards or flat JSONL for immediate SIEM ingestion.

---

## Highlights v0.5.25

**R19 Audit Completion — Inventory Accuracy & CI Hardening**

- **File capability mask now covers all 64 bits.**  
  Capability bits beyond the 41st are no longer silently dropped; they are reported as `cap_<N>`. A file with *only* inheritable or effective capabilities (permitted = 0) is now correctly included in the inventory instead of being discarded (R19‑05).
- **Unified filesystem walker.**  
  `setuid` and `file_capabilities` scanners now share a single recursive traversal (`fs_inventory`). Duplicate hardlinks are deduplicated **before** consuming the per‑directory budget, eliminating non‑determinism and false “budget exhausted” warnings (R19‑06, R19‑14, R19‑15).
- **Sudoers parsing matches real `sudo` behaviour.**  
  Files with a `.` (including `.conf`) or ending with `~` inside `sudoers.d` are now correctly ignored, matching the behaviour of the real sudo parser (R19‑13).
- **Honest provenance when the APK database is truncated.**  
  A new `PartialApk` provenance variant prevents files from being incorrectly flagged as “not owned by any package” when `/lib/apk/db/installed` was capped during reading (R19V5‑05).
- **macOS orchestrator CI is fully linted.**  
  All local‑only modules are now gated behind `#[cfg(feature = "local-scan")]`, allowing `cargo clippy --no-default-features` to pass cleanly. The macOS build is guarded against regressions.
- **Stronger CI guards.**  
  Every job now has an explicit `timeout‑minutes`. The E2E interrupt test distinguishes a graceful shutdown from a plain signal death and catches the case where the scan finishes before SIGINT arrives.

---

## Usage

### Local audit & Forensics

```bash
# Standard fast‑path audit
sudo ./owlzops-mapper audit

# Deep forensic scan (memory pointers, entropy, image headers)
sudo ./owlzops-mapper audit --deep

# Verbose terminal output (full VMA detail)
sudo ./owlzops-mapper audit --deep -v

# Export to Excel
sudo ./owlzops-mapper audit --deep --format excel --output report.xlsx
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
| `--deep` | Enable deep forensic scan: memory pointer resolution, entropy, binary header detection, and ghost PID (LKM rootkit) scanning |
| `--verdict-cache <PATH>` | Path to the deep‑forensics verdict cache (default: `/var/lib/owlzops/verdict-cache.json`) |
| `-v, --verbose` | Show full per‑VMA detail in memory anomaly tables (useful with `--deep`) |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

### Subcommands

| Command | Description |
| --- | --- |
| `audit` | Run an audit scan (local or remote) |
| `snapshot` | Run an audit and save the JSON snapshot to disk |
| `compare <before> <after>` | Compare two JSON snapshots and show drift |
| `dir-compare <dir>` | Compare the two most recent snapshots in a directory |
| `--deep` | Enable deep forensic scan: ghost PID (LKM rootkit) detection, extended /proc probing, and memory forensics. Root only. |
| `-v, --verbose` | Show full per‑region detail in memory tables (only effective with text output) |

---

## Exit Codes

| Code | Single Host | Multi-Host (Fleet) |
| --- | --- | --- |
| `0` | No critical issues found | All hosts clean |
| `1` | One or more critical findings (firewall disabled, SSH root login permitted, pending security updates, SSL certificate about to expire, failed services, missing backups, NTP not synced, sudo NOPASSWD entries, sysctl issues ≥ 3) | Any host has critical issues |
| `2` | Not running as root, scan warnings present, **or fleet scan produced zero reports** | Any host not running as root, **or all remote hosts failed** |
| `3` | **Active compromise detected** (IoC findings SEC‑015…SEC‑024, SEC‑028, DOCK‑010) | **Any host shows active compromise** |

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
| **SEC‑028 – Unattributed executable payload in memory (deep forensics)** | **+60** |
| **SEC‑029 – Provisional trust (allowlisted binary, memory unverified)** | **0** (auditable, no penalty) |
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
| **Memory Forensics (‑‑deep)** | **Process memory reading, pointer resolution (O(log N)), Shannon entropy, binary headers, prologue detection, origin attribution (FFI, GObject, JVM, trampoline), content‑bound verdict caching** |
| **Malware & Intrusion** | **Full /proc sweep for known malicious processes, fileless executables, memfd implants, bind‑mount masking, reverse shells, library injection, hidden PIDs (LKM rootkit), container runtime capability tampering, ghost inode recovery via map_files** |

---

## Infrastructure Services & Remediation

Owlzops provides high-tier engineering and security consulting to remediate the architectural vulnerabilities discovered by this scanner. We don't just find the holes; we close them.

| Finding Category | Business Impact | Our Service |
| --- | --- | --- |
| **Active compromise detected (SEC‑015…024, SEC‑028)** | Evidence of a rootkit, backdoor, or fileless malware. Immediate incident response is required to isolate and expel the threat. | **[Infrastructure Security Audit](https://owlzops.com/#assessment:~:text=here%20%C2%B7%20one%2Doff-,Infrastructure%20Security%20Audit,-%22What%20is%20exposed):** Deep forensic analysis to answer "Who is in our servers right now?" and secure the perimeter. |
| **Risk Score ≥ 70 / Firewall disabled / Socket Mounts** | The infrastructure has systemic architectural flaws exposing you to automated exploitation or container escapes. | **[Infrastructure Hardening](https://owlzops.com/#hardening:~:text=hands%2Don-,Infrastructure%20Hardening,-%22We%20close%20the%20gaps):** We rebuild your VPCs, implement strict firewall policies, and deploy secure rootless container environments. |
| **Pending updates / CIS Benchmark gaps** | You are accumulating technical debt and will fail compliance audits. | **[Compliance Readiness](https://owlzops.com/#assessment:~:text=SOC%202%20or%20ISO%2027001%20auditor):** Engineering consultation to align your infrastructure with strict SOC 2 and ISO 27001 requirements before the official auditor arrives. |

If `owlzops-mapper` flagged critical issues on your production fleet, we can review your JSON report and provide a concrete remediation plan.

→ [Book a free Infrastructure Security Audit consultation](https://owlzops.com/contact?service=assessment&utm_source=github&utm_medium=readme&utm_campaign=mapper_table)

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
<summary>Click to expand changelog (last 5 versions)</summary>

### v0.5.24 (2026-07-24)

**R19 Audit Fixes — Graceful Degradation & Drift Detection**

- **ProvenanceSource no longer lies when the DB is unreadable.**  
  A present but unreadable package database (EACCES, restrictive mount) is now reported as `Unavailable` instead of `Dpkg` with an empty map, preventing false “unexpected” classifications for every system binary.
- **Sudoers audit now emits coverage warnings on I/O errors.**  
  Unreadable `/etc/sudoers` (e.g. mode 0440 without root) no longer silently produces an empty NOPASSWD list. The operator sees a coverage warning instead of a false-negative.
- **Capped I/O in dpkg/apk backends + basename pre‑filter.**  
  Both resolvers now respect the project‑wide capped‑I/O policy, closing an OOM vector and reducing allocation pressure by ~1000×.
- **Structural capability baseline works on RPM/Arch hosts.**  
  `classify_cap_binary` checks the known‑binary list before consulting the package database, so `ping`, `mtr`, `dumpcap` are recognised even when the DB is unavailable.
- **Double‑stat eliminated in setuid scanner.**  
  Halves the number of `stat` syscalls and closes a TOCTOU window.
- **eBPF inventory completed.**  
  Link objects (kprobe/tracepoint attachments) are now collected, `prog_tag` is extracted, and dropped objects are reported as coverage warnings. Pin‑scan is protected against symlink traversal and stack overflow.
- **Two‑phase Ctrl‑C teardown.**  
  A first Ctrl‑C gives in‑flight tasks a 10 s grace period to finish and clean up remote binaries; a second Ctrl‑C aborts immediately.
- **Drift detection for setuid, capabilities, and eBPF.**  
  Snapshot comparison now reports added/removed setuid files, file capabilities, and changes in eBPF inventory.

### v0.5.23 (2026-07-22)

**Provenance‑Resolved Suppression for File Capabilities & Setuid**

- **Provenance crosses the SSH boundary.** The old `HashMap` transport is replaced by a `provenance_source` enum and per‑finding `package` fields. All findings are classified locally, but the verdict survives serialisation — fleet‑mode scoring is now consistent with local scans.
- **usrmerge‑aware canonical paths.** A single `canon_path` normaliser maps `/bin/su` → `/usr/bin/su` and `/lib/foo` → `/usr/lib/foo`. Both dpkg and APK backends use it on every line, eliminating manual alias branches.
- **Scan‑depth fix.** `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin` were previously skipped (`max_depth = 0`). Depth is now `1` — those directories are finally audited, dramatically increasing the setuid/capability inventory.
- **Per‑root budgets with exhaustion reporting.** Flat directories get 4 096 entries, recursive lib‑roots get 40 000. Truncation is reported per directory, so you know exactly which root was incomplete.
- **APK backend rewritten.** `/lib/apk/db/installed` is correctly parsed as a text file; `P:`, `F:`, and `R:` lines are interpreted according to the APK spec. Alpine‑based images work out of the box.
- **New classification functions.** `classify_cap_binary` and `classify_setuid` replace the old `is_known_*` helpers. Expected system files are suppressed (weight 0), while truly unattributed files receive appropriate weights based on location and ownership.
- **False‑positive suppression for snapd, GStreamer, sudo, ping, etc.** Standard system binaries with setcap/setuid are no longer flagged as “Unexpected”. The SEC‑036/‑037 warnings disappear on modern Ubuntu and Debian hosts.

### v0.5.22 (2026-07-18)

**Sixth Gate: Ghost Inode Content Recovery via `map_files`**

- **Ghost inode forensics (`--deep`)** – For deleted `.so` files still mapped in memory (`maps-so-unlink-on-load`), the scanner now reads the backing inode through `/proc/<pid>/map_files/<addr>` and performs streaming, constant‑memory entropy + ELF structure analysis.
- **Three new `Origin` variants** – `GhostCleanImage` (valid ET_DYN/ET_EXEC, low entropy), `GhostSuspectImage` (high entropy or non‑ELF), `GhostInconclusive` (mid‑band / truncated). Clean images are routed to SEC‑027 (Advisory), suspect payloads to SEC‑028 (Critical), unverifiable ones remain in SEC‑033 (visible, weight 0).
- **Invariant: `image_header` always false for ghost paths** – An ELF header in a recovered file is expected and benign. Setting `image_header = true` would cause Layer‑1 to escalate every clean recovered `.so` into a false SEC‑028. This invariant is enforced in the implementation and tested.
- **Graceful degradation** – If `map_files` is unreadable (EACCES, EPERM, ENOENT), the finding stays in SEC‑033 with `deep_forensics = None`. Remote SSH hosts cannot open `map_files` locally, so they remain in SEC‑033 by design.
- **Scoring & UI** – Layer 2b now branches on the new `Origin` values. New display strings in the terminal UI and JSON reports.
- **Increased `MAX_FINDINGS` from 64 → 128** – Prevents ghost‑eligible PIDs from being squeezed out by JIT‑advisory findings on machines with many Java processes.

### v0.5.21 (2026-07-18)

**macOS Orchestrator, False‑Positive Elimination & Transport Resilience**

- **macOS orchestrator (Apple Silicon):** A native `aarch64-apple-darwin` build is now available. It runs any remote scan (single host, fleet, snapshot) from macOS without requiring local audit support. The install script automatically selects the correct build, and the CI pipeline compiles the orchestrator on every push.
- **SEC‑026 false‑positive elimination:** Chrome V8 code‑cage (executable `[heap]` inside a JIT reservation) and heavy standalone applications (Telegram, AppImage) are now recognised by VMA‑topology and file‑text anchors, respectively. They are routed to **SEC‑029** (Provisional Trust, weight 0) instead of raising false alarms. All other detection remains intact — droppers and real heap‑spray still fire.
- **Drain‑time coverage scoping:** Coverage warnings from concurrent local and remote scans are now tagged with the correct scope at drain time. A single sequential drain point after fleet tasks guarantees correct attribution even if `coverage::record()` is later added to the SSH engine.
- **Safe teardown on timeout:** Binary cleanup and graceful SSH disconnect now execute **outside** the scan deadline, guaranteeing zero‑footprint even on slow or hung hosts.
- **io_uring soundness:** Fixed a use‑after‑free hazard in the ghost‑PID scanner when a signal interrupts `submit_and_wait`. In the rare failure case, resources are leaked instead of risking memory corruption.
- **Minor hardening:** Unified network decoders; XLSX formula injection guard now handles leading whitespace; semaphore acquisition correctly bails out when the scheduler is closed; `exe_provenance` is computed once per PID, not per memory region.

### v0.5.20 (2026-07-18)

**Structural JNI Trust — Netty/gRPC ghost inode reclassification & Transport Resilience**

- **False‑positive elimination for Netty/gRPC:** Legitimate JNI libraries loaded via `NativeLibraryLoader` (which deletes the `.so` after `dlopen`) are no longer classified as `SEC‑023` (weight 60). Instead, they are recognised by five structural gates and routed to the new **SEC‑033** (weight 0, suppressed, visible in reports).
- **Inode family analysis:** The scanner now builds segment families per `(dev, inode)` for deleted `.so` files, detecting the multi‑segment pattern produced by `ld.so` and distinguishing it from single‑shot `mmap` stagers. An `rwx` permission on *any* family segment poisons the whole inode.
- **Ghost inode transparency:** The `SEC‑033` finding includes the path to the live inode via `/proc/<pid>/map_files/<region_addr>`, enabling forensic recovery and verification of the deleted library’s content.
- **Safe teardown on timeout:** Binary cleanup and graceful SSH disconnect now execute **outside** the scan deadline, guaranteeing zero‑footprint even on slow or hung hosts. The fleet orchestrator adds a grace budget to accommodate teardown.
- **io_uring soundness:** Fixed a use‑after‑free hazard in the ghost‑PID scanner when a signal interrupts `submit_and_wait`. In the rare failure case, resources are leaked instead of risking memory corruption.
- **Coverage scope isolation:** Coverage warnings from concurrent local and remote scans are now tagged with the originating scan, preventing misleading attribution in fleet reports.
- **Legacy SSH removal:** The `snapshot` command now uses the pure‑Rust `russh` engine, eliminating the last dependency on the system `ssh`/`scp` binaries.
- **Blocking I/O eliminated:** Local binary upload and SSH key loading have been moved to async I/O and blocking thread‑pools, avoiding stalls of the tokio runtime under high concurrency.
- **Minor hardening:** XLSX formula injection guard now handles leading whitespace; duplicated network decoders have been unified; semaphore acquisition correctly bails out when the scheduler is closed.

</details>