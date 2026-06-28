# owlzops-mapper
[![CI](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/OWLZOPS/owlzops-mapper?include_prereleases&style=flat)](https://github.com/OWLZOPS/owlzops-mapper/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0%20with%20Commons%20Clause-blue.svg)](LICENSE)

> One binary. One command. Full picture of your server - now with **Risk Score**, **multi‑host remote audit** and **snapshot diff**.

**owlzops-mapper** is a self-contained Rust binary that performs a complete
Linux server audit in seconds and exports the result to Excel, JSON or
terminal. No internet required. No data leaves the server.

For sysadmins it's instant inventory. For CTOs it's technical debt visibility. For CEOs it's
risk and cost optimization.

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

## Usage

### Local audit
```bash
# Terminal dashboard (default, fully offline)
sudo ./owlzops-mapper audit

# Export to Excel (with Executive Summary as first sheet)
sudo ./owlzops-mapper audit --format excel --output report.xlsx

# JSON for programmatic use
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
# Scan a single remote host (binary must be present at /tmp/owlzops-mapper)
sudo ./owlzops-mapper audit --host 192.168.1.10 --ssh-user root

# Scan multiple comma-separated hosts
sudo ./owlzops-mapper audit --host 192.168.1.10,192.168.1.11 --ssh-user root

# Automatically copy the local static binary to the remote host first.
# Release binaries are static (musl), so --copy-binary works out of the box.
sudo ./owlzops-mapper audit --host 192.168.1.10 --ssh-user root --copy-binary

# If you built your own binary (e.g. debug build), point to the musl release:
sudo ./owlzops-mapper audit --host 192.168.1.10 --ssh-user root --copy-binary \
  --local-binary target/x86_64-unknown-linux-musl/release/owlzops-mapper

# Scan multiple hosts from a file (one per line)
sudo ./owlzops-mapper audit --hosts hosts.txt --ssh-user root --copy-binary

# Multi-host Excel report with one sheet per host
sudo ./owlzops-mapper audit --hosts hosts.txt --ssh-user root --format excel --output fleet-audit.xlsx
```

### Comparing snapshots (diff)
```bash
# Compare two JSON snapshots in terminal (colored table)
./owlzops-mapper compare before.json after.json

# Export diff to JSON
./owlzops-mapper compare before.json after.json --format json > diff.json

# Export diff to Excel (color-coded: green=improved, red=degraded, yellow=changed)
./owlzops-mapper compare before.json after.json --format excel --output diff.xlsx
```

---

## Command-Line Options

| Flag | Description |
|------|-------------|
| `-f, --format` | Output format: `text` (default), `json`, `xlsx` (or `excel`) |
| `-o, --output` | Output file for Excel reports (default: `owlzops-report-<hostname>-YYYY-MM-DD_HH-MM-SS.xlsx`) |
| `--external-ip` | Fetch public IP via outbound request (off by default) |
| `--refresh-packages` | Update package cache before scanning (off by default) |
| `--offline` | Disable **all** network calls. Overrides other flags if combined |
| `--host <HOST>` | Single hostname/IP (or comma‑separated list) for remote scanning |
| `--hosts <FILE>` | File with one hostname/IP per line for remote scanning |
| `--ssh-user <USER>` | SSH user for remote connections (default: `root`) |
| `--ssh-key <PATH>` | Path to SSH private key (default: `~/.ssh/id_rsa`) |
| `--copy-binary` | Copy the local binary to remote hosts before scanning. The binary **must** be statically linked (musl). GitHub release binaries are static, so you can safely use this flag with them. |
| `--local-binary <PATH>` | When using `--copy-binary`, path to a local static (musl) binary to copy instead of the currently running one. Useful if you're running a debug build locally but have a release build for remote hosts. |
| `--remote-path <PATH>` | Path where the binary is placed on remote hosts (default: `/tmp/owlzops-mapper`) |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

### Subcommands

| Command | Description |
|---------|-------------|
| `audit` | Run an audit scan (local or remote) |
| `compare <before> <after>` | Compare two JSON snapshots and show drift |

---

## Exit Codes

| Code | Single Host | Multi-Host (Fleet) |
|------|-------------|---------------------|
| `0`  | No critical issues found | All hosts clean |
| `1`  | One or more critical findings (firewall disabled, SSH root login permitted, pending security updates, SSL certificate about to expire, failed services, missing backups, NTP not synced, sudo NOPASSWD entries, sysctl issues ≥ 3) | Any host has critical issues |
| `2`  | Not running as root – results may be incomplete | Any host not running as root |

You can use these codes directly in CI/CD pipelines:
```bash
sudo ./owlzops-mapper audit || echo "Security scan failed – check the report"
```

---

## Risk Score

The dashboard and Excel report include a **Risk Score (0–100)** calculated
from real findings:

| Finding | Penalty |
|---|---|
| Firewall inactive | +30 |
| SSH root login allowed | +25 |
| Pending security updates | +20 |
| SSL certificate expires within 7 days | +15 (max) |
| Failed systemd services | +10 |
| SSH password authentication enabled | +10 |
| OOM kills present | +10 |
| No backup tools detected | +20 |
| NTP not synchronized | +10 |
| Sudo NOPASSWD entries found | +10 |
| Sudoers permissions not 0440 | +5 |
| Sysctl security issues | +5 per issue (max +15) |

Lower scores are better. The score is displayed in colour (green < 40, yellow 40–69, red ≥ 70)
and placed prominently at the top of every report.

---

## What It Scans

| Category | Details |
|---|---|
| System | OS, kernel, uptime, CPU, RAM, load average, LSM modules |
| Security | SSH config (effective and fallback), root login, password auth, users, authorized keys, login history, fail2ban & auditd presence, **sudo NOPASSWD entries, sudoers permissions, sysctl security audit** |
| Network | Listening ports with bind address (red = exposed on 0.0.0.0/::), firewall (ufw, firewalld, nftables, iptables), DNS, SSL certificates with expiry |
| Storage | Disk usage, inode usage per mount |
| Docker | Images, dangling layers, containers, mounts, log sizes, privileged flag, memory/CPU limits, dangerous capabilities |
| Packages | Installed count, upgradable, security updates (apt/dnf/yum/pacman/zypper) |
| Databases | PostgreSQL, MySQL, Redis, MongoDB — versions and data sizes |
| Internals | Cron jobs, systemd timers, /etc/hosts overrides, kernel errors, failed systemd units |
| Backups | Detection of restic, borg, duplicati, rsync/backup in cron |
| NTP | Time synchronization status and offset |

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

Apache-2.0 with Commons Clause - free to use, not to resell.
See [LICENSE](LICENSE) for details.