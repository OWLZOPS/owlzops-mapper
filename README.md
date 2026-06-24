# owlzops-mapper
[![CI](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/OWLZOPS/owlzops-mapper?include_prereleases&style=flat)](https://github.com/OWLZOPS/owlzops-mapper/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0%20with%20Commons%20Clause-blue.svg)](LICENSE)

> One binary. One command. Full picture of your server – now with a built‑in **Risk Score** for instant security assessment.

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
sudo ./owlzops-mapper
```

**Option 2 – install script (verifies SHA256):**
```bash
curl -sSL https://raw.githubusercontent.com/OWLZOPS/owlzops-mapper/main/install.sh | sh
sudo ./owlzops-mapper
```

## Usage

```bash
# Terminal dashboard (default, fully offline)
sudo ./owlzops-mapper

# Export to Excel
sudo ./owlzops-mapper --format excel --output report.xlsx

# JSON for programmatic use
sudo ./owlzops-mapper --format json > snapshot.json

# Detect external IP (opt-in outbound request)
sudo ./owlzops-mapper --external-ip

# Refresh package cache before checking updates (apt/dnf/pacman)
sudo ./owlzops-mapper --refresh-packages

# Air-gapped / restricted network — guarantees zero outbound calls
sudo ./owlzops-mapper --offline
```

## Command-Line Options

| Flag | Description |
|------|-------------|
| `-f, --format` | Output format: `text` (default), `json`, `xlsx` (or `excel`) |
| `-o, --output` | Output file for Excel reports (default: `owlzops-report-<hostname>-YYYY-MM-DD.xlsx`) |
| `--external-ip` | Fetch public IP via outbound request (off by default) |
| `--refresh-packages` | Update package cache before scanning (off by default) |
| `--offline` | Disable **all** network calls. Overrides other flags if combined |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No critical issues found |
| `1`  | One or more critical findings (firewall disabled, SSH root login permitted, pending security updates, or SSL certificate about to expire) |
| `2`  | Not running as root – results may be incomplete |

You can use these codes directly in CI/CD pipelines:
```bash
sudo ./owlzops-mapper || echo "Security scan failed – check the report"
```

## Risk Score

The dashboard and Excel report now include a **Risk Score (0–100)** calculated
from real findings:

- Firewall inactive (+30)
- SSH root login allowed (+25)
- Pending security updates (+20)
- SSL certificate expires within 7 days (+15)
- Failed systemd services (+10)
- SSH password authentication enabled (+10)
- OOM kills present (+10)

Lower scores are better. The score is displayed in colour (green < 40, yellow 40–69, red ≥ 70)
and placed prominently at the top of every report.

## What It Scans

| Category | Details |
|---|---|
| System | OS, kernel, uptime, CPU, RAM, load average, LSM modules |
| Security | SSH config (effective and fallback), root login, password auth, users, authorized keys, login history, **fail2ban & auditd presence** |
| Network | Listening ports with **bind address** (red = exposed on 0.0.0.0/::), firewall, DNS, SSL certificates with expiry |
| Storage | Disk usage, inode usage per mount |
| Docker | Images, dangling layers, containers, mounts, log sizes, **privileged flag, memory/CPU limits, dangerous capabilities** |
| Packages | Installed count, upgradable, security updates (apt/dnf/yum/pacman) |
| Databases | PostgreSQL, MySQL, Redis, MongoDB — versions and data sizes |
| Internals | Cron jobs, systemd timers, /etc/hosts overrides, kernel errors, **failed systemd units** |

## Why Rust?

Single static binary. No runtime, no Python, no dependencies to install on
the target server. Copy it, run it, done.

## Building from Source

```bash
git clone https://github.com/OWLZOPS/owlzops-mapper
cd owlzops-mapper
cargo build --release
sudo ./target/release/owlzops-mapper
```

Requires: Rust 1.75+, Linux target.

## Verifying Releases

All release artifacts are GPG-signed and SHA256 checksums are published.
The project public key is [`gpg-public-key.asc`](gpg-public-key.asc).
To verify:

```bash
gpg --import gpg-public-key.asc
gpg --verify owlzops-mapper-linux-x86_64.tar.gz.asc owlzops-mapper-linux-x86_64.tar.gz
```

## License

Apache-2.0 with Commons Clause - free to use, not to resell.
See [LICENSE](LICENSE) for details.