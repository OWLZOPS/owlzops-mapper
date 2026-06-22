# owlzops-mapper
[![CI](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/OWLZOPS/owlzops-mapper?include_prereleases&style=flat)](https://github.com/OWLZOPS/owlzops-mapper/releases)
[![License](https://img.shields.io/github/license/OWLZOPS/owlzops-mapper?style=flat)](LICENSE)
> One binary. One command. Full picture of your server.

**owlzops-mapper** is a self-contained Rust binary that performs a complete
Linux server audit in seconds and exports the result to Excel, JSON or
terminal. No internet required. No data leaves the server.

For sysadmins it's instant inventory. For CTOs it's technical debt visibility. For CEOs it's
risk and and cost optimization.

---

## Quick Start

```bash
# Download the latest binary
curl -L https://github.com/OWLZOPS/owlzops-mapper/releases/latest/download/owlzops-mapper-linux-x86_64.tar.gz | tar xz
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

## What It Scans

| Category | Details |
|---|---|
| System | OS, kernel, uptime, CPU, RAM, load average, LSM modules |
| Security | SSH config, root login, users, authorized keys, login history |
| Network | Listening ports, firewall, DNS, SSL certificates with expiry |
| Storage | Disk usage, inode usage per mount |
| Docker | Images, dangling layers, containers, mounts, log sizes |
| Packages | Installed count, upgradable, security updates (apt/dnf/yum/pacman) |
| Databases | PostgreSQL, MySQL, Redis, MongoDB — versions and data sizes |
| Internals | Cron jobs, systemd timers, /etc/hosts overrides, kernel errors |

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

## License

Apache-2.0 with Commons Clause — free to use, not to resell.
See [LICENSE](LICENSE) for details.