# owlzops-mapper

[![CI](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/OWLZOPS/owlzops-mapper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/OWLZOPS/owlzops-mapper?include_prereleases&style=flat)](https://github.com/OWLZOPS/owlzops-mapper/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0%20with%20Commons%20Clause-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-informational)](SECURITY.md)

**One static Rust binary. Sub-second Linux + Docker audit. No agents, no Python, no kernel modules.**

Finds reverse shells, fileless malware, ghost PIDs (LKM rootkits), container escapes, dangerous defaults and CIS gaps — then exits cleanly. Nothing stays on the box. Nothing phones home.

```bash
curl -L https://github.com/OWLZOPS/owlzops-mapper/releases/latest/download/owlzops-mapper-linux-x86_64.tar.gz | tar xz
sudo ./owlzops-mapper audit
```

Prefer signature verification handled for you? See [Install](#install) — the install script checks SHA256 and GPG before it writes anything.

<!-- DEMO: insert asciinema cast or GIF here, directly under the install block. -->

---

## Why this exists

Most scanners force you to choose:

| Tool | Typical trade-off |
|------|-------------------|
| **Lynis** | Excellent checklist, almost no live IoC or memory forensics |
| **osquery / Falco** | Powerful, but needs agents or eBPF and a heavier footprint |
| **chkrootkit / rkhunter** | Aging signatures, noisy false positives |
| **Trivy / kube-bench** | Strong on images and Kubernetes, weak on live host runtime state |

`owlzops-mapper` takes the opposite trade-off:

**one musl binary → drop via SSH → deep host + Docker state in seconds → gone.**

Built because running six different tools still left the question "is something already inside?" unanswered.

---

## What it actually catches

- **Active compromise** — reverse shells, memfd/fileless implants, library injection, bind-mount masking, known miners
- **Ghost PIDs / LKM rootkits** (`--deep`) — true hidden processes via `/proc` discrepancies
- **Container escapes** — `docker.sock` / Podman socket mounts, privileged containers, dangerous capabilities, missing resource limits
- **Classic landmines** — SSH root login + password auth, `sudo NOPASSWD:ALL`, wide-open listeners, disabled firewall
- **CIS-mapped findings** with evidence and penalty scores
- **Drift** — snapshot → compare → colour-coded Excel or terminal diff

Risk Score is split into **Security / Reliability / Hygiene** so one noisy category cannot hide a real problem.

---

## Example output (redacted)

```
🦉 Owlzops Mapper v0.5.28
🔍 Scan completed in 2.50s
🔒 Risk Score: 60/100 (At Risk)

Security −60  Reliability −0  Hygiene −0

🛡 Security Findings
╭──────────────────┬─────────┬──────────────────────────────────────╮
│ CIS / Ref        ┆ Penalty ┆ Finding                              │
╞══════════════════╪═════════╪══════════════════════════════════════╡
│ CIS 5.2.10       ┆ -25     ┆ SSH root login allowed               │
│ CIS 5.3          ┆ -15     ┆ Passwordless sudo to ALL commands    │
│ CIS 5.2.4        ┆ -10     ┆ SSH password authentication enabled  │
│ …                ┆         ┆                                      │
╰──────────────────┴─────────┴──────────────────────────────────────╯
```

Full evidence column, memory-forensics tables and suppression counts appear with `--deep`.

---

## What this is not

- Not a continuous EDR or runtime monitoring agent — this is point-in-time
- Not a replacement for Falco, Tetragon or other eBPF-based tooling
- No active blocking or prevention — detection and reporting only
- `--deep` memory forensics requires root
- The macOS binary is an orchestrator only; it cannot scan the local machine
- No Windows support
- Not a full CIS benchmark runner — findings are mapped to CIS rules where applicable, not every control is implemented
- A clean result is not proof of absence. No scanner can give you that.

---

## Install

### Linux

**Direct download** — verify by hand, see [Verifying releases](#verifying-releases):

```bash
curl -L https://github.com/OWLZOPS/owlzops-mapper/releases/latest/download/owlzops-mapper-linux-x86_64.tar.gz | tar xz
sudo ./owlzops-mapper audit
```

**Install script** — resolves the latest release, verifies SHA256, and verifies the GPG signature when `gpg` is available:

```bash
curl -sSL https://raw.githubusercontent.com/OWLZOPS/owlzops-mapper/main/install.sh | sh
sudo ./owlzops-mapper audit
```

Either way the binary lands in the current directory and nothing is added to your `PATH`. To make the examples below work verbatim:

```bash
sudo install -m 755 owlzops-mapper /usr/local/bin/
```

If piping a script into a shell isn't something you do — reasonable, given what this tool is for — use the direct download and verify manually. [SECURITY.md](SECURITY.md) lists every command the script runs that matters, plus the signing key fingerprint.

### macOS orchestrator (remote Linux hosts only)

```bash
# 1. Install the macOS orchestrator
curl -sSL https://raw.githubusercontent.com/OWLZOPS/owlzops-mapper/main/install.sh | sh

# 2. Extract the Linux agent under a different name — a plain `tar xz` here
#    would overwrite the orchestrator you just installed
curl -L https://github.com/OWLZOPS/owlzops-mapper/releases/latest/download/owlzops-mapper-linux-x86_64.tar.gz \
  | tar xzO owlzops-mapper > owlzops-agent-linux
chmod +x owlzops-agent-linux

# 3. Scan a remote host
./owlzops-mapper audit --deep \
  --host 192.168.1.10 \
  --ssh-user operator \
  --ssh-key ~/.ssh/id_rsa \
  --remote-path /tmp/owlzops-mapper \
  --copy-binary \
  --local-binary ./owlzops-agent-linux \
  --ask-sudo-pass
```

> The macOS binary is an orchestrator only — it cannot scan the machine it runs on. Extracting the Linux agent with a plain `tar xz` in the same directory replaces the orchestrator with a Linux ELF, and the next command fails with `cannot execute binary file`. `tar xzO … > owlzops-agent-linux` avoids that entirely. Apple Silicon only; there is no Intel macOS build.

---

## Usage

### Local audit

```bash
sudo owlzops-mapper audit                                    # fast path
sudo owlzops-mapper audit --deep                             # + memory forensics + ghost PID detection
sudo owlzops-mapper audit --deep -v                          # full per-region VMA detail
sudo owlzops-mapper audit --deep --format excel -o report.xlsx
sudo owlzops-mapper audit --format json > snapshot.json
sudo owlzops-mapper audit --offline                          # guaranteed zero outbound calls
```

### Remote / fleet scan

```bash
# Single host
owlzops-mapper audit --host 192.168.1.10 --ssh-user operator --copy-binary

# Fleet, one host per line in hosts.txt
owlzops-mapper audit \
  --hosts hosts.txt \
  --ssh-user ubuntu \
  --copy-binary \
  --ask-sudo-pass \
  --format excel \
  --output fleet-report.xlsx
```

The binary uploads itself over SSH, runs, collects JSON, removes itself from each host, and writes one multi-sheet Excel report. No agent install, no open ports beyond SSH.

`--ask-sudo-pass` forwards the sudo password securely over the SSH channel — no `NOPASSWD` sudoers rule required.

### Snapshot & drift

```bash
sudo owlzops-mapper snapshot
owlzops-mapper dir-compare ~/.owlzops/snapshots/hostname
owlzops-mapper compare before.json after.json --format excel -o drift.xlsx
```

---

## Core features

**Threat hunting & deep forensics**
- Full `/proc` sweep for reverse shells, fileless/memfd implants, library injection, bind-mount masking
- `--deep`: `process_vm_readv` memory reading, pointer resolution, Shannon entropy, binary header detection
- Ghost PID / LKM rootkit detection, ftrace syscall hook attribution
- Content-bound verdict cache — no static allowlists

**Container-aware**
- Docker + Podman (including rootless) socket detection
- Privileged containers, dangerous capabilities, sensitive host mounts
- Missing resource limits, OOM kills, restart loops, health status

**Operational**
- Agentless SSH fleet orchestration — parallel, automatic cleanup
- Snapshot + drift monitoring, terminal or colour-coded Excel
- JSONL / Excel export for SIEM ingestion
- Context-aware Risk Score — Docker/kubelet hosts are not punished for `ip_forward=1`
- Separate Security / Reliability / Hygiene sub-scores

**Trust & supply chain**
- Single static musl binary, zero runtime dependencies
- Read-only, zero permanent footprint, no telemetry
- GPG-signed releases + SHA256 checksums + SBOM
- CI pins every GitHub Action by commit SHA, runs `cargo audit` and `cargo deny`
- Source-available under Apache 2.0 with Commons Clause

The design commitments above are stated as testable properties in [SECURITY.md](SECURITY.md). A violation of any of them is treated as a vulnerability, not a bug.

---

## Command-line options (summary)

| Flag | Description |
|------|-------------|
| `--deep` | Memory forensics + ghost PID detection (root only) |
| `-f, --format` | `text` (default), `json`, `excel` / `xlsx` |
| `-o, --output` | Output file for Excel reports |
| `--offline` | Disable all network calls, overrides other flags |
| `--host` / `--hosts` | Remote target(s): comma-separated list or file |
| `--ssh-user` / `--ssh-key` | SSH credentials for remote scanning |
| `--copy-binary` | Upload the static binary automatically |
| `--local-binary` | Path to the static binary to upload instead of the running one |
| `--ask-sudo-pass` | Prompt for sudo password, forwarded over SSH |
| `--keep-binary` | Skip cleanup, leave the binary on the remote host |
| `--external-ip` | Opt-in public IP lookup |
| `-v, --verbose` | Full per-region memory detail |

Subcommands: `audit`, `snapshot`, `compare <before> <after>`, `dir-compare <dir>`.
Full list: `owlzops-mapper --help`.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean |
| 1 | Critical findings present |
| 2 | Not running as root / scan warnings / fleet produced zero reports |
| 3 | **Active compromise detected** (IoC / ghost PID / critical memory findings) |

```bash
sudo owlzops-mapper audit || echo "Security scan failed — check the report"
```

---

## Risk Score

0–100, lower is better, split into three capped sub-scores:

| Category | Cap | Examples |
|----------|-----|----------|
| Security | 60 | Firewall, SSH, updates, Docker risks, malware/IoC |
| Reliability | 30 | Failed services, missing backups, OOM, container health |
| Hygiene | 10 | NTP |

Colour legend: green < 40 · yellow 40–69 · red ≥ 70.

Active-compromise indicators escalate to exit code 3 regardless of score. When comparing snapshots taken with different scoring engine versions, score changes are reported as `~ Changed` rather than improved or degraded.

<details>
<summary><b>Full penalty table</b> — every finding and what it costs you</summary>

<br>

Weights are published so you can argue with them. If a penalty looks wrong for your environment, that's a legitimate issue to open.

**Baseline configuration**

| Finding | Penalty |
| --- | --- |
| Firewall inactive | +30 |
| SSH root login allowed | +25 (`prohibit-password` reduces weight) |
| Pending security updates | +20 (stepped: 10/15/20 by count) |
| No backup tools detected | +20 |
| SSL certificate expires within 7 days | +15 (max) |
| Sudo NOPASSWD entries found | +5 (restricted commands) / +15 (ALL) |
| SSH password authentication enabled | +10 |
| Failed systemd services | +10 |
| OOM kills present | +10 |
| NTP not synchronized | +10 |
| Root login with password (combo) | +5 |
| Sudoers permissions not 0440 | +5 |
| Sysctl security issues | +5 per issue (context-sensitive) |

**Containers**

| Finding | Penalty |
| --- | --- |
| Container mounts runtime control socket or host root | +15 |
| Container mounts sensitive host path (writable) | +10 |
| Privileged containers | +10 |
| Dangerous capabilities | +10 |
| Containers killed by OOM | +10 |
| Unhealthy containers (failing healthcheck) | +10 |
| Containers in restart loop | +5 |
| Containers without memory limits | +5 |
| Containers without CPU limits | +3 |

**Active compromise (IoC)** — these escalate to exit code 3

| Finding                                                                    | Penalty                           |
|----------------------------------------------------------------------------|-----------------------------------|
| **SEC-015** – Privileged non-root implant on network                       | **+60**                           |
| **SEC-016** – Known malicious process (by name)                            | **+60**                           |
| **SEC-017** – Fileless malware (deleted executable / memfd)                | **+60**                           |
| **SEC-019** – Fileless malware with critical kernel caps                   | **+60**                           |
| **SEC-020** – Kernel-thread masquerading process                           | **+60**                           |
| **SEC-021** – Bind-mount / overlay masking                                 | **+60**                           |
| **SEC-022** – Reverse shell / C2 connection                                | **+60**                           |
| **SEC-023** – Userspace rootkit / library injection                        | **+60**                           |
| **SEC-024** – True Ghost PID (LKM rootkit)                                 | **+60**                           |
| **SEC-028** – Unattributed executable payload in memory (`--deep`)         | **+60**                           |
| **SEC-040** – Hidden kernel module (Diamorphine-class LKM rootkit)         | **+55**                           |
| **SEC-041** – Ftrace syscall hook by hidden module                         | **+55** (via SEC-040)             |
| **SEC-018** – Suspicious cron job (persistence)                            | **+20**                           |
| **SEC-025** – Downgraded PID visibility mismatch                           | **+20** (no exit-code escalation) |
| **SEC‑042** - System‑wide LD_PRELOAD injected (volatile or corroborated)   | **+55 or +60**                    |
| **SEC‑049** - System‑wide LD_PRELOAD present (ownership unverifiable)      | **+20**                           |
| **SEC‑050** - System‑wide LD_PRELOAD injected (unpackaged, not yet mapped) | **+30**                           |
**Kernel & confinement**

| Finding | Penalty |
| --- | --- |
| **SEC-041** – Unexplained ftrace syscall hook (visible module) | +30 (verify EDR?) |
| **SEC-039** – SELinux running permissive | +15 |
| **SEC-038** – Kernel tainted by unsigned / force-loaded module | 0 informational (e.g. NVIDIA driver) / 10 forced load-unload / 25 correlated with SEC-040 |
| **SEC-041** – Unattributed ftrace hook under `kptr_restrict` | 0 (informational, drift still detected) |
| **SEC-039** – AppArmor profiles in complain mode | 0 (enforce→complain reported as Degraded by `compare`) |

**Capabilities**

| Finding | Penalty |
| --- | --- |
| **CAP-001** – Non-root process with critical capabilities | +8 (loopback) / +20 (wildcard exposure) |
| **CAP-002** – Ambient capabilities with NoNewPrivs disabled | 0 benign (`IPC_LOCK`, `SYS_TIME`) / 5 (`NET_RAW`) / 12 escalation-capable (`SYS_ADMIN`, `SYS_PTRACE`) |

**Visible but unpenalised** — surfaced for the operator, weight 0 by design

| Finding | Penalty |
| --- | --- |
| **SEC-029** – Provisional trust (binary attributed, memory unverified) | 0 (auditable) |

</details>

---

## What it scans

| Category | Details |
|----------|---------|
| Malware & Intrusion | `/proc` sweep, memfd, deleted executables, reverse shells, library injection, hidden PIDs, bind-mount masking |
| Security | SSH config, root login, password auth, sudo/NOPASSWD, sudoers permissions, sysctl, fail2ban/auditd |
| Network | Listening ports + bind address, firewall state, DNS, TLS certificate expiry |
| Docker / Podman | Privileged flag, capabilities, sensitive mounts, resource limits, OOM, health, socket exposure |
| Kernel | Taint flags, hidden modules, ftrace syscall hooks, LSM confinement downgrade |
| Memory (`--deep`) | `process_vm_readv`, entropy, binary headers, origin attribution, verdict cache |
| Packages | Security updates (apt/dnf/yum/pacman/zypper) |
| Databases | PostgreSQL, MySQL/MariaDB, Redis, MongoDB |
| Internals | Cron (severity-classified), systemd timers, `/etc/hosts` overrides, failed units |
| System | OS, kernel, uptime, CPU/RAM, LSM, disk/inode usage |
| Backups | restic, borg, duplicati, rsync patterns |

Full field reference: [docs/FIELDS.md](docs/FIELDS.md)

---

## Security

Read-only. No telemetry. Nothing stays resident. Scan output goes where you tell it and nowhere else.

To report a vulnerability in the tool itself, email **security@owlzops.com** — please don't open a public issue. Scope, response times, safe harbour and design commitments are in [SECURITY.md](SECURITY.md).

**False positives are not security issues** — open a normal issue for those. They matter and they get fixed, and a good false-positive report is one of the more useful things you can send.

---

## Verifying releases

Every release ships, per target (`linux-x86_64`, `linux-arm64`, `macos-arm64`): the tarball, its SHA256 checksum, a GPG signature over each, and an SBOM.

```bash
gpg --import gpg-public-key.asc
gpg --fingerprint 63C349F81ACBB9929EF8E73EB47BCE304E7C265E

gpg --verify owlzops-mapper-linux-x86_64.tar.gz.sha256.asc \
             owlzops-mapper-linux-x86_64.tar.gz.sha256
sha256sum -c owlzops-mapper-linux-x86_64.tar.gz.sha256
gpg --verify owlzops-mapper-linux-x86_64.tar.gz.asc \
             owlzops-mapper-linux-x86_64.tar.gz
```

Signing key fingerprint: `63C3 49F8 1ACB B992 9EF8  E73E B47B CE30 4E7C 265E`. Check it — a key fetched from the same repo as the binary proves nothing on its own. Full detail in [SECURITY.md](SECURITY.md).

---

## Building from source

```bash
git clone https://github.com/OWLZOPS/owlzops-mapper
cd owlzops-mapper
cargo build --release
sudo ./target/release/owlzops-mapper audit
```

Static musl build, recommended for remote use:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Requires Rust 1.85+, Linux target.

---

## If the scan came back bad

The scanner tells you something is wrong. [Owlzops](https://owlzops.com) tells you how wrong — then closes it. Fixed price, defined scope, and the engineer who scopes the work is the one who does it.

| What the mapper found | What it means | What we do |
|---|---|---|
| Exit code 3 — SEC‑015…024, SEC‑028, SEC‑040, DOCK‑010 | Evidence of a rootkit, backdoor or fileless implant. Something is likely already inside. | [**Infrastructure Security Audit**](https://owlzops.com/#assessment?utm_source=github&utm_medium=readme&utm_campaign=mapper_ioc) — read-only, point-in-time, IoC review and attack-surface map, ranked by what an attacker reaches first |
| Risk Score ≥ 70, firewall off, `docker.sock` mounted, privileged containers | Systemic architectural exposure. Automated scanners will find this before a human does. | [**Infrastructure Hardening**](https://owlzops.com/#hardening?utm_source=github&utm_medium=readme&utm_campaign=mapper_risk) — staged, reversible remediation with a before/after diff, without breaking production |
| Pending security updates, CIS gaps, drift since last snapshot | Accumulating debt, and the thing a SOC 2 / ISO 27001 auditor will ask you about | Covered inside the audit — the risk matrix ships with CIS references as engineering evidence. We are not an accredited auditor and don't sign anything off. |

**Run the scanner first.** If it comes back clean, we'll tell you so — and we won't sell you the audit. We'd rather lose the sale than charge for confirming what a free tool already told you.

If it didn't come back clean, send the JSON report. You get a **free 30-minute review call**: we read the report before we talk, and you leave with the remediation order and what we'd do first — whether or not you hire us.

→ [Send your report](https://owlzops.com/contact?service=mapper_consultation&utm_source=github&utm_medium=readme&utm_campaign=mapper_cta) · no pitch, just engineering facts

---

## License

**Apache 2.0 with Commons Clause** — free to use, not to resell.

You may use `owlzops-mapper` for commercial purposes, internal audits and security checks without restriction, forever. The Commons Clause only prevents third parties from taking the codebase and selling it as their own product or SaaS.

This is source-available, not open source in the strict sense — the Commons Clause fails the Open Source Definition, and we're not going to pretend otherwise. The full scanning engine is readable: you can review every line that will run as root on your servers before you run it. That's the point.

See [LICENSE](LICENSE) for the full text.

---

If the tool found something real on your box — star the repo. It's the only distribution this project has.
Issues and false-positive reports are equally welcome.