# Security Policy

`owlzops-mapper` is a security tool that runs as root on production systems. That
places a higher-than-usual obligation on us, and this document states what we
commit to, what we ask of you, and how to report a problem.

---

## Reporting a vulnerability

**Email: security@owlzops.com**

Please do **not** open a public issue for a security problem. Send it by email and
give us a chance to fix it before it's public.

Useful things to include, as far as you have them:

- The version (`owlzops-mapper --version`) and the host OS/kernel
- What you observed, and what you expected
- Steps to reproduce, or a proof of concept
- The impact as you see it

**What we commit to:**

| | |
|---|---|
| Acknowledgement | within **3 business days** |
| Initial assessment | within **10 business days** |
| Fix or mitigation plan | communicated with the assessment |
| Credit | your name/handle in the release notes, if you want it |


We don't run a paid bug bounty. We will credit you, we will fix the issue, and we
will tell you when it's out.

---

## Scope

### In scope

Things that would make this tool a liability on a host it's meant to protect:

- **Any write to the target system.** The tool is read-only by design. A code path
  that creates, modifies, or deletes anything on a scanned host is a vulnerability,
  regardless of impact.
- **Any outbound network traffic** during a scan, other than what a documented
  flag explicitly requests (e.g. `--external-ip`). Unrequested egress is a
  vulnerability.
- **Privilege escalation** — a local user leveraging the binary, or a scanned
  host's contents, to gain privileges they didn't have.
- **Command injection** via hostnames, process names, container labels, file
  paths, or any other attacker-controllable data the scanner reads. Assume a
  compromised host is trying to attack the scanner.
- **Memory-safety issues** in `unsafe` blocks, particularly around
  `process_vm_readv` and `/proc` parsing.
- **Report content leaks** — anything that writes credentials, key material, or
  secret values into report output where the field was meant to be redacted.
- **Supply-chain issues**: release-artifact tampering, signature or checksum
  verification that can be bypassed, malicious or compromised dependencies.
- **Detection bypass that is systematic** — a technique that reliably defeats a
  documented detection, not a one-off false negative.

### Out of scope

- **False positives.** Please report them as normal issues — they matter, and we
  fix them, but they aren't security vulnerabilities.
- **False negatives from an evasive attacker.** No scanner detects everything. A
  specific, reproducible bypass of a documented check is in scope; "it didn't
  catch my custom rootkit" is a feature request.
- **Findings on hosts you don't own.** See below.
- **Results from modified builds.** Report against official releases.
- Missing hardening in the tool that has no exploitable consequence, absent a
  described attack path.

---

## Safe harbour

If you're researching `owlzops-mapper` itself and you act in good faith, we will
not pursue legal action against you. Good faith means:

- You test against **your own systems**, or systems you have written permission to
  test — not ours, and not someone else's
- You don't access, modify, or exfiltrate data that isn't yours
- You don't degrade anyone's service
- You give us a reasonable window to fix before publishing

**This safe harbour covers the tool. It does not authorise you to scan
infrastructure you don't control.** Running a root-level scanner against someone
else's host without their permission is a criminal matter in most jurisdictions,
and nothing here changes that.

---

## Supported versions

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Previous minor | ✅ security fixes only |
| Anything older | ❌ |

We ship fixes forward. If you're behind, upgrading is the fix.

---

## Verifying what you run

Every release is published with:

- A **SHA256 checksum**, listed on the release page
- A **GPG signature** over the artifact
- An **SBOM** (software bill of materials) describing what went into the build

Verify manually:

```bash
# checksum
sha256sum -c owlzops-mapper-<version>-<target>.sha256

# signature
gpg --verify owlzops-mapper-<version>-<target>.asc owlzops-mapper-<version>-<target>
```

The install script performs both checks automatically and refuses to install on
mismatch. If you'd rather not pipe a script to a shell — a reasonable position —
download the binary and the signature and verify by hand. The commands above are
all it does.

**Build pipeline:** CI pins every GitHub Action to a commit SHA rather than a
mutable tag, and runs `cargo audit` and `cargo deny` on each build.

---

## Design commitments

These are properties of the tool, not aspirations. If you find one of them
violated, that is a vulnerability under "In scope" above.

**Read-only.** A scan does not create, modify, or delete anything on the target
host. No config is written, no service installed, no agent left resident. It
runs, prints, and exits.

**No telemetry.** The binary does not phone home. There is no analytics endpoint,
no licence check, no usage reporting. Network access happens only when a flag you
passed requires it, and `--offline` disables even that.

**Your data stays yours.** Scan output is written where you tell it to be written
and nowhere else. We never receive it unless you choose to send it to us.

**Least privilege where possible.** Deep inspection uses `process_vm_readv`
rather than attaching with `ptrace`, so the tool never stops or attaches to a
running process.

**Source-available.** Published under Apache 2.0 with the Commons Clause. Not
open source in the strict sense — the Commons Clause restricts reselling the
software, which fails the Open Source Definition — but the full scanning engine
is readable, and free for your company to use forever. You can read every line of
what will run as root on your servers before you run it. That's the point.

---

## Disclosure

Once a fix is released, we publish what the issue was, which versions were
affected, and what to do. We'd rather users understand the risk than have a quiet
changelog entry. If you reported it and want credit, you'll get it.

If a report turns out to affect something outside this project, we'll tell you and
step out of the way — we won't sit on someone else's vulnerability.

---

*Owlzops, LLC · Delaware, USA · [owlzops.com](https://owlzops.com)*