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

## Sudo password handling

Prefer `--sudo-pass-fd N` for automated scans; the secret never appears in
`/proc/self/environ` or the parent shell environment. Use a pipe, not a
here-string: `<<<` is implemented with a temporary file on bash < 5.1, which
puts the fleet password on disk (R27-23).

```bash
owlzops-mapper audit --host ... --sudo-pass-fd 3 \
  3< <(printf '%s' "$pass")
```

If you cannot use a file descriptor, pipe the password to `--ask-sudo-pass`:

```bash
printf '%s' "$pass" | owlzops-mapper audit --host ... --ask-sudo-pass
```

`OWLZOPS_SUDO_PASS` remains as a **deprecated** fallback and will be removed in a
future release. It is read from the initial environment **once**, before the Tokio
runtime starts, and the bytes are zeroed in `/proc/self/environ` (R27-13). However:

- There is an unavoidable window between `execve` and the scrub in `main`.
- The variable remains in the environment of the **parent shell** if exported,
  and may be visible to other processes of the same user or in shell history.

If you must use it, do so as a one-shot prefix assignment, which does not persist
in the parent shell:

```bash
OWLZOPS_SUDO_PASS='...' owlzops-mapper audit --host ...
```

Never export `OWLZOPS_SUDO_PASS` in a profile script or CI environment where
the value might be logged or inherited by unrelated processes.

---

## Secret handling in the orchestrator

The sudo password, whatever channel supplied it, lives in a `SecretString`
(`src/secrets.rs`). These are commitments, not implementation notes.

**Never readable from `/proc/self/environ`.** `OWLZOPS_SUDO_PASS` is copied out
and its bytes are zeroed in place in the initial environment block before the
Tokio runtime is built. `unsetenv` alone does not achieve this: the kernel
serves `/proc/<pid>/environ` from `mm->env_start .. mm->env_end`, a region fixed
at `execve`, and only the pointer leaves the `environ` array.

```bash
OWLZOPS_SUDO_PASS=canary owlzops-mapper audit --host 192.0.2.1 --ask-sudo-pass &
sleep 1
# The redirection must happen *inside* sudo: PR_SET_DUMPABLE(0) reassigns
# /proc/<pid>/environ (mode 0400) to root, so a shell-level `< file` is
# refused before sudo ever runs.
sudo cat /proc/$!/environ | tr '\0' '\n' | grep '^OWLZOPS_SUDO_PASS'
# must print exactly "OWLZOPS_SUDO_PASS=" — never "=canary"
kill %1
```

**Never in swap, never in a core dump.** `prctl(PR_SET_DUMPABLE, 0)` is the
first statement of `main`; `mlock(2)` and `madvise(MADV_DONTDUMP)` cover the
backing page. Failure of any of the three is reported on stderr *and* in
`coverage_warnings` — degradation of this control is never silent. **Linux
only**: the `macos-arm64` build has no equivalent and makes no such claim.

```bash
grep VmLck /proc/<scanning-pid>/status   # non-zero while a password is held
```

**Never in a log, a report or a panic message.** `SecretString` has no
`Display`; its `Debug` renders `SecretString([REDACTED])` and withholds even
the length. Enforced in CI by `.github/scripts/check_doctrine_gates.sh`.

**Zeroized on drop, exactly one copy.** `SecretString` is not `Clone`; the fleet
shares one instance through `Arc`. Every intermediate buffer on the stdin and
`--sudo-pass-fd` paths is `Zeroizing`, and no path grows a `String` holding the
secret (a reallocation would free an un-zeroed copy).

The interactive prompt is the exception: `dialoguer` builds the entered string
in its own buffers before handing it to us, and those are outside our control.
Use `--sudo-pass-fd` when the guarantee has to be complete.

On Linux, a build in which any of the four does not hold — within the scope
stated above — is a vulnerability, not a bug.

---

## Verifying what you run

Every release publishes, for each target:

| File | What it is |
|---|---|
| `owlzops-mapper-<target>.tar.gz` | The artifact |
| `owlzops-mapper-<target>.tar.gz.sha256` | SHA256 checksum of the artifact |
| `owlzops-mapper-<target>.tar.gz.asc` | GPG signature over the artifact |
| `owlzops-mapper-<target>.tar.gz.sha256.asc` | GPG signature over the checksum file |

`<target>` is one of `linux-x86_64`, `linux-arm64`, `macos-arm64`. An SBOM
describing what went into the build is attached to the release as well.

### Signing key

```
Fingerprint: 63C3 49F8 1ACB B992 9EF8  E73E B47B CE30 4E7C 265E
```

The key is in this repository as [`gpg-public-key.asc`](gpg-public-key.asc), but a
key you fetch from the same place as the binary proves very little on its own.
**Compare the fingerprint above against the key you imported** — that comparison
is what the signature is worth.

### Verify manually

```bash
# 1. Import the key and check the fingerprint matches the one above
gpg --import gpg-public-key.asc
gpg --fingerprint 63C349F81ACBB9929EF8E73EB47BCE304E7C265E

# 2. Verify the checksum file is signed by us
gpg --verify owlzops-mapper-linux-x86_64.tar.gz.sha256.asc \
             owlzops-mapper-linux-x86_64.tar.gz.sha256

# 3. Verify the artifact against that checksum
sha256sum -c owlzops-mapper-linux-x86_64.tar.gz.sha256

# 4. And verify the artifact signature directly
gpg --verify owlzops-mapper-linux-x86_64.tar.gz.asc \
             owlzops-mapper-linux-x86_64.tar.gz
```

On macOS, substitute `shasum -a 256 -c` for `sha256sum -c`.

### What the install script does

`install.sh` detects your OS and architecture, downloads the matching artifact and
its checksum, and:

- **Always** verifies the SHA256 checksum, and **aborts** on mismatch.
- **If `gpg` is present**, imports the public key, checks the fingerprint against
  the value hardcoded in the script, verifies the artifact signature, and
  **aborts** if either check fails.
- **If `gpg` is absent**, it says so on stdout and continues with checksum
  verification only. If you want the signature checked, install `gnupg` first or
  verify by hand using the commands above.

The binary is extracted into the current directory. Nothing is written outside it,
no service is installed, and nothing is added to your `PATH` without you doing it.

If you'd rather not pipe a script to a shell — a reasonable position, especially
for this category of tool — the four commands above are everything the script does
that matters.

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

**Stable exit-code contract (from v0.6.0).** Exit codes `0`, `1`, `2`, and `3`
are part of the public interface and MUST NOT change meaning **from this release
onwards**. They are relied upon by CI pipelines, paging systems, and downstream
automation:

> v0.5.x → v0.6.0 changed one meaning, deliberately and once: code `2` now also
> covers a failed scanner, a host that produced no report, and results that did
> not reach the output. Code `4` correspondingly narrowed to "no verdict at all,
> or `--fail-on-incomplete` with incomplete coverage". Pipelines keyed on `4` for
> failed scanners must switch to `2`, add `--fail-on-incomplete`, or read
> `failed_scanners` from the JSONL.

| Code | Meaning |
|------|---------|
| 0 | Clean — full coverage, no critical or compromised findings |
| 1 | Critical findings present — full coverage |
| 2 | Degraded — incomplete coverage: not root, warnings, failed scanner(s), missing host(s), or JSONL write errors |
| 3 | Active compromise detected — regardless of coverage |

Exit code `130` is reserved for SIGINT/SIGTERM. If a confirmed compromise
was already recorded before the interrupt, the process exits `3` instead;
`130` therefore never overrides a terminal security verdict. Consumers can
treat `130` as "no confirmed compromise was recorded before interrupt".

New failure modes are assigned **new** codes (e.g. `4`, `64`, `130`); they never
reuse or override the `0–3` band. Breaking this contract is a vulnerability, not a
feature change.

---

## Disclosure

Once a fix is released, we publish what the issue was, which versions were
affected, and what to do. We'd rather users understand the risk than have a quiet
changelog entry. If you reported it and want credit, you'll get it.

If a report turns out to affect something outside this project, we'll tell you and
step out of the way — we won't sit on someone else's vulnerability.

---

*Owlzops, LLC · Delaware, USA · [owlzops.com](https://owlzops.com)*