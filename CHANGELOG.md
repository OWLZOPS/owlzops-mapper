
## Bug Fixes

- SEC-058 config slot test – change parent mode after file creation
- SEC-058 config slot test – change parent mode after file creation
- **cli:** Move default remote_path out of /tmp (R24-41)
- **deps:** Use russh with ring backend for glibc 2.35 compat
- **deps:** Use russh with ring backend for glibc 2.35 compat
- **remote:** Harden --remote-path handling (R24-41/R24-96)
- **output:** Handle empty report list in output_multi
- **deps:** Enable rsa feature for russh ring backend
- **ssh:** Restore rsa auth and clean up sudo error output
- **utils:** Harden sanitize_for_log against ANSI and control chars
- **ssh:** Bound probes, classify sudo failures, keep staging path across timeout
- **ssh:** Harden remote probes and sudo error handling (R25 batch 1)
- **remote:** Complete R25 batch — staging ownership, sudo classification, coverage propagation
- **ssh:** Bound sudo NOPASSWD probe and handle wedged PAM
- **ssh:** Surface remote upload stderr instead of hanging on permission errors
- **ssh:** Fail fast on non-writable upload target
- **cli:** Refuse --keep-binary without explicit --remote-path
- **remote:** Use real write probe and keep static tmp blocklist
- **security:** Treat host key algorithm change as a key change, not TOFU
- **ftrace:** Classify hooks by callback symbol, not substring match
- **reverse-shell:** Require stdio fd before raising SEC-022
- **scoring:** Ignore findings from failed scanners
- **provenance:** Treat rpm exit code 1 as not-owned, not a failure
- **ssh_engine:** Harden upload teardown and write-probe validation
- **ssh_engine:** Use unique upload part and noclobber to avoid symlink race
- **scoring:** Failed scanners produce incomplete verdict
- **ssh_engine:** Generate unique upload part for owned staging dir
- **ftrace:** Module-tagged callbacks are never kernel builtin sources
- **provenance:** Rpm errors are not negative ownership answers
- **cli:** Usage errors exit 64 outside verdict band
- **cli:** Exit 4 when scanner failed and verdict incomplete
- **reverse_shell:** Deterministic candidate selection
- **remote:** Persist remote_privileged into reports and drift
- **ssh_engine:** Bound sudo preflight by SUDO_PROBE_BUDGET
- **ssh:** Pin host key algorithms to known_hosts
- **scoring:** Replace manual scanner ID maps with Finding source
- **ssh_engine:** Remove write probe to avoid FIM noise
- **utils:** Strip unicode bidi and format controls from logs
- **ui:** Avoid EPIPE panic when stderr is closed early
- **ssh_engine:** Harden upload loop and sudo auth
- **scoring:** Let incomplete outrank critical and close scanner mapping seam
- **cli:** Restore degraded exit for scan warnings
- **ci:** Address R25-53 cleanup items
- **known_hosts:** Fail-closed trust store and per-host filtering
- **main:** Aggregate fleet exit by verdict rank, not numeric max
- **main:** Allow dead_code for compute_exit_code without local-scan
- **main:** Return EX_SOFTWARE on panic, not interrupt code
- **known_hosts:** Normalize RSA key type before comparison
- **ssh_engine:** Bound upload tail after EOF
- **scoring:** Move scanner-name warning out of evaluate
- **runner:** Persist remote privilege fact in snapshots
- **compare:** Remove unreachable panics from diff paths
- **ui:** Strip Unicode TAG block in terminal sanitizer
- **main:** Suspend progress bars before warning from scan tasks
- Correct fleet exit-code polarity and reject truncated trust store (R25-62, R25-63)
- Log channel message shape instead of remote payload (R25-68)
- Classify remote privilege coverage loss as degraded (R25-69)
- Make remediation ref check PR-aware and deletion-friendly (R25-70)
- Make all structured logs progress-bar aware (R25-71)
- Fleet aggregation prefers Critical over Incomplete (R25-72)
- Strict UTF-8 and line numbers for known_hosts trust store (R25-72)
- **main:** Restore is_running_as_root and honour --fail-on-incomplete on output errors
- **known_hosts:** Fail closed on unsupported trust markers; ignore revoked keys
- **main:** Remove duplicate host-failure output
- **compare:** Derive privileged fact from remote_privileged and is_root_execution
- **safe_io:** Report trust-store truncation before UTF-8 error
- Close remaining R25-81 cleanup items
- **exit-codes:** Output failure must not erase the security verdict
- **main:** Allow dead code for local helpers on non-local-scan targets
- **models:** Host getuid() outranks orchestrator sudo intent
- **exit-codes:** Align docs, tests and drift fields after two-axis model
- **main:** Log fleet coverage facts before returning exit code
- **main:** Separate verdict and coverage explanations
- **utils:** Kill child group before reaping to avoid PID recycling race
- **known_hosts:** Support wildcard host patterns and defer marker check
- **scoring:** Extract evaluate side effects, call once per report
- **scoring:** Allow warn_evaluate_side_effects on non-local-scan targets
- **main:** Report missing fleet hosts by input address
- **models:** Detect privilege claim disagreement in both directions
- **main:** Never let SIGINT hide a recorded compromise
- **main:** Aggregate fleet outcome outside writer task
- **ghost-pid:** Record sync fallback coverage once per invocation
- Close R25-100 and R25-73
- Close R25-101
- **utils:** Close PGID reuse race in run_with_timeout_inner via wait_group_safe (R26-01)
- **compare:** Refuse multi-host diff when JSONL lines are unreadable (R26-05)
- **fleet:** Count lost channel sends in records_lost (R26-09
- Fix(scanners): use read_file_capped_regular for host-controlled paths (R26-02)
- Prevent FIFO/device hangs on /etc/passwd, /etc/ssh/sshd_config, /etc/sudoers and /var/run/reboot-required.pkgs. Non-regular files are now recorded as tampering instead of blocking open(2)
- **deep:** Replace chunks_exact(8) with as_chunks::<8>() for clippy
- **host:** Detect backup posture from local evidence, drop which/restic/borg probes (R26-03/R26-04)
- **xlsx:** Neutralize bidi/zero-width in document sanitizer (R26-07)
- **sudoers:** Resolve Cmnd_Alias indirection in NOPASSWD: ALL detection (R26-06)
- **models:** Add container-level serde(default) to SecurityInfo/PortInfo/NetworkInfo (R26-11)
- **sudoers:** Avoid double space when joining continuations (R26-08)

## Build System

- **deps:** Bump rust_xlsxwriter from 0.97.0 to 0.97.1 (#190)
- **deps:** Bump taiki-e/install-action from 2.85.5 to 2.85.10 (#194)
- **deps:** Bump clap from 4.6.5 to 4.6.6 (#192)
- **deps:** Bump data-encoding from 2.11.0 to 2.11.1 (#191)
- **deps:** Bump dtolnay/rust-toolchain
- **deps:** Bump Swatinem/rust-cache from 2.9.1 to 2.9.2 (#189)
- **deps:** Bump thiserror from 2.0.19 to 2.0.20 (#198)
- **deps:** Bump russh from 0.62.5 to 0.62.6 (#199)

## CI/CD

- Fail when commit message references a remediation ID not in diff
- Check remediation refs against diff, not full file
- Check each commit against its own diff
- Check only latest commit for remediation IDs
- **commit-refs:** Restore per-commit PR validation

## Documentation

- Update CHANGELOG for v0.5.33
- Update exit codes and remote flags after R25 remediation
- Add remote_privileged, failed_scanners and self_integrity to FIELDS
- Document fleet verdict ordering (R25-72)
- **known_hosts:** Document canonical_key_type scope
- Document two-axis exit-code model and --fail-on-incomplete
- **models:** Add R26-11 reference for CI

## Features

- SEC-058 detect writable PAM config slots (IoC)
- **ssh:** Include sudo stderr in error message for incorrect password
- **remote:** Use mktemp staging, add sudo NOPASSWD probe and requiretty detection
- **remote:** Show kept binary path when --keep-binary is used
- **ssh:** Pre-validate sudo password and show kept-binary path
- **ssh:** Validate sudo password before binary upload
- Honor @revoked and @cert-authority known_hosts markers (R25-66)

## Miscellaneous

- Address R25-61 minor review items
- Apply R25-72 minor cleanups
- Bump version to 0.5.34

## Performance Improvements

- **utils:** Exponential backoff for run_child_with_timeout

## Refactoring

- Unify terminal-unsafe codepoint classification (R25-65)
- Single exit-code mapping for local and fleet paths (R25-67)
- Centralize remote coverage application (R25-72)
- **exit-codes:** Two-axis security verdict and coverage
- **safe_io:** Strict capped read returns String, not impossible bool

## Testing

- Make canonical_key_type regression test actually fail without fix (R25-64)
- **utils:** Gate wait_group_safe test to Linux

## style

- Fix formatting

