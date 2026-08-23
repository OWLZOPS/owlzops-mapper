# Changelog

## [0.5.35] - 2026-08-23


### Bug Fixes

- **scanners:** Use capped-regular for /etc/passwd in access alignment (R26-17)
- **sudoers:** Single walk, capped passwd and scanner-resolved
- **scoring:** Key SEC-005 on scanner-resolved ALL marker (R26-19)
- **scoring:** Expose sudoers module internally for marker access
- **models:** Move sudo markers to always-compiled module
- **ghost-pid:** Gate io_uring imports to glibc Linux
- **scoring:** Bump scoring version for sudoers and backup weighting changes (R26-22)
- **sudoers:** Parse multiple Cmnd_Alias specs on one line (R26-23)
- **host:** Derive last_restic_snapshot from local cache mtime (R26-25)
- **sudoers:** Parse transitive sudo tags for NOPASSWD: ALL (R26-27)
- **compare:** Detect sudo NOPASSWD grant drift (R26-28)
- **runner:** Use capped-regular for /etc/passwd and add doctrine CI guard (R26-29)
- **compare:** Flag cross-version collection semantics change (R26-30)
- **scanners:** Use read_file_capped_regular for cron and DNS host files (R26-37)
- **provenance:** Use read_file_capped_regular for dpkg/apk databases (R26-38)
- **safe_io:** Allow dead_code for streaming opener on remote-only builds
- **main:** Import Read for streaming JSONL parser (R26-40)
- **safe-io:** Remove /dev from procfs doctrine; add literal path check (R26-43, R26-44)

### CI/CD

- Catch read_file_capped on host-controlled paths (R26-31)
- Enable raw-open guard and convert operator file readers (R26-40)
- Enable raw-open guard and annotate remaining operator/procfs exceptions

### Features

- **safe_io:** Add streaming regular-open primitive (R26-39)

### Refactoring

- **safe_io:** Rename procfs readers and make capped-I/O guard exact (R26-31/R26-33/R26-36)
- **scanners:** Fix misleading comment and dead branch (R26-45, R26-46)
- **scanners:** Fix misleading comment and dead branch

### Testing

- **sudoers:** Parameterize walk and add cross-file alias coverage (R26-24)
- **compare:** Add binary-version drift regression test

## [0.5.34] - 2026-08-20


### Bug Fixes

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

### Build System

- **deps:** Bump rust_xlsxwriter from 0.97.0 to 0.97.1 (#190)
- **deps:** Bump taiki-e/install-action from 2.85.5 to 2.85.10 (#194)
- **deps:** Bump clap from 4.6.5 to 4.6.6 (#192)
- **deps:** Bump data-encoding from 2.11.0 to 2.11.1 (#191)
- **deps:** Bump dtolnay/rust-toolchain
- **deps:** Bump Swatinem/rust-cache from 2.9.1 to 2.9.2 (#189)
- **deps:** Bump thiserror from 2.0.19 to 2.0.20 (#198)
- **deps:** Bump russh from 0.62.5 to 0.62.6 (#199)

### CI/CD

- Fail when commit message references a remediation ID not in diff
- Check remediation refs against diff, not full file
- Check each commit against its own diff
- Check only latest commit for remediation IDs
- **commit-refs:** Restore per-commit PR validation

### Documentation

- Update exit codes and remote flags after R25 remediation
- Add remote_privileged, failed_scanners and self_integrity to FIELDS
- Document fleet verdict ordering (R25-72)
- **known_hosts:** Document canonical_key_type scope
- Document two-axis exit-code model and --fail-on-incomplete
- **models:** Add R26-11 reference for CI

### Features

- SEC-058 detect writable PAM config slots (IoC)
- **ssh:** Include sudo stderr in error message for incorrect password
- **remote:** Use mktemp staging, add sudo NOPASSWD probe and requiretty detection
- **remote:** Show kept binary path when --keep-binary is used
- **ssh:** Pre-validate sudo password and show kept-binary path
- **ssh:** Validate sudo password before binary upload
- Honor @revoked and @cert-authority known_hosts markers (R25-66)

### Miscellaneous

- Address R25-61 minor review items
- Apply R25-72 minor cleanups

### Performance Improvements

- **utils:** Exponential backoff for run_child_with_timeout

### Refactoring

- Unify terminal-unsafe codepoint classification (R25-65)
- Single exit-code mapping for local and fleet paths (R25-67)
- Centralize remote coverage application (R25-72)
- **exit-codes:** Two-axis security verdict and coverage
- **safe_io:** Strict capped read returns String, not impossible bool

### Testing

- Make canonical_key_type regression test actually fail without fix (R25-64)
- **utils:** Gate wait_group_safe test to Linux

### style

- Fix formatting

## [0.5.33] - 2026-08-10


### Bug Fixes

- R24-01 correct PAM line parsing (whitespace runs, bracketed control)
- R24-01 correct PAM line parsing (whitespace runs, bracketed control), R24-02 capped safe read for authorized_keys
- R24-05 fail-closed for /proc/net/* read errors
- R24-05 fail-closed for /proc/net/* read errors in reverse_shell and proc_net
- R24-06 snapshot --hosts with unreadable/empty file fails loudly instead of falling back to local scan
- R24-07 one‑way switch vanishing between snapshots is now a Degraded drift event
- R24-04 use setsid for child processes, kill entire process group on timeout
- R24-11 capped-regular read for authorized_keys, R24-13 audit --hosts fails loud, pub(crate) CAP_AUTHORIZED_KEYS
- R24-12 InvalidInput -> InvalidData in access.rs
- R24-07 union-loop for one‑way switches, detect vanished keys as Degraded
- R24-14 replace remaining child.kill() with kill_group_and_reap in utils.rs
- R24-08 rename one‑way switch labels (no spaces), R24-09 make PAM uid/gid Option<u32>
- R24-15 restore one-way switch direction severity, add tests
- R24-16 record coverage when one-way switch contains a non-numeric value

### Documentation

- Update FIELDS.md for pam_injections uid/gid nullable (R24-09)

### Performance Improvements

- R24-03 memoize resolve_batch with negative caching

## [0.5.32] - 2026-08-10


### Bug Fixes

- PAM scanner audit fixes (R23-60, R23-61, R23-62, R23-63)
- **pam:** Resolve audit findings R23-68–R23-73
- **pam:** R23-74 parent_takeable for pam_exec, R23-75 remove root-only guard, R23-76 resolve_module mimics libpam
- **pam:** Close R23-80 (missing continue), R23-81 (.. bypass), R23-83 (test gap)
- **pam:** R23-85 detect pam_exec scripts hidden behind sh -c wrapper
- **pam:** R23-88 exclude non-executable data arguments from pam_exec targets

### Documentation

- SEC-055/056/057 weights in README, pam_injections schema in FIELDS.md, bump SCORING_VERSION to v11
- Updated README
- **README:** Fixed Security Findings table

### Features

- PAM stack injection scanner (SEC-055/056/057)

### Miscellaneous

- **pam:** R23-82 replace PamScriptInfo with target_kind, R23-86 add declared_as, R23-87 cleanup tests and dead sort

## [0.5.31] - 2026-08-07


### Bug Fixes

- Gate provenance resolution behind local-scan feature, fix fmt
- Gate generators and integrity modules behind local-scan feature
- Gate SEC-052 scoring block behind local-scan feature
- Exhaustive match in classify_generator, EACCES handling, misc R23-56
- Distinguish EACCES from Missing in assess_writability (R23-57)
- Gate BTreeMap import behind local-scan feature

### Features

- One-way kernel switches as a drift class (R23-08 ext)

### Miscellaneous

- Reference PERSISTENCE_IDS in runner comment to prevent drift

### SEC-052

- Systemd generator persistence scanner

### style

- Fix formatting

## [0.5.30] - 2026-08-04


### Build System

- **deps:** Bump russh from 0.62.4 to 0.62.5 (#165)
- **deps:** Bump clap from 4.6.4 to 4.6.5 (#166)
- **deps:** Bump taiki-e/install-action from 2.85.2 to 2.85.5 (#168)
- **deps:** Bump rust_xlsxwriter from 0.96.0 to 0.97.0 (#167)
- **deps:** Bump thiserror from 2.0.18 to 2.0.19 (#169)

### Documentation

- Updated README.md

### SEC-050

- Detect ld.so.conf.d library path injection
- Add drift detection for ld_so_conf_injections

### SEC-051

- Detect ld.so.conf.d library path injection
- Implement ld.so.conf injection scanner (R23 audit fixes)
- Address R23-40..R23-44 audit findings
- Fix volatile regression and directory include (R23-45, R23-46)
- Fix false positive on stale missing directories (R23-48)

## [0.5.29] - 2026-08-01


### Bug Fixes

- **sec-042:** Gate preload scanner behind local-scan feature
- Wire new scanners to scoring, deduplicate calls, fix package stub
- **sec-043:** Replace package-DB signal with stat-based privilege check
- **sec-043:** Distinguish vendor units from rogue via unit authorship
- **scoring:** Use vendor directory as authorship fallback for SEC-043
- **ui:** Handle broken pipe gracefully instead of panicking
- **exec_provenance:** Parse system crontab command correctly (R23-01)
- **preload:** Parse ld.so.preload with glibc semantics (R23-03)
- **scoring:** Use separate ID for unverifiable preload (R23-02)
- **preload:** Treat missing /etc/ld.so.preload as clean
- **scoring:** Require runs_as_root for SEC-046 (R23-06)
- **kernel_facts:** Make core_pattern Option, check handler basename (R23-07)
- **exec_provenance,preload:** Handle non-UTF-8 paths and count mapped PIDs
- **scanners:** Handle non-UTF-8 paths, count mapped PIDs, and protect against FIFO
- **preload:** Make count_mapped accurate and safe (R23-17)
- **scoring:** Split unpackaged preload into corroborated IoC and suspicion (R23-14)
- **exec_provenance:** Normalize whitespace around '=' in directives (R23-15)
- **exec_provenance:** Cron runs_as_root, user-manager scope, cron.d filter
- **compare,exec_provenance:** Tune drift severity and document drop-in limitation (R23-19)
- **exec_provenance:** Skip masked systemd units without noise
- Final R23 post-review fixes (R23-20..R23-24)
- Final R23 polishing (cap, preload accuracy, tier aggregation)

### Documentation

- Added false-positive.yml and updated install.sh,README, SECURITY
- Updated README

### Features

- **sec-042:** Detect system-wide LD_PRELOAD via /etc/ld.so.preload
- **kernel-facts:** Expose core_pattern, modules_disabled, and lockdown state
- **sec-043:** Provenance check for ExecStart in systemd units and cron
- **compare:** Add drift detection for exec_start_injections
- **exec_provenance:** Expand systemd coverage and fix quote bypass
- **exec_provenance:** Distinguish root- and user-executed units (R23-06)
- **compare:** Add drift for preload, core_pattern, modules_disabled, lockdown (R23-08)
- **safe_io:** Add O_NONBLOCK read for host-controlled paths (R23-10)

### Miscellaneous

- Bump scoring version, crate version, and update docs for R23

### Performance Improvements

- **audit:** Skip unnecessary rpm -qf calls for vendor units and fast mode
- **audit:** Cut rpm calls and fix under-reported duration
- **audit:** Cut rpm calls and fix under-reported duration
- **packages:** Replace `which` with internal `resolve_tool`
- **exec_provenance:** Gate target package resolution behind deep

### style

- Fix formatting

## [0.5.28] - 2026-07-30


### Bug Fixes

- Make file_capabilities module available without local-scan feature
- Gate fs_inventory import behind local-scan feature
- Universal runtime classification (R22-08,R22-09,R22-10)
- Close remaining runtime classification gaps (R22-11, R22-12)
- Recognize /nix/store as system install root (NixOS)
- NixOS support in provenance and listener classification (R22-15, R22-16)
- Structural provenance for user-space installs (R22-18)
- Home-base coverage, volatile precedence, and structural tests (R22-19, R22-20, R22-21)
- Close /run blind spot and unify volatile path definitions (R22-22)
- Exclude /run/wrappers from volatile/ephemeral classification (R22-23)

### Features

- Universal container runtime detection (Docker + Podman)
- Drift detection for setuid files and file capabilities

### Refactoring

- Unify socket existence checks via socket_reachable helper (R22-13)
- Extract classify_listeners for shadow-IT tiering

## [0.5.27] - 2026-07-28


### Bug Fixes

- Used create_dynamic_table() for Security & Health Checks table
- R22-02 SEC-040 race with dual /proc/modules snapshot
- R22-01 self-integrity now checks IPv6 transport
- R22-03 inheritable-only tagging in build_capability_names
- R22-04 sshd fallback notes Match presence in coverage

### Build System

- **deps:** Bump tokio from 1.52.3 to 1.53.1 (#127)
- **deps:** Bump taiki-e/install-action from 2.84.0 to 2.85.2 (#129)
- **deps:** Bump clap from 4.6.3 to 4.6.4 (#131)
- **deps:** Bump libc from 0.2.186 to 0.2.189 (#128)
- **deps:** Bump serde from 1.0.228 to 1.0.229 (#132)
- **deps:** Bump actions/labeler from 6.2.0 to 7.0.0

### Documentation

- Update risk score table with SEC-038/039/040 and tiered CAP-002 weights

### Features

- SEC-041 ftrace/kprobe hook-surface audit with attribution

## [0.5.26] - 2026-07-27


### Bug Fixes

- Close Raw Truth gaps in library_injection, DLP, eBPF pins, musl cfg
- Add __builtin__ftrace to pseudo-module exclusion list
- Add blank lines between kernel hardening info lines in terminal output
- Tier CAP-002 ambient caps, SEC-038/039 point-in-time vs drift weights

### Build System

- **deps:** Bump russh from 0.62.3 to 0.62.4 (#122)

### Features

- **compare:** Detect eBPF program swap by prog_tag, not count
- SEC-038/039/040 kernel hardening scanners
- Activate SEC-038/039/040 findings and UI rendering

### Miscellaneous

- Tighten dlp denied counter, fix eng comment in ebpf
- Ignore .idea directory

### Refactoring

- **fs_inventory:** Unify setuid predicate, remove double-indirection, clarify budget docs
- **ui:** Introduce tty-aware theme and unify unicode escapes

### Testing

- **library_injection:** Make lone_dropper_rwx_still_alarms independent of environment
- Add drift tests for AppArmor complain and kernel taint

## [0.5.25] - 2026-07-24


### Bug Fixes

- **ci:** Restore macOS tests, extend E2E IoC guard to all channels
- **ci:** Allowlist known injection FP on GitHub runner
- **scanners:** Report inheritable-only file caps; cover all 64 capability bits
- **sudoers:** Ignore files containing '.' or ending with '~' in sudoers.d
- **fs_inventory:** Deduplicate before budget, fix hardlink non-determinism
- Gate local-only modules behind cfg(local-scan) for macOS orchestrator
- Gate local-only symbols behind cfg(local-scan) via sed
- Isolate local-only code behind cfg(local-scan) for clean macOS build
- Isolate local-only code behind cfg(local-scan) for clean macOS build
- Gate local-only modules behind cfg(local-scan)
- **scanners:** Complete R19-05/06/14/15 — inheritable caps, shared budget, st_dev
- **scoring:** Strip (inh) suffix before matching known capability baseline
- **e2e:** Apply IoC allowlist to deep forensic result
- **e2e:** Define check_ioc in deep forensic step to fix command-not-found
- **e2e:** Deduplicate IoC check, exclude downgraded ghost_pids
- **e2e:** Sync workflow with main, use shared IoC check script
- Drop callback Result and unify setuid detection
- **rpm:** Use run_with_timeout and correct parsing (R20-01, R20-02)
- **scoring:** Exclude ambient-only entries from CAP-001 count (R20V-01)
- **scoring:** Exclude ambient-only entries from ephemeral-port correlation (R20V2-01)

### CI/CD

- Add job timeouts, harden E2E interrupt test
- Re-enable clippy for macOS orchestrator after dead-code cleanup

### Features

- **provenance:** Distinguish truncated APK database from complete
- Implement RPM package provenance backend
- Add prog_tags to eBPF inventory for stable drift detection (R19V-10)
- Feat(scoring): add CAP-002 for ambient caps without NoNewPrivs (R20-03)
chore: clarify comment on root euid skip (R20-04)

### Miscellaneous

- Start 0.5.25 development cycle

### Refactoring

- **scanners:** Unify filesystem walk for setuid and file capabilities

## [0.5.24] - 2026-07-23


### Bug Fixes

- **provenance:** Distinguish unreadable DB from missing package
- **scoring:** Align classify_* with ProvenanceSource semantics
- **sudoers:** Use capped I/O and emit coverage on unreadable files
- **fleet:** Two-phase Ctrl-C teardown preserves remote cleanup
- R19V follow-up — eBPF links, teardown grace, lost reports
- R19-V follow‑up – graceful degradation, APK, eBPF, and local Ctrl‑C
- Kill helpers on local interrupt; clarify sudoers NotFound message
- Local scan interrupt in mixed fleet + panic=unwind invariant
- **ci:** Cover --no-default-features with clippy and tests, guard panic=unwind
- **e2e:** Harden CI contract — triage IoC, add deep+interrupt checks
- Suppress clippy warnings for --no-default-features build
- **ci:** Temporarily drop clippy+tests from macOS orchestrator job
- **e2e:** Allowlist provjobd with any suffix in suspicious process check

### CI/CD

- Add custom CodeQL workflow for musl target
- Drop CodeQL due to false positives and slow execution

### Documentation

- Added Security Policy

### Features

- **ebpf:** Add link objects, prog_tag, and truncation coverage
- **compare:** Add drift detection for setuid, capabilities, and eBPF

### Performance Improvements

- **setuid:** Reuse Metadata from read_dir to avoid double stat

## [0.5.23] - 2026-07-22


### Bug Fixes

- Improve sudoers file detection and NOPASSWD matching
- Parse_vfs_cap_data - correct full 64-bit permitted/inheritable masks, add effective flag
- Parse_vfs_cap_data - correct full 64-bit permitted/inheritable masks, add effective flag
- Address R17 audit blockers for setuid & file capabilities
- Suppress clippy::unnecessary_cast in setuid tests for cross-platform compat
- Recognize setuid helpers in /usr/lib*, /usr/libexec as expected
- Always compute the score locally to avoid depending on a possibly stale `risk_score` from an older remote agent
- **provenance:** Resolve dpkg/apk ownership for SEC-036/037 suppression
- **provenance:** Strip double leading slash in usrmerge alias
- Resolve provenance serialization, scan depth, budgets, and APK parsing

### Build System

- **deps:** Bump actions/checkout from 7.0.0 to 7.0.1 (#94)
- **deps:** Bump serde_json from 1.0.150 to 1.0.151 (#96)
- **deps:** Bump uuid from 1.23.5 to 1.24.0 (#98)
- **deps:** Bump clap from 4.6.1 to 4.6.3 (#100)
- **deps:** Bump russh from 0.62.2 to 0.62.3 (#99)
- **deps:** Bump dtolnay/rust-toolchain
- **deps:** Bump taiki-e/install-action from 2.83.2 to 2.84.0

### Documentation

- Add service links to README for improved navigation

### Features

- Implement unified sudoers parser for NOPASSWD checks across scanners
- Add file capabilities inventory module (R16)
- Extend security reporting with file capabilities (SEC-034)
- Add eBPF inventory scanner (R17)
- Integrate eBPF inventory (SEC-035) into security reporting
- Enhance SEC-034 with risk-tiering and introduce SEC-036 for unexpected file capabilities
- Integrate setuid/setgid inventory (SEC-037) into security reporting
- Integrate dpkg provenance resolver for file caps & setuid tiering

### Refactoring

- Modularize file capabilities scanner for Linux compatibility
- Use location+ownership heuristic for setuid tiering instead of hardcoded name list

## [0.5.22] - 2026-07-20


### Bug Fixes

- Increase `MAX_FINDINGS` limit from 64 to 128 in library injection scanner
- R16 hardening - log sanitization, unconditional arg validation, /usr/local in PATH

### Features

- Implement Sixth Gate for ghost inode content recovery

## [0.5.21] - 2026-07-19


### Bug Fixes

- **coverage:** Consolidate drain points and enforce single attribution scope
- **ghost_pid:** Correct cfg attributes for io_uring and format inconsistencies
- **ghost_pid:** Refine cfg for io_uring to exclude musl and add explanatory comments
- **local-scan:** Resolve local host handling indentation and cfg attribute order
- **local-scan:** Resolve local host handling indentation and cfg attribute order
- **local-scan:** Add conditional handling for deep enrichment with cfg attributes
- **ci:** Add conditional build logic for macOS targets in release workflow
- Gate host-scan modules under local-scan feature (R17-01)
- Make key scanner modules available on all platforms for scoring & UI
- Restrict `security` module to `local-scan` feature and consolidate `SUDO_PRIVESC_MARKER` definition

### CI/CD

- **release:** Optimize workflow by using pre-built cargo-cyclonedx binary and standardize branch naming

### Documentation

- **readme:** Update remote audit instructions and macOS guidance
- **readme:** Clarify macOS remote audit setup and binary handling

### Features

- **local-scan:** Add conditional support for local scans and platform-specific TCP hardening
- **runtime-trust:** Add file-text anchoring and exec-heap provisional trust
- **ci+release:** Add macOS orchestrator build and packaging support
- **install:** Add macOS support and OS-specific architecture handling
- **install:** Add macOS support and OS-specific architecture handling

## [0.5.20] - 2026-07-18


### Refactoring

- **coverage:** Remove thread-local scope management and implement scoped draining for accurate attribution

## [0.5.19] - 2026-07-18


### Bug Fixes

- **ghost_pid:** Ensure safe completion drain to prevent use-after-free/errors during inflight SQE handling
- **xlsx:** Add guard for formula injection bypass via leading whitespace/control chars

### Refactoring

- **ssh:** Streamline session teardown, improve timeout handling and replace mutable flag with `AtomicBool`
- **proc_net:** Consolidate address decoding and inode helpers for reuse in reverse_shell
- **ssh:** Transition to async I/O with `tokio::fs` for file operations and handle blocking key loading safely
- **coverage:** Implement scoped coverage tracking and transition remote scans to `russh` engine

## [0.5.18] - 2026-07-17


### Features

- **scoring/runtime:** Extend trust logic to handle unverified JNI .so mappings
- **scanners/runtime:** Add inode family analysis and unlink-on-load detection
- **runtime:** Refine classification for unlink-on-load and JIT advisory sources
- **scoring:** Add unlink-on-load ghost inode classification (SEC-033)

## [0.5.17] - 2026-07-17


### Features

- **ssh:** Improve reliability with TCP hardening and deadline wrapping
- **scanners:** Add self-attribution and safety measures for scanner identity

## [0.5.16] - 2026-07-14


### Build System

- **deps:** Bump uuid from 1.23.4 to 1.23.5 (#76)

### Features

- **scanners:** Refine suspicious listener detection and add SEC-030 for developer tool monitoring
- **scanners/ui:** Add SEC-031 for provisional trust and refine loopback listener classification
- **ui:** Refine listener classification and emphasize IPC provenance
- **scanners:** Implement verdict cache for deep scan results and refine provisional trust logic
- **scanners:** Introduce multi-tier attribution funnel and enhance trust evaluation
- **scanners:** Enhance trust logic with strong signals and JIT buffer detection
- **ui:** Expand trust logic to include `ManagedJIT` and `ReservedBuffer` origins
- **scoring/utils:** Expand runtime and trust logic with additional sources and heuristics

### Miscellaneous

- **deps:** Bump softprops/action-gh-release from 3.0.1 to 3.0.2 (#72)
- **deps:** Bump EmbarkStudios/cargo-deny-action from 2.0.20 to 2.1.1 (#73)
- **deps:** Bump actions/labeler from 6.1.0 to 6.2.0 (#74)
- **deps:** Bump taiki-e/install-action from 2.82.9 to 2.83.2

### Refactoring

- **ui:** Simplify condition logic for ephemeral executable checks
- **utils/scoring/ui:** Update `exe_provenance` to include PID and refine provenance logic

## [0.5.15] - 2026-07-13


### Features

- **scanners:** Add self-integrity preflight checks for tamper detection
- **scanners:** Refine self-integrity and library injection logic
- **scanners/ui:** Enhance library injection scanner and improve memory anomaly reporting
- **scanners:** Expand allow list with additional binaries for injection scanner
- **ui:** Add verbose mode for detailed dashboard rendering
- **scanners:** Implement deep memory forensics and pointer resolution analysis
- **scanners/ui:** Introduce SEC-028 for deep memory forensics and enhance anomaly reporting
- **scanners/ui:** Add HotSpot origin classification for Java JIT detection
- **scanners/ui:** Introduce SEC-029 for trusted-path executable memory verification
- **scanners/ui:** Enhance anomaly filtering and expand runtime allowlist
- **scanners/ui:** Add PCRE2 JIT origin classification and update deep scanner logic
- **ui:** Add PCRE2 JIT to benign anomaly filter

## [0.5.14] - 2026-07-12


### Bug Fixes

- **ui:** Reuse spinner for local scan and ensure proper cleanup

### Documentation

- **README:** Document `--host` and `--deep` scan options

### Features

- **scanners:** Enforce fd limits per PID and improve logging for partial socket scans
- **scanners:** Add "reason" field for ambient capabilities and support LD_AUDIT/LD_PROFILE detection

### Miscellaneous

- **docs:** Update README for v0.5.13 release

## [0.5.13] - 2026-07-12


### Bug Fixes

- R11 audit fixes (cleanup guarantee, terminal sanitization, coverage cap)
- **utils:** Handle stdout/stderr take safety in child process
- **scanners:** Disable io_uring statx on musl to fix Alpine build
- **ui:** Ensure progress bars are always cleared and improve error logging
- **progress:** Make upload progress bar optional based on conditions
- **scanners:** Skip self-zombies in zombie detection logic and apply minor formatting adjustments
- **scanners:** Update comments in zombie detection to improve clarity and consistency
- **ssh_engine:** Make `sudo_pass` optional and adjust remote scan logic

### Features

- **scanners:** Enhance ghost PID detection with thread filtering and hidepid safeguard
- Add `--deep` flag for enhanced scan depth and ghost PID detection
- **audit:** Add spinner for progress visualization and improve shutdown handling
- **ssh_engine:** Add upload progress bar integration and improve user feedback

### Refactoring

- **utils:** Reorder `poll_wait` for better readability

## [0.5.12] - 2026-07-11


### Bug Fixes

- **russh:** Enforce binary cleanup and JSONL error handling (R10-01, R10-02, R10-03)
- **utils:** Improve poison lock handling, tool resolution, and child process safety (R10-04, R10-05)
- **utils:** Improve poison lock handling, tool resolution, and child process safety (R10-04, R10-05)
- **ui:** Sanitize bidi and zero-width characters (R10-06)
- **utils:** SIGTERM legacy SSH children on shutdown (R10-07)
- **exporters:** Add integer format for PID and EUID in XLSX reports (R10-08)
- **russh:** Optimize TCP_NODELAY settings and reduce chunk size for file streams
- **workflows:** Remove stderr redirection for audit JSON output
- **workflows:** Update exit code validation and capture stderr logs in e2e tests

### Documentation

- **exporters:** Add `euid` and `is_mimic` fields, adjust XLSX formatting (R10-08)

### Features

- **scoring, scanners:** Add DOCK-010 to detect runtime capability tampering
- **scoring:** Introduce SEC-019 to detect fileless processes with critical kernel capabilities
- **scoring, main:** Track active compromises with `compromised_host` flag, update exit codes
- **scoring:** Add SEC-020 for detection of kernel thread mimicry
- **scoring:** Add SEC-021 for detecting bind-mount and overlay masking
- **scoring, exporters, ui:** Add SEC-022 for reverse shell/C2 detection
- **scoring, exporters, ui:** Add SEC-023 for userspace rootkit/library injection detection
- **scoring, detectors, tests:** Add SEC-024 for detecting LKM rootkit-hidden "ghost" PIDs
- **exporters, ui, docs:** Add SEC-024/025 ghost PID detection

### Refactoring

- **scoring:** Streamline SEC-019 logic for fileless malware detection

## [0.5.11] - 2026-07-10


### Bug Fixes

- **compare, utils:** Prevent false escalation for wildcard binds already present with loopback

### Documentation

- **fields:** Update FIELDS.md with new properties and enhanced descriptions

### Features

- **ui, exporters, scanners:** Add elevated capabilities audit for non-root processes
- **scanners:** Enhance capability audit with NoNewPrivs and Seccomp support
- **ui, exporters:** Extend capability audit with NoNewPrivs and Seccomp details
- **scoring:** Adjust CAP-001 weighting for global exposure, bump SCORING_VERSION to 6
- **scoring:** Add SEC-015 active compromise IoC detector
- **scoring:** Add SEC-016 detector for known malware and miners by process name
- **scoring, scanners:** Full /proc malware sweep, two-tier name detection
- **scoring, scanners, ui:** Add SEC-017 detector for malicious cron jobs
- **scoring, scanners:** Enhance process classification and introduce SEC-017 fileless malware detector
- **utils, scoring:** Add /memfd: to ephemeral path predicate, bump scoring version
- **scoring:** Enhance SEC-017 to distinguish in-memory (memfd) processes

### Refactoring

- **network, utils:** Centralize bind address checks into reusable predicates
- **ui:** Improve data presentation with dynamic tables and enhanced sanitization
- **ui:** Add category-specific risk breakdown with improved headers and icons
- **ui:** Simplify category formatting with conditional icon support for TTY

### classify

- **scanners:** Extend fileless detection to include /memfd: base paths

## [0.5.10] - 2026-07-09


### Bug Fixes

- **storage:** Use MiB for DiskInfo, add exact usage_pct (R10-01, R10-02)

### CI/CD

- **workflows:** Set `CC` environment variable to clang for test jobs (to fix undefined symbol __isoc23_sscanf )
- **workflows:** Switch to GCC, update matrix cache prefix key for consistency
- **workflows:** Force GCC over Clang for aws-lc-sys on Ubuntu 22.04, adjust child process handling
- **workflows:** Enhance caching logic, refine GCC enforcement and organize steps for clarity

### Features

- **compare:** Detect port exposure escalation from local to wildcard (R10-03)
- **network:** Detect and display DNS upstreams in UI and XLSX output
- **ui, exporters, host:** Display reboot-required package details in UI and XLSX output
- **ui, scoring:** Enhance cron job analysis and risk scoring output
- **ui, exporters, host:** Improve zombie process reporting with parent details
- **ui, scanners:** Add container RW size, aggregated process counts and reclaimable disk space
- **ui, exporters, scanners:** Improve image size reporting and calculation logic
- **scanners:** Add support for identifying container runtimes and orchestrators

## [0.5.9] - 2026-07-08


### Bug Fixes

- **main:** Replace `notify_waiters` with `notify_one` for proper signal handling during shutdown (R9-04-a)
- **scanners:** Improve error handling for `/proc/<pid>/fd` access, add coverage for incomplete port attribution (R9-08)
- **main:** Avoid panic on non-UTF-8 output paths (R9-09)
- **ssh_engine, utils:** Centralize timeout calculation with `host_budget_secs`, cleanup debug config (R9-10, R9-11)

### Features

- Render coverage_warnings in terminal and xlsx output
- **models:** Add forward-compatible deserialization for `PackageManager` enum (R9-12)

## [0.5.8] - 2026-07-08


### Bug Fixes

- V0.5.8 - coverage in reports, russh upload exit-status (R9-01, R9-02)
- **ssh_engine:** Improve known_hosts handling, add error reporting, and extend tests (R9-07)
- **main:** Add clarification on writer.await to indicate guaranteed completion when channel is closed R9-03

### Refactoring

- **scanners:** Optimize path handling and error reporting, improve shutdown logic(R9-04, R9-05)
- **runner, ssh_engine:** Reuse `split_host_port`, improve SSH/SCP argument handling (R9-06)

## [0.5.7] - 2026-07-08


### Bug Fixes

- **main, runner:** Support IPv6 in SSH args, improve shutdown handling scenarios
- **ssh_engine:** Replace SCP with russh-based binary upload, add tests for capped reading

## [0.5.6] - 2026-07-07


### Bug Fixes

- **russh:** Cap stdout/stderr buffers to prevent OOM (R8-01)
- **known_hosts:** Avoid false HostKeyChanged for multi-key hosts (R8-02)
- **utils:** Cap stderr of child processes at 1 MiB (R8-03)
- **ssh_engine:** Improve host key error messages and IPv6 handling (R8-04, R8-05)
- **utils:** Nullify stdin for child processes to enhance security (R8-07)
- **safe_io:** Handle invalid UTF-8 conversion gracefully, remove unused variable in main.rs (N8-1, N8-4)
- **ssh_engine:** Add detailed russh error context and robust error handling N8-5
- **dlp:** Prevent OOM by capping comm file reads and log truncation events (N8-6)
- **models:** Add #[serde(default)] for backward compatibility with older snapshots (R8-06)
- **proc_net:** Improve parsing robustness, handle edge cases, and clean up logic (N8-2)
- **network:** Deduplicate listening ports with HashSet (N8-3)
- **ssh_engine:** Switch progress bar to spinner for uploads, simplify key handling (N8-7)
- **main:** Add graceful shutdown handling with signal support (N8-8)

## [0.5.5] - 2026-07-07


### Bug Fixes

- **ssh:** Log errors when writing to known_hosts instead of silently ignoring
- **ssh:** Add keepalive support with configurable interval and max attempts

### Build System

- **deps:** Bump dialoguer from 0.11.0 to 0.12.0 (#43)
- **deps:** Bump russh from 0.62.1 to 0.62.2 (#45)
- **deps:** Bump rust_xlsxwriter from 0.77.0 to 0.96.0 (#47)
- **deps:** Bump thiserror from 1.0.69 to 2.0.18

### CI/CD

- Update CLA workflow to use 'cla-signatures' branch for signatures
- Expand CLA workflow allowlist to include additional bot patterns
- Update CLA workflow allowlist to include `web-flow` bot

### Features

- **scanners:** Add capped I/O for safer /proc parsing; introduce truncation tracking and coverage logging
- **scanners:** Integrate capped I/O across DLP and security scanners; enhance truncation tracking and coverage logging
- **exporters/ui:** Add sanitization for XLSX and terminal outputs to mitigate injection risks
- **utils:** Add hardened tool resolution and environment sanitization

### Miscellaneous

- Update `crossbeam-epoch` to v0.9.20 in Cargo.lock to avoid RUSTSEC-2026-0204
- Add `Zlib` to deny.toml license exceptions
- **deps:** Bump taiki-e/install-action from 2.82.6 to 2.82.9
- **deps:** Bump dtolnay/rust-toolchain

### Refactoring

- **ssh:** Introduce `KnownHostsChecker` for streamlined host key verification and TOFU handling

## [0.5.4] - 2026-07-06


### CI/CD

- Remove unused CLA workflow configuration options

### Refactoring

- Replace icons with Unicode code points for improved consistency
- Optimize timeout handling and enhance JSON parsing fallback in scanners
- Remove redundant JSONL parsing comment in agent report handling
- Improve output file handling and fail-fast mechanism for report generation
- Enhance DLP scanning logic, optimize process attribution and improve input validation in runner
- Simplify remote binary upload by removing temporary file usage and streamline error handling in report dispatch
- Improve code readability with formatting fixes
- Fix inconsistent formatting and improve code readability in async block and error handler

## [0.5.3] - 2026-07-06


### CI/CD

- Update CLA Assistant action to v2.4.0
- Update CLA workflow to use contributor-assistant action
- Update CLA Assistant action to v2.6.1
- Update CLA Assistant action to v2.6.1
- Add tar and gzip to apk installation in CI workflow

### Features

- Add IAM & access alignment checks for SSH key policy and sudoers
- Improve network scanning and add shadow IT detection
- Add DLP scanner for secrets in process memory
- Add streaming JSONL support for audit output

### Refactoring

- Streamline host scanning logic and improve concurrency handling

## [0.5.2] - 2026-07-06


### CI/CD

- Add Rust dependencies caching in CI workflow for build optimization

### Features

- Add detection of sensitive Docker mounts and update scoring version to 3
- Add Docker reliability checks and bump SCORING_VERSION to 4
- Add interactive sudo support and SSH concurrency configuration
- Add progress bar for SCP uploads using `indicatif`
- Add progress bar and optional binary cleanup flag
- Enhance terminal output with TTY detection and risk score colorization

### Miscellaneous

- Allow RUSTSEC-2023-0071 advisory in deny.toml
- Fix inconsistent icon spacing in TTY output

### Refactoring

- Implement atomic binary deployment and cleanup CLA integration

## [0.5.1] - 2026-07-05


### Bug Fixes

- Handle mapper exit codes in E2E workflow

### Features

- Integrate scoring version into reports and comparison logic
- Improve multi-host comparison and reporting logic
- Display hostname in terminal diff metadata header

### Miscellaneous

- Add E2E workflow for local audit smoke testing on PRs

### Refactoring

- Remove redundant comments and improve width handling in XLSX exports

## [0.5.0] - 2026-07-05


### Features

- Introduce new scoring model and structured findings evaluation system
- Filter suppressed sysctl issues in UI
- Enhance security scoring with detailed conditions and Docker checks
- Add CIS references to findings and enhance UI

### Miscellaneous

- Optimize build settings, streamline CI workflows and improve SBOM generation

### Refactoring

- Replace legacy risk scoring logic with new evaluation model

## [0.4.11] - 2026-07-04


### Bug Fixes

- Improve async handling and error reporting for remote scans, refactor `gather_host_info` interface
- Refactor sudo self-exclusion logic, simplify path checks and improve related tests
- Update timeout values and adjust README for clarity in options
- Suppress sysctl false positives for Docker/kubelet hosts

### Documentation

- Update README for v0.4.10
- Clarify License section in README, expand on Commons Clause usage
- Remove trailing space from CONTRIBUTING.md filename

### Features

- Resolve home directory for snapshots under sudo, update README with core features and examples

### style

- Apply cargo fmt to runner.rs

## [0.4.10] - 2026-07-04


### Bug Fixes

- Prevent deadlocks in `run_child_with_timeout` by managing stdout/stderr handling in separate threads and add related tests
- Enhance `run_child_with_timeout` tests to prevent deadlocks and improve process cleanup
- Simplify `installed_count` function by removing unnecessary `bin` parameter
- Handle empty fleet scan reports with specific exit code and warning logging
- Add error handling for report output functions and support `Path` for output files
- Increase du timeout to 60s, add -x to avoid crossing filesystem boundaries
- Increase du timeout to 60s and add -x to avoid crossing filesystem boundaries
- Wrap `run_local_scan_async` in a span for better tracing and simplify async handling
- Add timeout for dangling volumes check and improve SSH config fallback parsing
- Simplify authorized keys path resolution by using user home directories
- Restrict self-exclusion in sudo audit to known canonical paths
- Improve NTP offset parsing by adding unit support and handling edge cases
- Enhance scoring and scanning logic with safer calculations and stricter validations

## [0.4.9] - 2026-07-03


### Bug Fixes

- Handle incomplete scanner runs and update reporting/logging to warn on scan failures
- Enhance installation security with GPG key fingerprint verification
- Validate and refactor output format handling with `OutputFormat` enum

### Miscellaneous

- Update README with highlights for v0.4.8 release changes

## [0.4.8] - 2026-07-03


### Bug Fixes

- Add scan_warnings to detect scanner panics and adjust exit code
- Add host validation for SSH arguments in `validate_host`
- Refine chrony output parsing to improve time sync detection
- Add support for parsing user crontabs in RHEL/CentOS/Fedora
- Add support for exporting custom /etc/hosts overrides to XLSX report
- Allow license-file in cargo-deny for custom LICENSE
- Remove allow-license-file from deny.toml configuration
- Use only license-file for non-standard license
- Clarify license configuration in deny.toml
- Add hash for license clarification in cargo-deny
- Prevent duplicate entries in local hosts list
- Clarify license expression and include Commons Clause in deny.toml

### CI/CD

- Update workflows with refined permissions and improved artifact signing

### Features

- Detect process and image changes for network ports and containers
- Add support for parsing sshd_config includes and glob patterns

### Miscellaneous

- Add tempfile as a dev-dependency in Cargo.toml
- Move SBOM generation to signing step in release workflow
- Optimize SBOM generation in release workflow for x86_64 targets only
- Update CHANGELOG with bug fixes, features, CI/CD changes, and refactoring notes for v0.4.8
- Move SBOM generation to signing step and update dependencies in CI workflow
- Add SBOM generation step to CI workflow and update dependencies
- Update SBOM filename override handling in release workflow

### Refactoring

- Refactor XLSX export sections for standalone mode support and consolidate redundant code

### Testing

- Add unit tests for security module and update dependencies (tempfile)

## [0.4.7] - 2026-07-02


### Bug Fixes

- Refine `is_self_only` logic in security scanner to handle edge cases with "ALL" command detection

### CI/CD

- Replace direct changelog commits with PR-based automation
- Docs: update CHANGELOG for v0.4.6
- Uppdate action version in release workflow to latest commit hash
- Replace action with custom script for changelog PR creation

### Documentation

- Update JSON schema reference with expanded fields and new sections
- Update highlights and CLI options for v0.4.7

### Refactoring

- Introduce `run_child_with_timeout` for robust command execution
- Streamline package manager logic with parsers and reduce duplication
- Reuse dmesg output for OOM kill detection and error filtering

### enhance

- Detect backup tools via systemd timers in addition to cron jobs
- Add timeouts for Docker API calls to prevent indefinite waits
- Prevent duplicate sheet names in XLSX exports

## [0.4.6] - 2026-07-02


### Bug Fixes

- Implement timeout for remote scan tasks

### CI/CD

- Added changelog update automation to release workflow

### Refactoring

- Centralize XLSX format handling and streamline row styling

## [0.4.5] - 2026-07-02


### Build System

- **deps:** Bump uuid from 1.23.3 to 1.23.4

### CI/CD

- Fix missing cc binary in openSUSE test setup
- Added Alpine support to CI workflow
- Forced consistent cc symlink in openSUSE workflow
- Add auto-approve step for patch/minor updates
- Remove redundant CI checks waiting step
- Configure Rust compiler and linker settings in CI
- Updated CI workflow to improve package installation
- Triggered workflow on all branches
- Fix welcome action input names
- Added auto-approve workflow for drobit
- Update auto-approve workflow message to English

### Documentation

- Added comprehensive JSON field reference documentation
- Added project rationale to README and improve openSUSE CI setup
- Added bug reporting guidelines to CONTRIBUTING.md
- Updated README with Risk Score breakdown and remediation guidance
- Update README with breakdown feature and findings mapping

### Miscellaneous

- **deps:** Bump actions/checkout from 4.2.2 to 7.0.0
- **deps:** Bump taiki-e/install-action from 2.82.5 to 2.82.6
- **deps:** Bump actions/labeler from 5.0.0 to 6.1.0
- **deps:** Bump actions/first-interaction from 1.3.0 to 3.1.0
- **deps:** Bump dependabot/fetch-metadata from 2.0.0 to 3.1.0

### Refactoring

- Added `poll_wait` for improved child process management
- Fixed duplicate insert and updated port comparison logic
- Improved zypper patch handling and risk calculations
- Added OS basics extraction into `SystemBasics` struct
- Improve readability and security logic
- Restructured code into `cli` and `runner` modules
- Centralized report output logic in `output` module
- Streamline XLSX export with reusable formats and writer
- Introduce Formats and SheetWriter, migrate sheet_security and sheet_storage
- Migrate sheet functions to SheetWriter, remove dead code
- Migrate sheet_host_combined to SheetWriter API
- Complete xlsx migration to SheetWriter, unify sections
- Add risk score breakdown and integrate into UI output

### doc

- Updated to v0.4.4
- Add demo GIF for remote audit

## [0.4.4] - 2026-06-29


### CI/CD

- Relax cargo audit from --deny unsound --deny yanked to cargo audit --deny yanked

### Miscellaneous

- Added pipefail to install script and update labeler configs
- Truncated long Docker mount paths for better readability

### Performance Improvements

- Perf: added `is_known` method to `PackageManager` for clarity
ci: relax cargo audit from --deny warnings to --deny unsound --deny yanked

Replaced direct comparisons with `PackageManager::Unknown` by introducing the `is_known` method. This improves code readability and simplifies conditionals where package manager detection is required.

### Refactoring

- Updated command execution to use Rust threads for timeout.
- Updated case-insensitive matching and path handling
- Added `is_known` method to `PackageManager` for clarity
- Added cron job detection and improve NTP handling.
- Updated host scanning logic for improved modularity

### Testing

- Add unit tests for compare, cron parsing and Excel export

## [0.4.3] - 2026-06-29


### Bug Fixes

- Correct NTP false positive and missing iptables DROP policy

### CI/CD

- Set explicit CC environment variable in CI workflow

### Documentation

- Update remote audit examples to use operator user
- Update README for v0.4.3 features (snapshot, multi-host compare, dir-compare)

### Features

- Add snapshot, dir-compare, multi-host compare and refine firewall detection

### Refactoring

- Refactor main function to support graceful shutdown
- Replaced `truncate_hostname` with `sanitize_sheet_name`

## [0.4.2] - 2026-06-29


## [0.4.1] - 2026-06-28


### Performance Improvements

- Perf: parallelize zypper security patch inspection with rayon
refactor: remove duplicate OutputFormat::Xlsx2 variant

### release

- V0.4.1 – critical bugfixes, performance improvements, CI hardening

## [0.4.0] - 2026-06-27


### Bug Fixes

- Commit Cargo.lock for reproducible builds

### release

- Bump to v0.4.0 with security, performance and observability improvements

## [0.3.0] - 2026-06-25


### Bug Fixes

- False positives for rust/rabbitmq, sync exit code with risk score and fix xlsx format lifetime

### Features

- Add risk score, fail2ban/auditd, failed services, docker security checks, ssh source, date in Excel
- Add colored risk score in Excel, hyperlinks, timestamp in filename

### style

- Apply cargo fmt

## [0.2.0] - 2026-06-23


### Bug Fixes

- Collapse nested if in is_running_as_root

### release

- Bump version to 0.2.0

### style

- Apply cargo fmt

## [0.1.0] - 2026-06-22


### Bug Fixes

- Build static musl binaries for Linux compatibility
- Build static v2 musl binaries for Linux compatibility

### Features

- Static musl binaries for x86_64 and arm64

