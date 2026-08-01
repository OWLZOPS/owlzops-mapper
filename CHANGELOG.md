
## Bug Fixes

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

## Documentation

- Update CHANGELOG for v0.5.28
- Added false-positive.yml and updated install.sh,README, SECURITY
- Updated README

## Features

- **sec-042:** Detect system-wide LD_PRELOAD via /etc/ld.so.preload
- **kernel-facts:** Expose core_pattern, modules_disabled, and lockdown state
- **sec-043:** Provenance check for ExecStart in systemd units and cron
- **compare:** Add drift detection for exec_start_injections
- **exec_provenance:** Expand systemd coverage and fix quote bypass
- **exec_provenance:** Distinguish root- and user-executed units (R23-06)
- **compare:** Add drift for preload, core_pattern, modules_disabled, lockdown (R23-08)
- **safe_io:** Add O_NONBLOCK read for host-controlled paths (R23-10)

## Miscellaneous

- Bump scoring version, crate version, and update docs for R23

## Performance Improvements

- **audit:** Skip unnecessary rpm -qf calls for vendor units and fast mode
- **audit:** Cut rpm calls and fix under-reported duration
- **audit:** Cut rpm calls and fix under-reported duration
- **packages:** Replace `which` with internal `resolve_tool`
- **exec_provenance:** Gate target package resolution behind deep

## style

- Fix formatting

