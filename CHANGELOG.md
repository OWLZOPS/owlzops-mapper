
## Bug Fixes

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

## CI/CD

- Add job timeouts, harden E2E interrupt test
- Re-enable clippy for macOS orchestrator after dead-code cleanup

## Documentation

- Update CHANGELOG for v0.5.24

## Features

- **provenance:** Distinguish truncated APK database from complete

## Miscellaneous

- Start 0.5.25 development cycle
- **release:** Bump version to v0.5.24

## Refactoring

- **scanners:** Unify filesystem walk for setuid and file capabilities

