
## Bug Fixes

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

## Build System

- **deps:** Bump actions/checkout from 7.0.0 to 7.0.1 (#94)
- **deps:** Bump serde_json from 1.0.150 to 1.0.151 (#96)
- **deps:** Bump uuid from 1.23.5 to 1.24.0 (#98)
- **deps:** Bump clap from 4.6.1 to 4.6.3 (#100)
- **deps:** Bump russh from 0.62.2 to 0.62.3 (#99)
- **deps:** Bump dtolnay/rust-toolchain
- **deps:** Bump taiki-e/install-action from 2.83.2 to 2.84.0

## Documentation

- Update CHANGELOG for v0.5.22
- Add service links to README for improved navigation

## Features

- Implement unified sudoers parser for NOPASSWD checks across scanners
- Add file capabilities inventory module (R16)
- Extend security reporting with file capabilities (SEC-034)
- Add eBPF inventory scanner (R17)
- Integrate eBPF inventory (SEC-035) into security reporting
- Enhance SEC-034 with risk-tiering and introduce SEC-036 for unexpected file capabilities
- Integrate setuid/setgid inventory (SEC-037) into security reporting
- Integrate dpkg provenance resolver for file caps & setuid tiering

## Miscellaneous

- **release:** Bump version to v0.5.23

## Refactoring

- Modularize file capabilities scanner for Linux compatibility
- Use location+ownership heuristic for setuid tiering instead of hardcoded name list

