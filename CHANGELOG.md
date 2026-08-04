
## Build System

- **deps:** Bump russh from 0.62.4 to 0.62.5 (#165)
- **deps:** Bump clap from 4.6.4 to 4.6.5 (#166)
- **deps:** Bump taiki-e/install-action from 2.85.2 to 2.85.5 (#168)
- **deps:** Bump rust_xlsxwriter from 0.96.0 to 0.97.0 (#167)
- **deps:** Bump thiserror from 2.0.18 to 2.0.19 (#169)

## Documentation

- Update CHANGELOG for v0.5.29
- Updated README.md

## Miscellaneous

- Release v0.5.30 — SEC-051, docs, scoring version bump

## SEC-050

- Detect ld.so.conf.d library path injection
- Add drift detection for ld_so_conf_injections

## SEC-051

- Detect ld.so.conf.d library path injection
- Implement ld.so.conf injection scanner (R23 audit fixes)
- Address R23-40..R23-44 audit findings
- Fix volatile regression and directory include (R23-45, R23-46)
- Fix false positive on stale missing directories (R23-48)

