
## Bug Fixes

- **ssh:** Log errors when writing to known_hosts instead of silently ignoring
- **ssh:** Add keepalive support with configurable interval and max attempts

## Build System

- **deps:** Bump dialoguer from 0.11.0 to 0.12.0 (#43)
- **deps:** Bump russh from 0.62.1 to 0.62.2 (#45)
- **deps:** Bump rust_xlsxwriter from 0.77.0 to 0.96.0 (#47)
- **deps:** Bump thiserror from 1.0.69 to 2.0.18

## CI/CD

- Update CLA workflow to use 'cla-signatures' branch for signatures
- Expand CLA workflow allowlist to include additional bot patterns
- Update CLA workflow allowlist to include `web-flow` bot

## Documentation

- Update CHANGELOG for v0.5.4

## Features

- **scanners:** Add capped I/O for safer /proc parsing; introduce truncation tracking and coverage logging
- **scanners:** Integrate capped I/O across DLP and security scanners; enhance truncation tracking and coverage logging
- **exporters/ui:** Add sanitization for XLSX and terminal outputs to mitigate injection risks
- **utils:** Add hardened tool resolution and environment sanitization

## Miscellaneous

- Update `crossbeam-epoch` to v0.9.20 in Cargo.lock to avoid RUSTSEC-2026-0204
- Add `Zlib` to deny.toml license exceptions
- **deps:** Bump taiki-e/install-action from 2.82.6 to 2.82.9
- **deps:** Bump dtolnay/rust-toolchain
- Bump version to 0.5.5, update changelog

## Refactoring

- **ssh:** Introduce `KnownHostsChecker` for streamlined host key verification and TOFU handling

