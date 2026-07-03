# Changelog

## Bug Fixes

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

## CI/CD

- Update workflows with refined permissions and improved artifact signing

## Documentation

- Update CHANGELOG for v0.4.7

## Features

- Detect process and image changes for network ports and containers
- Add support for parsing sshd_config includes and glob patterns

## Miscellaneous

- Add tempfile as a dev-dependency in Cargo.toml
- Bump version to 0.4.8 in Cargo.toml and Cargo.lock
- Move SBOM generation to signing step in release workflow

## Refactoring

- Refactor XLSX export sections for standalone mode support and consolidate redundant code

## Testing

- Add unit tests for security module and update dependencies (tempfile)

