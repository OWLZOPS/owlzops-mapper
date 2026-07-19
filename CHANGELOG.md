
## Bug Fixes

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

## CI/CD

- **release:** Optimize workflow by using pre-built cargo-cyclonedx binary and standardize branch naming

## Documentation

- Update CHANGELOG for v0.5.20
- Update CHANGELOG for v0.5.21
- **readme:** Update remote audit instructions and macOS guidance
- **readme:** Clarify macOS remote audit setup and binary handling

## Features

- **local-scan:** Add conditional support for local scans and platform-specific TCP hardening
- **runtime-trust:** Add file-text anchoring and exec-heap provisional trust
- **ci+release:** Add macOS orchestrator build and packaging support
- **install:** Add macOS support and OS-specific architecture handling
- **install:** Add macOS support and OS-specific architecture handling

## Miscellaneous

- **release:** Bump version to 0.5.21

