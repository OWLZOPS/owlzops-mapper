
## CI/CD

- Add Rust dependencies caching in CI workflow for build optimization

## Documentation

- Update CHANGELOG for v0.5.1

## Features

- Add detection of sensitive Docker mounts and update scoring version to 3
- Add Docker reliability checks and bump SCORING_VERSION to 4
- Add interactive sudo support and SSH concurrency configuration
- Add progress bar for SCP uploads using `indicatif`
- Add progress bar and optional binary cleanup flag
- Enhance terminal output with TTY detection and risk score colorization

## Miscellaneous

- Allow RUSTSEC-2023-0071 advisory in deny.toml
- Fix inconsistent icon spacing in TTY output
- Bump version to 0.5.2, update changelo

## Refactoring

- Implement atomic binary deployment and cleanup CLA integration

