
## Bug Fixes

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

## Documentation

- Update CHANGELOG for v0.5.27

## Features

- Universal container runtime detection (Docker + Podman)
- Drift detection for setuid files and file capabilities

## Miscellaneous

- **release:** Bump version to 0.5.28

## Refactoring

- Unify socket existence checks via socket_reachable helper (R22-13)
- Extract classify_listeners for shadow-IT tiering

