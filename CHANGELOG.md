
## Build System

- **deps:** Bump uuid from 1.23.4 to 1.23.5 (#76)

## Documentation

- Update CHANGELOG for v0.5.15

## Features

- **scanners:** Refine suspicious listener detection and add SEC-030 for developer tool monitoring
- **scanners/ui:** Add SEC-031 for provisional trust and refine loopback listener classification
- **ui:** Refine listener classification and emphasize IPC provenance
- **scanners:** Implement verdict cache for deep scan results and refine provisional trust logic
- **scanners:** Introduce multi-tier attribution funnel and enhance trust evaluation
- **scanners:** Enhance trust logic with strong signals and JIT buffer detection
- **ui:** Expand trust logic to include `ManagedJIT` and `ReservedBuffer` origins
- **scoring/utils:** Expand runtime and trust logic with additional sources and heuristics

## Miscellaneous

- **deps:** Bump softprops/action-gh-release from 3.0.1 to 3.0.2 (#72)
- **deps:** Bump EmbarkStudios/cargo-deny-action from 2.0.20 to 2.1.1 (#73)
- **deps:** Bump actions/labeler from 6.1.0 to 6.2.0 (#74)
- **deps:** Bump taiki-e/install-action from 2.82.9 to 2.83.2
- **release:** Bump version to 0.5.16 and update README

## Refactoring

- **ui:** Simplify condition logic for ephemeral executable checks
- **utils/scoring/ui:** Update `exe_provenance` to include PID and refine provenance logic

