
## Bug Fixes

- R11 audit fixes (cleanup guarantee, terminal sanitization, coverage cap)
- **utils:** Handle stdout/stderr take safety in child process
- **scanners:** Disable io_uring statx on musl to fix Alpine build
- **ui:** Ensure progress bars are always cleared and improve error logging
- **progress:** Make upload progress bar optional based on conditions
- **scanners:** Skip self-zombies in zombie detection logic and apply minor formatting adjustments
- **scanners:** Update comments in zombie detection to improve clarity and consistency
- **ssh_engine:** Make `sudo_pass` optional and adjust remote scan logic

## Documentation

- Update CHANGELOG for v0.5.12

## Features

- **scanners:** Enhance ghost PID detection with thread filtering and hidepid safeguard
- Add `--deep` flag for enhanced scan depth and ghost PID detection
- **audit:** Add spinner for progress visualization and improve shutdown handling
- **ssh_engine:** Add upload progress bar integration and improve user feedback

## Miscellaneous

- **release:** Bump version to 0.5.13 and update documentation

## Refactoring

- **utils:** Reorder `poll_wait` for better readability

