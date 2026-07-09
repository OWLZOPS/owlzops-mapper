
## Bug Fixes

- **storage:** Use MiB for DiskInfo, add exact usage_pct (R10-01, R10-02)

## CI/CD

- **workflows:** Set `CC` environment variable to clang for test jobs (to fix undefined symbol __isoc23_sscanf )
- **workflows:** Switch to GCC, update matrix cache prefix key for consistency
- **workflows:** Force GCC over Clang for aws-lc-sys on Ubuntu 22.04, adjust child process handling
- **workflows:** Enhance caching logic, refine GCC enforcement and organize steps for clarity

## Documentation

- Update CHANGELOG for v0.5.9

## Features

- **compare:** Detect port exposure escalation from local to wildcard (R10-03)
- **network:** Detect and display DNS upstreams in UI and XLSX output
- **ui, exporters, host:** Display reboot-required package details in UI and XLSX output
- **ui, scoring:** Enhance cron job analysis and risk scoring output
- **ui, exporters, host:** Improve zombie process reporting with parent details
- **ui, scanners:** Add container RW size, aggregated process counts and reclaimable disk space
- **ui, exporters, scanners:** Improve image size reporting and calculation logic
- **scanners:** Add support for identifying container runtimes and orchestrators

## Miscellaneous

- **release:** Bump version to 0.5.10, update changelog

