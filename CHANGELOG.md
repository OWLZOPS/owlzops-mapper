
## Bug Fixes

- **main:** Replace `notify_waiters` with `notify_one` for proper signal handling during shutdown (R9-04-a)
- **scanners:** Improve error handling for `/proc/<pid>/fd` access, add coverage for incomplete port attribution (R9-08)
- **main:** Avoid panic on non-UTF-8 output paths (R9-09)
- **ssh_engine, utils:** Centralize timeout calculation with `host_budget_secs`, cleanup debug config (R9-10, R9-11)

## Documentation

- Update CHANGELOG for v0.5.8

## Features

- Render coverage_warnings in terminal and xlsx output
- **models:** Add forward-compatible deserialization for `PackageManager` enum (R9-12)

## Miscellaneous

- **release:** Bump version to 0.5.9, update changelog

