
## Bug Fixes

- Prevent deadlocks in `run_child_with_timeout` by managing stdout/stderr handling in separate threads and add related tests
- Enhance `run_child_with_timeout` tests to prevent deadlocks and improve process cleanup
- Simplify `installed_count` function by removing unnecessary `bin` parameter
- Handle empty fleet scan reports with specific exit code and warning logging
- Add error handling for report output functions and support `Path` for output files
- Increase du timeout to 60s, add -x to avoid crossing filesystem boundaries
- Increase du timeout to 60s and add -x to avoid crossing filesystem boundaries
- Wrap `run_local_scan_async` in a span for better tracing and simplify async handling
- Add timeout for dangling volumes check and improve SSH config fallback parsing
- Simplify authorized keys path resolution by using user home directories
- Restrict self-exclusion in sudo audit to known canonical paths
- Improve NTP offset parsing by adding unit support and handling edge cases
- Enhance scoring and scanning logic with safer calculations and stricter validations

## Documentation

- Update CHANGELOG for v0.4.9

## Miscellaneous

- Bump version to 0.4.10

