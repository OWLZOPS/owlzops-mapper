
## Bug Fixes

- V0.5.8 - coverage in reports, russh upload exit-status (R9-01, R9-02)
- **ssh_engine:** Improve known_hosts handling, add error reporting, and extend tests (R9-07)
- **main:** Add clarification on writer.await to indicate guaranteed completion when channel is closed R9-03

## Documentation

- Update CHANGELOG for v0.5.7

## Miscellaneous

- **release:** Bump version to 0.5.8, update changelog

## Refactoring

- **scanners:** Optimize path handling and error reporting, improve shutdown logic(R9-04, R9-05)
- **runner, ssh_engine:** Reuse `split_host_port`, improve SSH/SCP argument handling (R9-06)

