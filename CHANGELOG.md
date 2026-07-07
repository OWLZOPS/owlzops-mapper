
## Bug Fixes

- **russh:** Cap stdout/stderr buffers to prevent OOM (R8-01)
- **known_hosts:** Avoid false HostKeyChanged for multi-key hosts (R8-02)
- **utils:** Cap stderr of child processes at 1 MiB (R8-03)
- **ssh_engine:** Improve host key error messages and IPv6 handling (R8-04, R8-05)
- **utils:** Nullify stdin for child processes to enhance security (R8-07)
- **safe_io:** Handle invalid UTF-8 conversion gracefully, remove unused variable in main.rs (N8-1, N8-4)
- **ssh_engine:** Add detailed russh error context and robust error handling N8-5
- **dlp:** Prevent OOM by capping comm file reads and log truncation events (N8-6)
- **models:** Add #[serde(default)] for backward compatibility with older snapshots (R8-06)
- **proc_net:** Improve parsing robustness, handle edge cases, and clean up logic (N8-2)
- **network:** Deduplicate listening ports with HashSet (N8-3)
- **ssh_engine:** Switch progress bar to spinner for uploads, simplify key handling (N8-7)
- **main:** Add graceful shutdown handling with signal support (N8-8)

## Documentation

- Update CHANGELOG for v0.5.5

## Miscellaneous

- **release:** Bump version to 0.5.6, update changelog

