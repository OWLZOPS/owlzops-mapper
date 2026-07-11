
## Bug Fixes

- **russh:** Enforce binary cleanup and JSONL error handling (R10-01, R10-02, R10-03)
- **utils:** Improve poison lock handling, tool resolution, and child process safety (R10-04, R10-05)
- **utils:** Improve poison lock handling, tool resolution, and child process safety (R10-04, R10-05)
- **ui:** Sanitize bidi and zero-width characters (R10-06)
- **utils:** SIGTERM legacy SSH children on shutdown (R10-07)
- **exporters:** Add integer format for PID and EUID in XLSX reports (R10-08)
- **russh:** Optimize TCP_NODELAY settings and reduce chunk size for file streams
- **workflows:** Remove stderr redirection for audit JSON output
- **workflows:** Update exit code validation and capture stderr logs in e2e tests

## Documentation

- Update CHANGELOG for v0.5.11
- **exporters:** Add `euid` and `is_mimic` fields, adjust XLSX formatting (R10-08)

## Features

- **scoring, scanners:** Add DOCK-010 to detect runtime capability tampering
- **scoring:** Introduce SEC-019 to detect fileless processes with critical kernel capabilities
- **scoring, main:** Track active compromises with `compromised_host` flag, update exit codes
- **scoring:** Add SEC-020 for detection of kernel thread mimicry
- **scoring:** Add SEC-021 for detecting bind-mount and overlay masking
- **scoring, exporters, ui:** Add SEC-022 for reverse shell/C2 detection
- **scoring, exporters, ui:** Add SEC-023 for userspace rootkit/library injection detection
- **scoring, detectors, tests:** Add SEC-024 for detecting LKM rootkit-hidden "ghost" PIDs
- **exporters, ui, docs:** Add SEC-024/025 ghost PID detection

## Miscellaneous

- Bump version to 0.5.12, update README with refocused messaging and feature highlights

## Refactoring

- **scoring:** Streamline SEC-019 logic for fileless malware detection

