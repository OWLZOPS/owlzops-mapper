
## Bug Fixes

- **provenance:** Distinguish unreadable DB from missing package
- **scoring:** Align classify_* with ProvenanceSource semantics
- **sudoers:** Use capped I/O and emit coverage on unreadable files
- **fleet:** Two-phase Ctrl-C teardown preserves remote cleanup

## Documentation

- Update CHANGELOG for v0.5.23
- Added Security Policy

## Features

- **ebpf:** Add link objects, prog_tag, and truncation coverage
- **compare:** Add drift detection for setuid, capabilities, and eBPF

## Miscellaneous

- **release:** Bump version to v0.5.24

## Performance Improvements

- **setuid:** Reuse Metadata from read_dir to avoid double stat

