
## Bug Fixes

- **provenance:** Distinguish unreadable DB from missing package
- **scoring:** Align classify_* with ProvenanceSource semantics
- **sudoers:** Use capped I/O and emit coverage on unreadable files
- **fleet:** Two-phase Ctrl-C teardown preserves remote cleanup
- R19V follow-up — eBPF links, teardown grace, lost reports
- R19-V follow‑up – graceful degradation, APK, eBPF, and local Ctrl‑C
- Kill helpers on local interrupt; clarify sudoers NotFound message
- Local scan interrupt in mixed fleet + panic=unwind invariant
- **ci:** Cover --no-default-features with clippy and tests, guard panic=unwind
- **e2e:** Harden CI contract — triage IoC, add deep+interrupt checks
- Suppress clippy warnings for --no-default-features build
- **ci:** Temporarily drop clippy+tests from macOS orchestrator job
- **e2e:** Allowlist provjobd with any suffix in suspicious process check

## CI/CD

- Add custom CodeQL workflow for musl target
- Drop CodeQL due to false positives and slow execution

## Documentation

- Update CHANGELOG for v0.5.23
- Added Security Policy
- Update CHANGELOG for v0.5.24
- Update CHANGELOG for v0.5.24

## Features

- **ebpf:** Add link objects, prog_tag, and truncation coverage
- **compare:** Add drift detection for setuid, capabilities, and eBPF

## Miscellaneous

- **release:** Bump version to v0.5.24

## Performance Improvements

- **setuid:** Reuse Metadata from read_dir to avoid double stat

