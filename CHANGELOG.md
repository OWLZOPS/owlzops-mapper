
## Bug Fixes

- Close Raw Truth gaps in library_injection, DLP, eBPF pins, musl cfg
- Add __builtin__ftrace to pseudo-module exclusion list
- Add blank lines between kernel hardening info lines in terminal output
- Tier CAP-002 ambient caps, SEC-038/039 point-in-time vs drift weights

## Build System

- **deps:** Bump russh from 0.62.3 to 0.62.4 (#122)

## Documentation

- Update CHANGELOG for v0.5.25
- Update CHANGELOG for v0.5.26

## Features

- **compare:** Detect eBPF program swap by prog_tag, not count
- SEC-038/039/040 kernel hardening scanners
- Activate SEC-038/039/040 findings and UI rendering

## Miscellaneous

- Tighten dlp denied counter, fix eng comment in ebpf
- Ignore .idea directory
- **release:** Bump version to 0.5.26

## Refactoring

- **fs_inventory:** Unify setuid predicate, remove double-indirection, clarify budget docs
- **ui:** Introduce tty-aware theme and unify unicode escapes

## Testing

- **library_injection:** Make lone_dropper_rwx_still_alarms independent of environment
- Add drift tests for AppArmor complain and kernel taint

