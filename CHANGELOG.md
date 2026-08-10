
## Bug Fixes

- R24-01 correct PAM line parsing (whitespace runs, bracketed control)
- R24-01 correct PAM line parsing (whitespace runs, bracketed control), R24-02 capped safe read for authorized_keys
- R24-05 fail-closed for /proc/net/* read errors
- R24-05 fail-closed for /proc/net/* read errors in reverse_shell and proc_net
- R24-06 snapshot --hosts with unreadable/empty file fails loudly instead of falling back to local scan
- R24-07 one‑way switch vanishing between snapshots is now a Degraded drift event
- R24-04 use setsid for child processes, kill entire process group on timeout
- R24-11 capped-regular read for authorized_keys, R24-13 audit --hosts fails loud, pub(crate) CAP_AUTHORIZED_KEYS
- R24-12 InvalidInput -> InvalidData in access.rs
- R24-07 union-loop for one‑way switches, detect vanished keys as Degraded
- R24-14 replace remaining child.kill() with kill_group_and_reap in utils.rs
- R24-08 rename one‑way switch labels (no spaces), R24-09 make PAM uid/gid Option<u32>
- R24-15 restore one-way switch direction severity, add tests
- R24-16 record coverage when one-way switch contains a non-numeric value

## Documentation

- Update CHANGELOG for v0.5.32
- Update FIELDS.md for pam_injections uid/gid nullable (R24-09)

## Miscellaneous

- Bump version to 0.5.33, finalise R24 documentation

## Performance Improvements

- R24-03 memoize resolve_batch with negative caching

