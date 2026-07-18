
## Bug Fixes

- **ghost_pid:** Ensure safe completion drain to prevent use-after-free/errors during inflight SQE handling
- **xlsx:** Add guard for formula injection bypass via leading whitespace/control chars

## Documentation

- Update CHANGELOG for v0.5.18

## Miscellaneous

- **release:** Bump version to 0.5.19, update README with transport resilience, async I/O and SSH refactor

## Refactoring

- **ssh:** Streamline session teardown, improve timeout handling and replace mutable flag with `AtomicBool`
- **proc_net:** Consolidate address decoding and inode helpers for reuse in reverse_shell
- **ssh:** Transition to async I/O with `tokio::fs` for file operations and handle blocking key loading safely
- **coverage:** Implement scoped coverage tracking and transition remote scans to `russh` engine

