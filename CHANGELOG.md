
## Bug Fixes

- Refine `is_self_only` logic in security scanner to handle edge cases with "ALL" command detection

## CI/CD

- Replace direct changelog commits with PR-based automation
- Docs: update CHANGELOG for v0.4.6
- Uppdate action version in release workflow to latest commit hash
- Replace action with custom script for changelog PR creation

## Documentation

- Update JSON schema reference with expanded fields and new sections
- Update highlights and CLI options for v0.4.7

## Miscellaneous

- Bump version to 0.4.7

## Refactoring

- Introduce `run_child_with_timeout` for robust command execution
- Streamline package manager logic with parsers and reduce duplication
- Reuse dmesg output for OOM kill detection and error filtering

## enhance

- Detect backup tools via systemd timers in addition to cron jobs
- Add timeouts for Docker API calls to prevent indefinite waits
- Prevent duplicate sheet names in XLSX exports

