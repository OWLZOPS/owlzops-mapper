
## Bug Fixes

- PAM scanner audit fixes (R23-60, R23-61, R23-62, R23-63)
- **pam:** Resolve audit findings R23-68–R23-73
- **pam:** R23-74 parent_takeable for pam_exec, R23-75 remove root-only guard, R23-76 resolve_module mimics libpam
- **pam:** Close R23-80 (missing continue), R23-81 (.. bypass), R23-83 (test gap)
- **pam:** R23-85 detect pam_exec scripts hidden behind sh -c wrapper
- **pam:** R23-88 exclude non-executable data arguments from pam_exec targets

## Documentation

- Update CHANGELOG for v0.5.31
- SEC-055/056/057 weights in README, pam_injections schema in FIELDS.md, bump SCORING_VERSION to v11
- Updated README
- **README:** Fixed Security Findings table

## Features

- PAM stack injection scanner (SEC-055/056/057)

## Miscellaneous

- **pam:** R23-82 replace PamScriptInfo with target_kind, R23-86 add declared_as, R23-87 cleanup tests and dead sort
- Bump version to 0.5.32

