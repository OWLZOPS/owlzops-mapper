
## Bug Fixes

- **compare, utils:** Prevent false escalation for wildcard binds already present with loopback

## Documentation

- Update CHANGELOG for v0.5.10
- **fields:** Update FIELDS.md with new properties and enhanced descriptions

## Features

- **ui, exporters, scanners:** Add elevated capabilities audit for non-root processes
- **scanners:** Enhance capability audit with NoNewPrivs and Seccomp support
- **ui, exporters:** Extend capability audit with NoNewPrivs and Seccomp details
- **scoring:** Adjust CAP-001 weighting for global exposure, bump SCORING_VERSION to 6
- **scoring:** Add SEC-015 active compromise IoC detector
- **scoring:** Add SEC-016 detector for known malware and miners by process name
- **scoring, scanners:** Full /proc malware sweep, two-tier name detection
- **scoring, scanners, ui:** Add SEC-017 detector for malicious cron jobs
- **scoring, scanners:** Enhance process classification and introduce SEC-017 fileless malware detector
- **utils, scoring:** Add /memfd: to ephemeral path predicate, bump scoring version
- **scoring:** Enhance SEC-017 to distinguish in-memory (memfd) processes

## Miscellaneous

- **release:** Bump version to 0.5.11, refine utils for improved process handling

## Refactoring

- **network, utils:** Centralize bind address checks into reusable predicates
- **ui:** Improve data presentation with dynamic tables and enhanced sanitization
- **ui:** Add category-specific risk breakdown with improved headers and icons
- **ui:** Simplify category formatting with conditional icon support for TTY

## classify

- **scanners:** Extend fileless detection to include /memfd: base paths

