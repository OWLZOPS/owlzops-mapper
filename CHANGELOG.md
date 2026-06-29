## v0.4.2 (2026-06-29)

### Fixed
- C-1: Parallelized `last -i` calls to single invocation, reducing scan time by 90%
- C-3: Removed `take(20)` limit in zypper security patch detection, ensuring all patches flagged
- H-4: Added warnings when Docker inspect fails or container missing
- H-5: Extended `compare` to detect firewall, SSH, NTP, fail2ban, auditd, OS/kernel, package count, SSL critical threshold drifts
- H-6: Removed `sh -c` dependency; replaced with direct `dmesg` calls and `/proc/self/limits` parsing
- Fixed `compare` to accept both single object and array JSON snapshots
- Fixed backup detection false positives (restic/borg/duplicati without actual data)