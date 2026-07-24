#!/usr/bin/env bash
set -euo pipefail

f="$1"

# Known false positives on the GitHub runner:
#   suspicious_processes : provjobd* (Azure provisioning daemon)
#   library_injections   : networkd-dispat with source maps-rwx-provisional
# Any other IoC finding on any channel breaks the build.

unexpected=$(jq -r '
  ([.security.suspicious_processes[]?.name
     | select(test("^provjobd") | not)] | length)
  + ([.security.library_injections[]?
     | select(.process != "networkd-dispat")] | length)
  + ([.security.ghost_pids[]? | select(.confirmed_ioc)] | length)
  + ([.security.reverse_shells[]?] | length)
  + ([.security.mount_masking[]?]  | length)' "$f")

if [ "$unexpected" -ne 0 ]; then
  echo "::error::$unexpected unexpected IoC finding(s) in $f — new false positive or real regression"
  jq '.security | {suspicious_processes, library_injections, ghost_pids, reverse_shells, mount_masking}' "$f"
  exit 1
fi