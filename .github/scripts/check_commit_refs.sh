#!/usr/bin/env bash
set -uo pipefail

commit="HEAD"
body="$(git log -1 --format=%B "$commit")"
ids="$(printf '%s\n' "$body" | grep -oE 'R2[0-9]-[0-9]{2}' | sort -u || true)"

if [ -z "$ids" ]; then
  echo "No remediation IDs found in the latest commit; skipping."
  exit 0
fi

diff_text="$(git diff --unified=0 "$commit^" "$commit" 2>/dev/null || true)"
failing=0
for id in $ids; do
  if ! printf '%s\n' "$diff_text" | grep -Fq -- "$id"; then
    echo "::error::latest commit claims $id but its diff does not mention it"
    failing=1
  fi
done
exit "$failing"
EOF