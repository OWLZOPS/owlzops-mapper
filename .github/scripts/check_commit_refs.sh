#!/usr/bin/env bash
set -euo pipefail

# Check the most recent commit: any R24-xx / R25-xx reference in the commit
# message must also appear in the files changed by that commit.
# This prevents false remediation claims from leaking into the changelog (R25-33).

commit="HEAD"
body="$(git log -1 --format=%B "$commit")"

# Collect all R2x-xx style IDs from the commit body.
ids="$(printf '%s\n' "$body" | grep -oE 'R2[0-9]-[0-9]{2}' | sort -u || true)"

if [ -z "$ids" ]; then
  echo "No remediation IDs found in commit message; skipping."
  exit 0
fi

changed_files="$(git diff --name-only "$commit~1" "$commit" 2>/dev/null || true)"

if [ -z "$changed_files" ]; then
  echo "::error::Commit references remediation IDs but changes no files"
  exit 1
fi

failing=0
for id in $ids; do
  found=""
  for file in $changed_files; do
    if git show "$commit:$file" 2>/dev/null | grep -Fq -- "$id"; then
      found=1
      break
    fi
  done

  if [ -z "$found" ]; then
    echo "::error::commit claims $id but no changed file mentions it"
    failing=1
  fi
done

exit "$failing"