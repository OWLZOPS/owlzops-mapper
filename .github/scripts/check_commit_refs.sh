#!/usr/bin/env bash
set -euo pipefail

# Check that every R24-xx / R25-xx reference in the PR commit messages also
# appears in the PR diff.
#
# This prevents false remediation claims from leaking into the changelog
# (R25-33, R25-49).
#
# R25-70:
# - use the pull request merge-base, not HEAD~1, so multi-commit PRs are checked
#   and merge commits do not break the diff;
# - check BOTH added and removed lines: a remediation is often a deletion;
# - collect IDs from ALL commits in the PR, not just HEAD.

commit="HEAD"

if [ -n "${BASE_SHA:-}" ]; then
  # PR run: diff from the true merge-base so changes on the base branch do not
  # pollute the PR diff.
  base="$(git merge-base "$BASE_SHA" "$commit" 2>/dev/null || echo "$BASE_SHA")"
else
  # Local fallback: last commit only.
  base="$commit~1"
fi

# All R2x-xx IDs from every commit in this PR.
body="$(git log --format=%B "$base".."$commit" 2>/dev/null || true)"
ids="$(printf '%s\n' "$body" | grep -oE 'R2[0-9]-[0-9]{2}' | sort -u || true)"

if [ -z "$ids" ]; then
  echo "No remediation IDs found in commit messages; skipping."
  exit 0
fi

changed_files="$(git diff --name-only "$base" "$commit" 2>/dev/null || true)"

if [ -z "$changed_files" ]; then
  echo "::error::Commit references remediation IDs but changes no files"
  exit 1
fi

failing=0
for id in $ids; do
  # R25-70: a remediation may be a DELETION, not only an addition. `^[+-][^+-]`
  # matches diff body lines but excludes `---` / `+++` headers.
  if ! git diff --unified=0 "$base" "$commit" 2>/dev/null \
      | grep -E '^[+-][^+-]' \
      | grep -Fq -- "$id"; then
    echo "::error::commit claims $id but no changed file mentions it"
    failing=1
  fi
done

exit "$failing"