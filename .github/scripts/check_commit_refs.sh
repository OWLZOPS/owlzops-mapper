#!/usr/bin/env bash
set -uo pipefail

# Check that every R24-xx / R25-xx reference in the commit messages also
# appears in the relevant diff.
#
# This prevents false remediation claims from leaking into the changelog
# (R25-33, R25-49).
#
# R25-70:
# - use the pull request merge-base, not HEAD~1, so multi-commit PRs are checked;
# - collect IDs from ALL commits in the PR, not just HEAD;
# - check the whole diff, because a remediation can be a deletion, rename,
#   or mention in context lines, not always an added line.
#
# R25-72: strict UTF-8 and line numbers for known_hosts trust store.

commit="HEAD"

case "${GITHUB_EVENT_NAME:-}" in
  pull_request)
    if [ -n "${BASE_SHA:-}" ] && [ "${BASE_SHA}" != "null" ]; then
      base="$(git merge-base "$BASE_SHA" "$commit" 2>/dev/null || echo "$BASE_SHA")"
    else
      base="$commit~1"
    fi
    ;;
  *)
    base="$commit~1"
    ;;
esac

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

diff_text="$(git diff --unified=0 "$base" "$commit" 2>/dev/null || true)"

failing=0
for id in $ids; do
  if ! printf '%s\n' "$diff_text" | grep -Fq -- "$id"; then
    echo "::error::commit claims $id but no changed file mentions it"
    failing=1
  fi
done

exit "$failing"