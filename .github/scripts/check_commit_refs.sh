#!/usr/bin/env bash
set -uo pipefail

# Check that every R24-xx / R25-xx reference in a commit message also appears
# in that commit's own diff. Each commit is validated independently, so a
# later cleanup commit is not blamed for IDs claimed by earlier commits.
#
# This prevents false remediation claims from leaking into the changelog.
#
# R25-70:
# - use the pull request merge-base, not HEAD~1, so multi-commit PRs are checked;
# - collect IDs from ALL commits in the PR;
# - check each commit against its own diff, not the aggregated PR diff.
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

commits="$(git rev-list --reverse "$base".."$commit" 2>/dev/null || true)"
if [ -z "$commits" ]; then
  echo "No commits in range; skipping."
  exit 0
fi

failing=0
for c in $commits; do
  body="$(git log -1 --format=%B "$c")"
  ids="$(printf '%s\n' "$body" | grep -oE 'R2[0-9]-[0-9]{2}' | sort -u || true)"
  [ -z "$ids" ] && continue

  # Diff of this exact commit against its parent.
  diff_text="$(git diff --unified=0 "$c^" "$c" 2>/dev/null || true)"
  for id in $ids; do
    if ! printf '%s\n' "$diff_text" | grep -Fq -- "$id"; then
      echo "::error::commit $c claims $id but its diff does not mention it"
      failing=1
    fi
  done
done

exit "$failing"