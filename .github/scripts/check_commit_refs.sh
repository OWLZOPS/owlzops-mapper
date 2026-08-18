#!/usr/bin/env bash
set -euo pipefail

# R25-84: on pull_request, GitHub checks out a merge commit; HEAD-only here
# would see no R-IDs and silently skip. Validate every commit in the PR
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

failing=0

for id in $ids; do
  found=0
  for c in $(git rev-list --reverse "$base".."$commit"); do
    # Body lines only. `--unified=0` still emits `@@ ... @@ <section heading>`,
    # and git takes that heading from the nearest column-0 line — very often a
    # `// R25-xx:` comment here. Grepping the raw diff lets any hunk in that
    # block satisfy an unrelated claim (R25-49). `^rename ` keeps renames.
    diff_text="$(git diff --unified=0 "$c^" "$c" 2>/dev/null || true)"
    if printf '%s\n' "$diff_text" \
      | grep -E '^[+-][^+-]|^rename ' \
      | grep -Fq -- "$id"; then
      found=1
      break
    fi
  done

  if [ "$found" -eq 0 ]; then
    echo "::error::no changed file mentions $id"
    failing=1
  fi
done

exit "$failing"