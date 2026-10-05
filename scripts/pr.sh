#!/bin/sh
# pr.sh <branch> <title> <path>...: open a PR with exactly these paths, on top of origin/$BASE (default main).
# Files come from $SRC (default: the work dir). A fix for a reviewed PR sets BASE to that PR's branch and SRC to the
# worktree holding the fix, so each fix is its own PR into the reviewed branch.
# Uses a temporary worktree, so the shared work dir and its main stay untouched. Prints the PR URL.
set -eu
br=$1; title=$2; shift 2
base=${BASE:-main}
top=$(git rev-parse --show-toplevel); src=${SRC:-$top}; wt=$HOME/.cache/netbird-zig-context/wt-$(echo "$br" | tr / -)
cd "$top"; git fetch -q origin
git worktree add -q -b "$br" "$wt" "origin/$base"
trap 'git -C "$top" worktree remove --force "$wt"' EXIT
for p in "$@"; do mkdir -p "$wt/$(dirname "$p")"; cp -a "$src/$p" "$wt/$(dirname "$p")/"; done
cd "$wt"; git add -- "$@"; git commit -q -m "$title"
git push -q -u origin "$br"
gh pr create --base "$base" --head "$br" --title "$title" --body "${PR_BODY:-$title}

Port of NetBird v0.79.0 to Zig, see PLAN.md.

https://claude.ai/code/session_01BsVwQEhCy4c35aK8tjA9A6"
