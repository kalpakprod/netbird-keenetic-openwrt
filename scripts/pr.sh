#!/bin/sh
# pr.sh <branch> <title> <path>...: open a PR with exactly these paths from the work dir, on top of origin/main.
# Uses a temporary worktree, so the shared work dir and its main stay untouched. Prints the PR URL.
set -eu
br=$1; title=$2; shift 2
top=$(git rev-parse --show-toplevel); wt=$HOME/.cache/netbird-zig-context/wt-$(echo "$br" | tr / -)
cd "$top"; git fetch -q origin
git worktree add -q -b "$br" "$wt" origin/main
trap 'git -C "$top" worktree remove --force "$wt"' EXIT
for p in "$@"; do mkdir -p "$wt/$(dirname "$p")"; cp -a "$top/$p" "$wt/$(dirname "$p")/"; done
cd "$wt"; git add -- "$@"; git commit -q -m "$title"
git push -q -u origin "$br"
gh pr create --base main --head "$br" --title "$title" --body "${PR_BODY:-$title}

Port of NetBird v0.79.0 to Zig, see PLAN.md.

https://claude.ai/code/session_01BsVwQEhCy4c35aK8tjA9A6"
