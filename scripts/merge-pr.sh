#!/bin/sh
# merge-pr.sh <pr-number>: merge a reviewed PR locally and push its base branch, so the merge commit carries the repo's
# noreply identity (GitHub web merges sign with the account's primary email). Deletes the branch, then syncs the
# shared work dir: it never holds local commits, so `reset --mixed` only moves HEAD/index; working files stay.
set -eu
n=$1; top=$(git rev-parse --show-toplevel); cd "$top"
br=$(gh pr view "$n" --json headRefName -q .headRefName)
title=$(gh pr view "$n" --json title -q .title)
base=$(gh pr view "$n" --json baseRefName -q .baseRefName)
open=$(gh pr list --base "$br" --json number -q '[.[].number]|join(" ")')
[ -z "$open" ] || { echo "PR #$n: merge its fix PRs first: $open" >&2; exit 1; }
git fetch -q origin "$base" "$br"
wt=$HOME/.cache/netbird-zig-context/wt-merge-$n
git worktree add -q --detach "$wt" "origin/$base"
trap 'git -C "$top" worktree remove --force "$wt"' EXIT
cd "$wt"
git merge -q --no-ff "origin/$br" -m "Merge pull request #$n from kalpakprod/$br" -m "$title"
git push -q origin "HEAD:$base"
git push -q origin --delete "$br"
cd "$top"; git fetch -q origin; git reset -q --mixed origin/main
echo "PR #$n: $(gh pr view "$n" --json state -q .state)"; git log --oneline -1
