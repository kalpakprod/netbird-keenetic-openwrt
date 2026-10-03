#!/bin/sh
# merge-pr.sh <pr-number>: merge a reviewed PR (merge commit) and sync the shared work dir to origin/main.
# The work dir never holds local commits, so `reset --mixed` only moves HEAD/index; working files stay as they are.
set -eu
gh pr merge "$1" --merge --delete-branch
cd "$(git rev-parse --show-toplevel)"; git fetch -q origin; git reset -q --mixed origin/main
git log --oneline -1
