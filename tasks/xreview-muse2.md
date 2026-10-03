$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Review GLM's protobuf wire runtime PR against protowire and merge it on approval.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first (PR rules changed: every change goes through scripts/pr.sh). Plan: PLAN.md and council/r3-merged.md. Reference: upstream/netbird (with vendor/), Zig std at `mise where zig`/lib/std.</workspace>
  <authority>May create or change only: GitHub review comments only. May run gh for this repo (pr, issue, review). Must not: commit on main, push main, install anything, ssh anywhere, touch other files. Load limits from AGENTS.md apply.</authority>
  <steps>1. Wait until /home/kukuruza/.cache/netbird-zig-context/results/impl-proto-glm.md has a STATUS line and a PR URL (sleep 120 between checks, 120 min max, then BLOCKED). 2. Compare src/proto/wire.zig with vendor/google.golang.org/protobuf/encoding/protowire/wire.go: overflow rules, max lengths, error cases. 3. In a temporary worktree of the PR branch run zig build test and zig test on the PR's test files; paste output. 4. Post the verdict: gh pr review <n> --comment -b '<ДА/НЕТ + findings file:line>'. 5. On ДА run scripts/merge-pr.sh <n>. On НЕТ wait for GLM's fix (max two rounds).</steps>
  <rules>Real changes only, never empty or cosmetic commits to inflate activity. Facts from files and commands you ran. If a step is impossible, write BLOCKED with the reason. Every "works" claim carries the command and its output.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/xreview-muse2.md: one-line result, files, PR/issue URLs, commands with output, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
