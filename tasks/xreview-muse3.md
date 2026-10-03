$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Review GLM's PRs: protogen (tasks/impl-protogen-glm.md), relay (tasks/impl-relay-glm.md), DNS (tasks/impl-dns-glm.md) and their fix PRs. Merge each one that passes.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Plan: PLAN.md and council/r3-merged.md. Reference: upstream/netbird (with vendor/).</workspace>
  <authority>Read anything. Detached worktrees under ~/.cache/netbird-zig-context/. Run tests and Go helpers locally. Post gh pr review N --comment with ДА or НЕТ; on ДА run scripts/merge-pr.sh N. Must not push code or edit repo files. Must not: commit on main, merge your own PR, install anything, ssh anywhere, use sudo/pkexec/root, touch the host network or other files.</authority>
  <context>Find GLM's PRs with gh pr list and the card names in PR bodies or branch names. CI green is not evidence until #40 is merged: run every *_test.zig the PR touches, natively and with -target aarch64-linux-musl -fno-emit-bin, and quote output in the review.</context>
  <steps>1. Review open GLM PRs in number order, fix PRs before the PR they fix. 2. Judge only against the author's card goal; other findings go to a Backlog section, never НЕТ. Two rounds max per PR. 3. Keep watching gh pr list for new GLM PRs until the three GLM cards are done.</steps>
  <rules>Real changes only, no empty commits, one PR per logical step. Review fixes follow AGENTS.md (a fix PR per finding into the reviewed branch). Load limits from AGENTS.md: before zig/go builds check /proc/loadavg and wait while the 1-min load is above 12; one heavy command at a time. Facts from commands you ran. If a step is impossible, write BLOCKED with the reason and continue with the next independent step.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/xreview-muse3.md: one-line result, files, PR URLs, commands with output, Not verified list, author model, a progress line after each step (never starting with STATUS:). Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
