$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Review Muse's WireGuard device PRs #27, #37, #38 and, when they appear, Muse's PRs from tasks/impl-tun-muse.md (test discovery in build.zig, src/tun, src/routes, WG over TUN). Merge each one that passes.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Reference: upstream/netbird (with vendor/).</workspace>
  <authority>Read anything in the repo. Detached worktrees under ~/.cache/netbird-zig-context/. Run zig test and Go helpers locally (load limits from AGENTS.md). Post `gh pr review N --comment` with a verdict ДА or НЕТ. On ДА run scripts/merge-pr.sh N. Must not: push code to any branch, edit files in the repo, install anything, ssh anywhere, use root.</authority>
  <steps>
    1. For each PR in order 27, 37, 38: worktree on its branch, compare with the upstream Go source named in the file headers, run its tests, check that tests prove the claim (no assertion that passes trivially). Verdict comment.
    2. Judge only against the card goal of the author's card (tasks/impl-wgdev-muse.md, tasks/impl-tun-muse.md). Findings outside it go to a Backlog section of your report, never set НЕТ.
    3. At most two review rounds per PR. After a second НЕТ, stop on that PR and write it in the report.
    4. Then watch `gh pr list` for Muse's impl-tun PRs and review them the same way.
  </steps>
  <rules>Facts from commands you ran. Progress line after each PR (never starting with STATUS:).</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/xreview-codex2.md: per PR verdict, commands with output, Backlog, Not verified. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
