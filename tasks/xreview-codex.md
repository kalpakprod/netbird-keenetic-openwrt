$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Independent review (GPT family) of open PRs by Muse and GLM; post verdicts on GitHub and merge approved PRs, keeping the queue short.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Reference: upstream/netbird (with vendor/).</workspace>
  <authority>GitHub reviews and scripts/merge-pr.sh only. Temporary worktrees under ~/.cache/netbird-zig-context/. No file changes in the repo, no installs, no ssh.</authority>
  <steps>
    1. Review PRs #21 (HPACK), #22 (frame codec), #23 (h2 client connection) in this order; then any open PR that has no review yet and is not being reviewed by GLM (#3, #16, #17 are GLM's). Re-list open PRs with gh pr list after each merge.
    2. For each PR: git fetch origin; worktree of origin/&lt;branch&gt;; compare with the Go source it ports (vendor/golang.org/x/net/http2, hpack; RFC 7540/7541); check kernel-4.9 rules and license headers from AGENTS.md; run zig build test and the PR's own tests; paste output.
    3. gh pr review N --comment -b '&lt;ДА/НЕТ + findings file:line, why, fix&gt;'. On ДА run scripts/merge-pr.sh N (stacked PRs in order). On НЕТ leave it for the author; re-check after a fix, two rounds max, then write the open findings in the report.
  </steps>
  <rules>Judge against the PR goal and AGENTS.md; out-of-scope ideas go to a Backlog section in the report, never block a merge. Facts from commands you ran. If a step is impossible, write BLOCKED with the reason.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/xreview-codex.md: per PR verdict, findings, test output, merge result, progress lines. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
