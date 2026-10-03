$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>GitHub issues for milestones M1-M10 of the merged plan, so every PR links to its milestone.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first (PR rules changed: every change goes through scripts/pr.sh). Plan: PLAN.md and council/r3-merged.md. Reference: upstream/netbird (with vendor/), Zig std at `mise where zig`/lib/std.</workspace>
  <authority>May create or change only: GitHub issues of kalpakprod/netbird-keenetic-openwrt only (no files). May run gh for this repo (pr, issue, review). Must not: commit on main, push main, install anything, ssh anywhere, touch other files. Load limits from AGENTS.md apply.</authority>
  <steps>1. Read council/r3-merged.md §3 and PLAN.md lead decisions. 2. For each milestone create one issue: title 'M<n>: <scope>', body with scope, acceptance test, Go size reference and module dirs; command: gh issue create --repo kalpakprod/netbird-keenetic-openwrt --title ... --body ... 3. Create a label 'milestone' (gh label create) and apply it. 4. List the issue numbers in the report and append them to the same report as a table M<n> → #<issue>.</steps>
  <rules>Real changes only, never empty or cosmetic commits to inflate activity. Facts from files and commands you ran. If a step is impossible, write BLOCKED with the reason. Every "works" claim carries the command and its output.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/issues-muse.md: one-line result, files, PR/issue URLs, commands with output, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
