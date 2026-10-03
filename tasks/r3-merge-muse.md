$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Draft the merged porting plan from both council rounds into council/r3-merged.md for the lead.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Reference: upstream/netbird (with vendor/), Zig std at `mise where zig`/lib/std.</workspace>
  <authority>May create or change only: council/r3-merged.md. Must not: commit, push, install anything, ssh anywhere, touch other files. Load limits from AGENTS.md apply.</authority>
  <steps>1. Wait until /home/kukuruza/.cache/netbird-zig-context/results/r2-glm.md has a STATUS line (sleep 120 between checks, 60 min max, then BLOCKED). 2. Read council/r1-*.md and council/r2-*.md. 3. Write one plan: module layout, milestones in order with tests and sizes, open disagreements listed with both sides. Do not edit PLAN.md.</steps>
  <rules>Facts from files and commands you ran; guesses marked as guesses. If a step is impossible, write BLOCKED with the reason. Every "works" claim carries the command and its output.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/r3-merge-muse.md: one-line result, files written, commands with output, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
