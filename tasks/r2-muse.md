$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Council round 2: review the other agent's porting proposal and write council/r2-muse-on-glm.md.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Reference: upstream/netbird (with vendor/), Zig std at `mise where zig`/lib/std.</workspace>
  <authority>May create or change only: council/r2-muse-on-glm.md. Must not: commit, push, install anything, ssh anywhere, touch other files. Load limits from AGENTS.md apply.</authority>
  <steps>1. Wait until /home/kukuruza/.cache/netbird-zig-context/results/r1-glm.md has a STATUS line (check every 2 minutes: sleep 120). If it is BLOCKED or still missing after 60 minutes, write BLOCKED. 2. Read council/r1-glm.md fully and check its key claims against upstream files (cite paths). 3. Write: agreements, disagreements with evidence, missing items, your merged proposal for milestones 1-3.</steps>
  <rules>Facts from files and commands you ran; guesses marked as guesses. If a step is impossible, write BLOCKED with the reason. Every "works" claim carries the command and its output.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/r2-muse.md: one-line result, files written, commands with output, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
