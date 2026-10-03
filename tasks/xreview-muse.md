$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Review GLM's protobuf wire runtime (src/proto/wire*.zig) against protowire; write council/review-muse-on-proto.md.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Reference: upstream/netbird (with vendor/), Zig std at `mise where zig`/lib/std.</workspace>
  <authority>May create or change only: council/review-muse-on-proto.md. Must not: commit, push, install anything, ssh anywhere, touch other files. Load limits from AGENTS.md apply.</authority>
  <steps>1. Wait until /home/kukuruza/.cache/netbird-zig-context/results/impl-proto-glm.md has a STATUS line (sleep 120, 90 min max, then BLOCKED). 2. Compare with vendor/google.golang.org/protobuf/encoding/protowire/wire.go: overflow rules, max lengths, error cases. 3. Run zig test src/proto/wire_test.zig and paste output. 4. Verdict ДА/НЕТ with findings (file:line, why, fix).</steps>
  <rules>Facts from files and commands you ran; guesses marked as guesses. If a step is impossible, write BLOCKED with the reason. Every "works" claim carries the command and its output.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/xreview-muse.md: one-line result, files written, commands with output, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
