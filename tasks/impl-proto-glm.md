$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Protobuf wire-format runtime in pure Zig: src/proto/wire.zig (varint, zigzag, fixed32/64, length-delimited, tag/field skipping, encoder and decoder over slices) with tests.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Reference: upstream/netbird (with vendor/), Zig std at `mise where zig`/lib/std.</workspace>
  <authority>May create or change only: src/proto/wire.zig, src/proto/wire_test.zig, build.zig (create only if missing; only a test step for src/proto). Must not: commit, push, install anything, ssh anywhere, touch other files. Load limits from AGENTS.md apply.</authority>
  <steps>1. Read the protobuf wire format used by upstream/netbird/vendor/google.golang.org/protobuf/encoding/protowire/wire.go and port its semantics. 2. Write src/proto/wire.zig with doc comment '// Port of google.golang.org/protobuf/encoding/protowire (BSD-3-Clause)'. 3. Tests: round-trip of every wire type, max varint, truncated input errors, unknown field skip; include byte vectors produced by Go: write a tiny Go program under ~/.cache/netbird-zig-context/gen/ (not in repo) using protowire to print the vectors. 4. Run: zig test src/proto/wire_test.zig (or zig build test) and paste output. 5. Build for aarch64-linux-musl once to prove it compiles for the router.</steps>
  <rules>Facts from files and commands you ran; guesses marked as guesses. If a step is impossible, write BLOCKED with the reason. Every "works" claim carries the command and its output.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/impl-proto-glm.md: one-line result, files written, commands with output, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
