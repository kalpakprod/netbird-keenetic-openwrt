$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>M3 (#6) first part: HTTP/2 client framing and HPACK in pure Zig, the base for gRPC.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first (PR rules, kernel 4.9 limits, load limits). Plan: PLAN.md (lead decisions) and council/r3-merged.md. Reference: upstream/netbird (with vendor/), Zig std at `mise where zig`/lib/std.</workspace>
  <authority>May create or change only: src/net/h2/**, src/net/testdata/**. PRs through scripts/pr.sh, one PR per logical step (split big work into several PRs, each with passing tests). Go helpers for vectors only under ~/.cache/netbird-zig-context/gen/. Must not: commit on main, install anything, ssh anywhere, touch other files.</authority>
  <steps>1. Read RFC 7540/7541 behaviour as implemented in vendor/golang.org/x/net/http2 (frame.go, hpack/*.go) and port: frame reader/writer (DATA, HEADERS, CONTINUATION, SETTINGS, PING, GOAWAY, RST_STREAM, WINDOW_UPDATE), HPACK encoder/decoder with static+dynamic table and Huffman. Header comment per AGENTS.md (golang.org/x/net is BSD-3-Clause). PR 1: HPACK with the RFC 7541 Appendix C examples as tests. PR 2: frame codec with tests from byte vectors produced by a Go helper using x/net/http2 Framer. 3. PR 3: client connection state (preface, settings ack, stream ids, flow control windows) with an in-memory test against a Go http2 server helper over a socketpair or localhost TCP (no TLS yet). Each PR body 'Part of #6'. 4. zig build test passes; build for aarch64-linux-musl; paste output.</steps>
  <rules>Real changes only, never empty or cosmetic commits. Before pushing to an existing branch: git fetch origin and base on origin/&lt;branch&gt;. Facts from files and commands you ran. If a step is impossible, write BLOCKED with the reason. Every "works" claim carries the command and its output.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/impl-h2-muse.md: one-line result, files, PR URLs, commands with output, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
