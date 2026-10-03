$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Council round 1: an independent, evidence-based plan for porting the NetBird client (v0.79.0, Linux router) to Zig 0.17, written to council/r1-muse.md.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first, fully. Reference sources: upstream/netbird (with vendor/).</workspace>
  <authority>
    May create or change only: council/r1-muse.md.
    May run: go list / go test on upstream code, grep, wc, find, zig, qemu-aarch64-static. Read anything under the repo.
    Must not: commit, push, install anything, use the network beyond what is already vendored, ssh anywhere, edit other files.
  </authority>
  <context>
    Owner wants the whole client ported to Zig with no C code; size does not matter. Target router: aarch64, Linux 4.9 (see AGENTS.md for missing syscalls and the statx workaround).
    The router runs the client with userspace WireGuard (NB_WG_KERNEL_DISABLED=true), log level warning, against NetBird cloud.
  </context>
  <steps>
    1. Map the client runtime path from the entry point (upstream/netbird/client/main.go, cmd "service run" and "up"): login with setup key, management sync (gRPC), signal exchange, ICE/STUN/TURN, relay, WireGuard userspace + TUN, DNS, routes, firewall, state files. Cite file paths.
    2. List every protocol the client speaks on the wire (proto files, HTTP/2, gRPC, TLS, WebSocket/QUIC for relay, STUN) and what Zig 0.17 std already provides for each (check lib/std of `mise where zig`; cite file names). Do not read council/r1-glm.md or docs/inventory.md in this round.
    3. Propose the Zig module layout (directories and modules) and the port order as milestones. Each milestone must be testable on its own: name the Go reference tests or interop check that proves it.
    4. Name the risks with evidence: kernel 4.9 syscalls, memory, gaps in Zig std, parts that need a local upstream stack for testing.
    5. Estimate the size of each milestone in Go lines being ported (measured with wc on the listed files).
  </steps>
  <rules>Facts only from files and commands you ran; mark guesses as guesses. Do not write Zig code in this round. If a step is impossible, write BLOCKED with the reason.</rules>
  <verification>Every number in the report has the command that produced it next to it.</verification>
  <stop_conditions>Upstream sources missing, a needed write outside the allowed files, load limits from AGENTS.md.</stop_conditions>
  <deliverable>
    council/r1-muse.md with sections: runtime path, protocols and std coverage, module layout, milestones with tests and sizes, risks, open questions.
    Report /home/kukuruza/.cache/netbird-zig-context/results/r1-muse.md: one-line result, files written, commands run, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.
  </deliverable>
</task>
```
