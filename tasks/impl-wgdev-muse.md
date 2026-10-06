$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>M4 (#7) first part: WireGuard device transport over UDP without TUN: peers, handshake driver, timers, keepalive, replay window, data encryption, interop with wireguard-go.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Plan: PLAN.md and council/r3-merged.md. Reference: upstream/netbird (with vendor/).</workspace>
  <authority>May create or change only: src/wg/**, src/wireguard/** (only to reuse noise.zig; changes there need their own PR). PRs through scripts/pr.sh, one PR per logical step, each with passing tests. Go helpers only under ~/.cache/netbird-zig-context/gen/. Must not: commit on main, install anything, ssh anywhere, use root or /dev/net/tun, touch other files.</authority>
  <steps>1. Read vendor/golang.zx2c4.com/wireguard/device/{device,peer,send,receive,timers,keypair,replay?}.go (check names with ls). 2. Port the device core with a pluggable packet source/sink instead of TUN, using src/wireguard/noise.zig. 3. Interop test: Go helper runs wireguard-go device with a channel-based tun.Device on 127.0.0.1; Zig device peers with it, handshake completes, an IP packet sent from each side arrives intact, keepalive and rekey timers fire (shortened timers allowed in test build). 4. PRs: timers+replay, device core, interop test; body 'Part of #7'.</steps>
  <rules>Real changes only. Before pushing to an existing branch: git fetch origin and base on origin/&lt;branch&gt;. Facts from commands you ran. If a step is impossible, write BLOCKED with the reason.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/impl-wgdev-muse.md: one-line result, files, PR URLs, commands with output, Not verified list, author model, progress lines. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
