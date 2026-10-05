$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>M6 (#9) first part: STUN client, ICE agent subset NetBird uses, TURN allocate and channels, so two peers find each other directly or through TURN.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Plan: PLAN.md and council/r3-merged.md. Reference: upstream/netbird (with vendor/).</workspace>
  <authority>May create src/ice/** only. Go helpers and local STUN/TURN servers (from vendor/github.com/pion) only under ~/.cache/netbird-zig-context/gen/, localhost or unshare -Urn namespaces, stopped after the test. PRs through scripts/pr.sh, body 'Part of #9'. Must not: commit on main, merge your own PR, install anything, ssh anywhere, use sudo/pkexec/root, touch the host network or other files.</authority>
  <context>Upstream: client/internal/peer/ice/ (agent.go, config.go, StunTurn.go), client/internal/peer/worker_ice.go, client/internal/stdnet/, vendor/github.com/pion/{stun,ice,turn,transport}. Port only what NetBird calls (one API major per protocol, council §5.2). UDP only first; TCP candidates later. Kernel 4.9 syscall list in AGENTS.md.</context>
  <steps>1. STUN message codec + binding client, byte vectors from pion/stun both ways. PR. 2. ICE candidate gathering (host, srflx) and connectivity checks for the NetBird config; test: Zig agent vs pion/ice agent in two namespaces reach Connected. PR. 3. TURN client allocate, permissions, channel bind, send through relay; test against pion/turn server on localhost. PR.</steps>
  <rules>Real changes only, no empty commits, one PR per logical step. Review fixes follow AGENTS.md (a fix PR per finding into the reviewed branch). Load limits from AGENTS.md: before zig/go builds check /proc/loadavg and wait while the 1-min load is above 12; one heavy command at a time. Facts from commands you ran. If a step is impossible, write BLOCKED with the reason and continue with the next independent step.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/impl-ice-muse.md: one-line result, files, PR URLs, commands with output, Not verified list, author model, a progress line after each step (never starting with STATUS:). Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
