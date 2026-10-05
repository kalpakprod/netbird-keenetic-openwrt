$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>M5 (#8) first part: NetBird relay protocol messages, WebSocket client, relay client connect and traffic, tested against the upstream relay server running locally.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Plan: PLAN.md (lead decision 1: WebSocket relay first, QUIC at M10) and council/r3-merged.md. Reference: upstream/netbird (with vendor/).</workspace>
  <authority>May create src/relay/** and src/net/ws/**. Go helpers and the local relay server binary only under ~/.cache/netbird-zig-context/gen/ (go build -p 4, nice -n 19, localhost only, stopped after the test). PRs through scripts/pr.sh, one PR per logical step, each with passing tests, body 'Part of #8'. Must not: commit on main, merge your own PR, install anything, ssh anywhere, use root, touch other files.</authority>
  <context>Upstream: shared/relay/messages/ (wire format), shared/relay/client/ (client.go, conn.go, manager), shared/relay/client/dialer/ws/ (WebSocket dialer), shared/relay/auth/ (token), relay/ (server, main.go). TLS: Zig std.crypto.tls client; on kernel 4.9 use the statx workaround from AGENTS.md when loading CA files.</context>
  <steps>
    1. Port shared/relay/messages with byte vectors from a Go helper (every message type, round-trip both ways). PR.
    2. src/net/ws/: RFC 6455 client (handshake, masking, fragmentation, ping/pong, close), plain and TLS. Test against a Go WebSocket server from vendor/ (the one the relay uses). PR.
    3. Relay client: auth token, connect, open a peer connection, send and receive. Test: build the upstream relay server, run it on 127.0.0.1, two Zig clients exchange data through it; and one Zig client with one Go relay client. PR.
  </steps>
  <rules>Real changes only, no empty commits. Before pushing to an existing branch: git fetch origin and base on origin/&lt;branch&gt;. Load limits from AGENTS.md. Facts from commands you ran. If a step is impossible, write BLOCKED with the reason.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/impl-relay-glm.md: one-line result, files, PR URLs, commands with output, Not verified list, author model, a progress line after each step (never starting with STATUS:). Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
