$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>M3 (#6): TLS with ALPN h2, gRPC-minimum over our HTTP/2, then the NetBird Management client (GetServerKey, Login, Sync stream) and the Signal client (ConnectStream, Send), each tested against Go servers on localhost.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Plan: PLAN.md and council/r3-merged.md (M3 row). Reference: upstream/netbird (with vendor/).</workspace>
  <authority>May create src/net/tls/**, src/net/grpc/**, src/mgmt/**, src/signal/**. Go helpers and fake servers only under ~/.cache/netbird-zig-context/gen/ (go build -p 4, nice -n 19, localhost only, stopped after tests). One outbound TLS handshake probe to a public NetBird endpoint is allowed (handshake only, no login, no account). PRs through scripts/pr.sh, body 'Part of #6'. Must not: commit on main, merge your own PR, install anything, ssh anywhere, use root, touch other files.</authority>
  <context>
    Zig 0.17 std.crypto.tls.Client has no ALPN (grep of lib/std/crypto/tls/Client.zig finds none). gRPC over h2 requires ALPN "h2". Options: wrap or vendor the std client into src/net/tls with ALPN added (keep the Zig MIT notice in the file header) — pick the smallest that works and say why in the PR.
    HTTP/2: src/net/h2 frame.zig and hpack.zig are on main (#21, #22); the connection (#23, branch feat/h2-conn) is still in review. If #23 is not merged when you need it, open your gRPC PR stacked on it (BASE=feat/h2-conn) and say so in the body.
    Upstream: shared/management/client/grpc.go and client.go, shared/signal/client/grpc.go, client.go and worker.go, shared/management/proto, shared/signal/proto, encryption/ (Login and signal bodies are NaCl-box encrypted: src/crypto on main). grpc-go is NOT ported (council): implement only what these clients call.
    Kernel 4.9: no syscalls newer than 4.9 (list in AGENTS.md); CA loading uses the statx workaround in AGENTS.md.
  </context>
  <steps>
    1. TLS+ALPN: test against a Go tls server with NextProtos ["h2"] on localhost (negotiated protocol must be h2), plus one handshake probe to the public endpoint. PR.
    2. gRPC-minimum: length-prefixed messages, content-type, te: trailers, grpc-status/grpc-message trailers, deadlines, unary and server-streaming and bidi streams over src/net/h2. Test against a Go grpc server built from vendor/ (echo service). PR.
    3. Management client: GetServerKey, Login with setup key (encrypted body), Sync stream receiving a NetworkMap. Test against a fake Go ManagementService on localhost that returns a canned SyncResponse; decode it with src/proto. PR.
    4. Signal client: ConnectStream and Send with encrypted bodies; two Zig clients exchange a message through a Go signal server (upstream signal/ built locally). PR.
  </steps>
  <rules>Real changes only, no empty commits, one PR per logical step. Review fixes follow AGENTS.md (a fix PR per finding into the reviewed branch). Load limits from AGENTS.md: before zig/go builds check /proc/loadavg and wait while the 1-min load is above 12; one heavy command at a time. Facts from commands you ran. If a step is impossible, write BLOCKED with the reason and continue with the next independent step.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/impl-grpc-muse.md: one-line result, files, PR URLs, commands with output, Not verified list, author model, a progress line after each step (never starting with STATUS:). Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
