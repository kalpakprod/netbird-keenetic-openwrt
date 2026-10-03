# Council round 2 — Muse on GLM (`council/r1-glm.md`)

Reviewer: Muse Spark. Method: re-checked GLM's cited lines and numbers against
`upstream/netbird` (+vendor) and Zig 0.17.0 std with the commands quoted below.
GLM's `STATUS: DONE` in `results/r1-glm.md:33` arrived after ~50 min of 2-minute polling.

## 1. Agreements (verified with evidence)

- Runtime path `main.go → cmd → daemon/server → ConnectClient.run → engine.Start`: confirmed.
  `createEngineConfig` is exactly `client/internal/connect.go:625`, `loginToManagement` exactly `:734`
  (`grep -n "^func loginToManagement"`), `Engine.Start` is `engine.go:544`, `Conn.open` is
  `peer/conn.go:230`, `NewTunDevice` is `device_usp_unix.go:33`, signal `NewClient` is
  `shared/signal/client/grpc.go:105`, `encrypt/decryptMessage` are `:434/:414` — all line cites check out.
- Wire numbers: 736 non-std packages — reproduced exactly
  (`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go list -mod=vendor -deps … ./client | wc -l` → `736`).
  Spot-checks match: `protowire/wire.go` 571, `shared/management/proto` 14778, signal client/proto 881/837,
  relay messages 399, `dns/` 340, `client/proto` 13006, `go-nat` 2477, `google/nftables` 9024, `wgtypes` 288
  (all via `find … -name '*.go' ! -name '*_test.go' | xargs wc -l`).
- GLM's GOOS-filtered counting (only linux/arm64-compiled files) is more target-precise than my r1
  whole-dir counts. Examples: his `encryption` 245 is right (my 387 wrongly included `testprotos/`);
  his mgmt-client 1250 = `client.go`(37)+`grpc.go`(1075)+`mock.go`(138), correctly excluding the admin
  `rest/` API client (~4k lines, not on the router path). I adopt his method for merged milestones.
- Std gaps table: agree on all rows — no protobuf/gRPC/H2/QUIC/WS/ICE/STUN/TURN/DNS/TUN/netlink in std
  (my r1 greps confirm), WG crypto primitives present (`x25519.zig`, `chacha20.zig`, `blake2.zig`, `hkdf.zig`).
- Relay transports (QUIC + WS race, `coder/websocket`, `quic-go`), HMAC auth, relay message framing: agree.
- Risks: kernel-4.9 syscall set, memory baseline, need for a lead-provided local stack, nftables-vs-iptables
  unknown on Keenetic: agree.
- Good catches GLM made that my r1 missed: NAT portforward via `netbirdio/go-nat`
  (confirmed: `client/internal/portforward/manager.go:13` imports it); eBPF proxy question
  (`client/iface/wgproxy/ebpf/` exists); daemon-vs-foreground question (foreground-only would defer the
  13006-line daemon proto); gVisor exclusion as an explicit decision.

## 2. Disagreements with evidence

1. **uspfilter-first firewall contradicts the no-gVisor decision.** GLM proposes starting M9 with
   `uspfilter` while excluding gVisor (95k lines). But `client/firewall/uspfilter/forwarder/` imports
   gVisor directly:
   `endpoint.go:9-11` (`gvisor.dev/gvisor/pkg/tcpip`, `/header`, `/stack`), `forwarder.go:16` (`/pkg/buffer`)
   (`grep -rn gvisor client/firewall/uspfilter/`). Either M9 ports a `tcpip` subset too (unmeasured —
   bigger than it looks), or "uspfilter-first" means only `filter.go`/`nat.go`/`conntrack/` without the
   forwarder (unproven split). My r1 said nftables-first; I still hold that for the router (kernel 4.9
   has nftables), with the forwarder question returned to the lead.
2. **TURN version is misstated.** GLM's table says `pion/turn/v4 (5 960)`. The v4 number is real
   (`find vendor/github.com/pion/turn/v4 …` → 5960) but v4 reaches the client only indirectly, through
   the ICE fork (`vendor/github.com/pion/ice/v4/gather.go` imports `pion/turn/v4`); the only direct
   client-code importer uses v3 (`client/internal/relay/relay.go:14`, v3 = 5350 lines, `go.mod:101`
   direct vs `:303` `v4 // indirect`). The port needs the TURN *protocol*, but milestone sizing and
   API refs should name both, not v4 alone.
3. **WG-first milestone order (M3 before networking) retires the wrong risk first.** GLM's M3/M4 prove a
   local WG tunnel early, but the largest unknowns — hand-rolled H2/gRPC interop with real servers and
   the TLS ALPN gap (see §4) — slip to M5. A local ping cannot fail on those. I argue for a networking
   spike (TLS+ALPN+H2 against a real-Go server) inside the first milestones, before or beside WG device work.
4. **Minor factual errors:** the UAPI configurator is `client/iface/configurer/uapi.go` (`openUAPI`, `:11`),
   not `configurer/usp.go` (no such file — `ls` shows `common.go, err.go, kernel_unix.go, name*.go,
   stats_cache.go, uapi*.go`). `statemanager`'s `(state.json)` filename is not confirmed —
   `grep -rn "state.json" client/internal/statemanager/ client/internal/profilemanager/` is empty
   (only "state file" error strings at `manager.go:25,189,217`).
5. **Count deltas to reconcile (method, not error):** uspfilter 3959 (GLM) vs 7757 (all-files `wc`);
   `internal/dns` 6413 vs 10350; `server` 5379 vs 5475; `cmd` 7242 vs 8386; relay client 2488 vs 3274;
   ICE fork 9315 vs 9585; WG device+conn 7743 vs 7544 (5315+2229); STUN 3636 vs 7415. All consistent with
   GOOS-filtered vs whole-dir counting; merged milestones below use GLM's filtered numbers where verified.

## 3. Missing items (in GLM's proposal)

- Kernel 4.9 vs Zig's `Io` backend: `lib/std/Io/` ships `Uring.zig` and `Threaded.zig`; if the default
  backend emits io_uring syscalls, all socket I/O fails on 4.9. Needs a qemu-strace gate per build
  (my r1 §4.1). GLM covers statx but not this.
- Mgmt/signal messages are NaCl-boxed (`encryption/encryption.go:18` `Encrypt`) — GLM names the package
  but no milestone owns the box interop vector (fold into M2 below).
- No mention of SSH server, auto-updater, OIDC/SSO, flow exporter as explicitly deferred (my r1 deferred
  them with sizes: 8600/3509/2141/2691). For "port everything" scope these need a parked list, not silence.
- `wsproxy` (mgmt/signal dial path, `util/wsproxy`) correctly ignorable on Linux (JS transport) — worth one
  line so nobody ports it.

## 4. New evidence found during this review

- **std TLS client has no ALPN**: `grep -c -i alpn lib/std/crypto/tls/Client.zig` → `0`. gRPC-over-TLS
  normally negotiates `h2` via ALPN, so the std client needs an ALPN extension (or cleartext h2c where the
  server allows it) before any cloud interop. This upgrades GLM's open question №1 from "check" to "planned work".
- TLS 1.3 is supported (`Client.zig:357` asserts `tls_1_3`), `supported_versions` extension is sent (`:213`).

## 5. Merged proposal for milestones 1–3

Adopt GLM's structure (M1/M2 numbering) and GOOS-filtered sizing, with my reorder (networking risk first):

- **M1 — proto wire + mgmt/signal codecs + NaCl box.** Scope: `protowire` behaviour (571-line ref),
  codecs for `management.proto`/`signalexchange.proto` messages on the login/sync path only,
  `encryption` (245) box interop. Test: byte-exact vectors generated by a Go helper against
  `shared/management/client/grpc_test.go` and `shared/signal/client/client_suite_test.go` fixtures;
  `zig test`. Size ref: 571 + 245 + message-subset of 14778+837.
- **M2 — TLS(+ALPN)+H2+gRPC-minimum, proven against real Go servers.** Scope: std TLS client + hand-added
  ALPN, minimal H2 client (settings, headers, data, trailers, flow control), gRPC unary + server-streaming.
  Test: `Login` + `Sync` against upstream management and `ConnectStream` against upstream signal built from
  `upstream/` (lead stack or `go run` locally); then a TLS-handshake-only probe against netbird.cloud
  endpoints to confirm ALPN/TLS-1.3 acceptance (no account needed). This is the spike GLM's order postpones.
- **M3 — WG device + TUN + local tunnel.** GLM's M3+M4 merged: Noise IK handshake, transport, replay,
  timers from the wireguard-go fork's `device`+`conn` (7544-line ref), `/dev/net/tun` wrapper, UAPI
  configurator (`configurer/uapi.go`). Test: handshake + ping zig↔wireguard-go over UDP, then over TUN.
  Deferred out of M3: `udpmux`, `wgproxy` (needed only when ICE/relay binds arrive in later milestones).

Later milestones keep GLM's M5→M10 shape with two amendments: relay-WS before ICE (agree with GLM's
reasoning — simpler channel first for debugging), and firewall decided by the lead's Keenetic answer
(nftables-first unless the firmware lacks it; uspfilter only with an explicit gVisor-tcpip scope ruling).
Foreground-only CLI first; daemon IPC (`client/proto`, 13006) after engine e2e, per GLM's question №6.
