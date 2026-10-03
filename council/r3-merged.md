# Merged porting plan — NetBird client v0.79.0 → Zig 0.17 (council r1+r2)

Draft for the lead. Merges `council/r1-muse.md`, `council/r1-glm.md` (as corrected by GLM in r2:
encryption = NaCl box), `council/r2-muse-on-glm.md`, `council/r2-glm-on-muse.md`.
Both agents verified each other's line cites (12/12 Muse cites confirmed by GLM; ~25 GLM cites
re-checked by Muse).-agents agree on scope, risks and test-per-milestone; remaining disagreements
are listed in §5 with both sides. Numbers carry their method: **build** = `go list .GoFiles`
(linux/arm64-compiled files, GLM's method) or **find** = all non-test `*.go` under a dir (Muse's method).

## 1. Agreed facts

- Entry `client/main.go → cmd.Execute()`; daemon gRPC on `unix:///var/run/netbird.sock`
  (`client/cmd/root.go:151`) + foreground `up -F`; `Server.Up` (`client/server/server.go:989`) →
  `ConnectClient.run` (`client/internal/connect.go:174`) → `loginToManagement` (`:734`) →
  `createEngineConfig` (`:625`) → `Engine.Start` (`engine.go:544`).
- `NB_WG_KERNEL_DISABLED=true` forces userspace WG (`client/iface/device/kernel_module_linux.go:89`).
- Mgmt/signal payloads are NaCl-boxed: `encryption/encryption.go` imports `nacl/box`,
  `Encrypt = box.Seal` (`:18`); comment names Curve25519/XSalsa20/Poly1305.
- Zig 0.17 std HAS: TCP/UDP (`Io/net.zig`), TLS 1.3 client (`crypto/tls/Client.zig`, no ALPN —
  `grep -c -i alpn` → 0), HTTP/1.1 (`http/Client.zig`), X25519/Blake2s/HKDF/ChaCha20Poly1305/
  XSalsa20Poly1305 (`crypto.zig` re-exports), JSON.
- Std LACKS: protobuf, gRPC/HTTP-2, QUIC, WebSocket, ICE/STUN/TURN, DNS codec, TUN ioctls,
  netlink/nftables constants (all confirmed by empty `find`/`grep` over `lib/std`).
- Std risk: `Io/` ships `Uring.zig` and `Threaded.zig` — default backend may emit io_uring
  syscalls missing on kernel 4.9; plus known statx issue (`File.stat`/`Reader.getSize`).
- Dependency pins that matter: netbirdio wireguard-go fork and netbirdio ICE fork (`go.mod`
  replace directives), `quic-go v0.62.0`, TURN v3 direct + v4 via the ICE fork, `miekg/dns`,
  `coder/websocket`, `vishvananda/netlink`, `google/nftables`, `coreos/go-iptables`,
  `netbirdio/go-nat` (portforward), gVisor `tcpip` (uspfilter forwarder).

## 2. Module layout (`src/`, one Zig module per dir, `zig test` beside each)

Agreed (Muse's 16-module layout, no structural objection from GLM):

```text
src/proto/   protobuf wire + hand codecs for mgmt/signal/daemon/flow messages
src/crypto/  X25519 keys, NaCl-box Encrypt/Decrypt, WG primitives glue
src/state/   profilemanager + statemanager JSON (config.json, state files)
src/net/     TLS(+ALPN)+HTTP/2+gRPC-minimum client, WebSocket client
src/mgmt/    ManagementService client: Login/Sync/Job (behavior ref: shared/management/client)
src/signal/  SignalExchange client + peer/Signaler logic
src/wg/      WireGuard device: Noise IK, transport, replay, timers, cookie
src/tun/     /dev/net/tun wrapper
src/iface/   udpmux, wgproxy/udp forwarder, UAPI configurator (configurer/uapi.go)
src/relay/   relay messages + manager + WS dialer, then QUIC dialer
src/ice/     ICE agent + STUN binding + TURN allocate/channels + NAT portforward
src/dns/     DNS codec + local resolver + unix OS-config backends + dnsfwd/interceptor
src/routes/  netlink routes + sysctl + forwarding (routemanager subset)
src/fw/      firewall manager + ONE first backend (lead decides, §5.1)
src/engine/  Engine + ConnectClient + connMgr + monitors
src/daemon/  DaemonService server + CLI (foreground subset first, full IPC later)
```

Build: `zig build-exe -target aarch64-linux-musl`, no C, no `-lc`.

## 3. Milestones in order (each independently testable)

| # | Scope | Test / acceptance | Size ref (Go, non-test) |
|---|---|---|---|
| M1 | proto wire + codecs for login/sync-path messages (Login/LoginResponse/SyncResponse/NetworkMap, signal EncryptedMessage) | byte vectors from a Go helper (round-trip all wire types, max varint, truncation, skip-unknown) + decode of a real SyncResponse captured from Go; `zig test` | protowire 571 (build); generated ≤25634 (find, upper bound, not ported 1:1) |
| M2 | crypto + state: NaCl box interop, X25519 keys, profile/state JSON round-trip | box vectors from Go both directions; decrypt a Go-encrypted message; JSON round-trip | encryption 245 (build) / 387 (find); wgtypes 288; profilemanager 2604 + statemanager 539 (find; build_unrefined — guess close) |
| M3 | TLS(+hand-added ALPN)+H2+gRPC-minimum; mgmt Login+Sync, signal ConnectStream | fake Go ManagementService/Signal replay; then local upstream stack; TLS-probe vs netbird.cloud (handshake only, no account); qemu-strace on 4.9 (no io_uring/statx); RSS measured vs ~44 MB free / Go 24.1 MB | mgmt client 1250 (build: client.go 37 + grpc.go 1075 + mock.go 138); signal client 881 + proto 837; grpc-go 36678 NOT ported |
| M4 | WG device + TUN + local tunnel (Noise IK, transport, replay, timers, UAPI) | handshake + ping zig↔wireguard-go over UDP, then over TUN; noise vectors | device+conn 7544 (find) / 7743 (GLM build-figure); iface-subset of 8967 |
| M5 | relay messages + manager + WS dialer; wgproxy/udp forwarder | local `relay/` server: connect + traffic through relay; routed traffic via forwarder (AGENTS.md:210-214: routed/exit traffic goes through the userspace forwarder) | relay client 2488 (build) / 3274 (find); messages 399; wgproxy/udp 430 |
| M6 | ICE/STUN/TURN + NAT portforward | two clients via local STUN stub exchange candidates; direct P2P ping; TURN allocate relay ping | peer 6090 (find); ice fork 9315 (build) / 9585 (find); stun v3 + turn (ONE API major per protocol — §5.2); go-nat 2477; upnp via netbirdio/go-nat |
| M7 | DNS + routes + firewall-first-backend | netns: `dig` to our resolver, `ip route` applied, `nft list`/filter check | dns 6413 (build) / 10350 (find) + dns/ 340; routes ~8384-8684; fw backend per lead decision |
| M8 | engine + foreground CLI e2e (up/login/down/status, setup-key only) | full `up` vs local mgmt+signal+relay stack, then lead-provided upstream stack | engine-core 3926 + server-subset + cmd-subset (find upper bounds: server 5475/5379, cmd 8386/7242) |
| M9 | daemon IPC + privilege boundary (SO_PEERCRED via `ipcauth/`) + remaining CLI | CLI↔daemon over unix socket; cred check rejects foreign user | client/proto 13006 (generated); ipcauth dir |
| M10 | QUIC relay dialer + H2 hardening + full CLI parity | M5/M8 suites with `NB_RELAY_TRANSPORT=quic` | quic-go 27864-28287 (subset, guess small fraction) |

Deferred (parked, not forgotten): SSO/OIDC (`auth/` 2141), SSH server (5851 build / 8600 find),
updater (1009 / 3509), Rosenpass (582 + cunicu 2620-2688), flow/netflow (1305+1386), lazyconn (1466),
eBPF proxy (`wgproxy/ebpf`, kernel 4.9 — likely N/A), gVisor netstack (95029 — excluded unless §5.1
forces it), Prometheus/AWS branches, proxy-service protos, mobile/Windows/macOS files.

## 4. Port rules (agreed)

1. File I/O: never `File.stat`/`Reader.getSize` — use `lseek(SEEK.END)` (AGENTS.md workaround);
   every new file op gets a 4.9 strace check.
2. Sockets: pin the `Io` backend that emits no post-4.9 syscalls (Threaded or raw posix);
   qemu-strace gate on every networked milestone's build.
3. Sizes in future cards state the method (build vs find).
4. Memory: RSS measured in qemu-aarch64 at M3 and M8 against the Go baseline (24.1 MB RSS, 53.6 peak).
5. No `wsproxy` port (JS-only transport), no `rest/` admin client in M3 (server-side API surface).

## 5. Open disagreements (both sides, for the lead)

1. **First firewall backend.** Muse: nftables-first — kernel 4.9 ships nftables, and uspfilter's
   `forwarder/` imports gVisor `tcpip`/`stack`/`buffer` (`endpoint.go:9-11`, `forwarder.go:16`), so
   "uspfilter-first" silently re-opens the 95k-line gVisor question. GLM: uspfilter-first as the simpler
   userspace start (3959 build-lines), nftables later; gVisor split (`filter.go`/`nat.go`/`conntrack/`
   without `forwarder/`) unproven either way. Common ground: need the Keenetic firmware answer first.
2. **TURN API major.** GLM: port one major per protocol — turn v4 (5960). Muse: both majors compile
   into the client (v3 direct from `client/internal/relay/relay.go:14`, v4 via `pion/ice/v4/gather.go`);
   size the port as "TURN protocol once" and keep both call sites compiling. Effect: same code, different
   accounting; no milestone impact.
3. **WG placement nuance (nearly converged).** GLM's r2 M1–M3 (proto/crypto/grpc) effectively accepts
   Muse's networking-spike-first order; table above puts WG device at M4. No action unless the lead
   wants an even earlier local-tunnel demo.

## 6. Lead decisions needed (not council scope)

1. QUIC required for relay, or is WS enough long-term?
2. Daemon on the router, or foreground-only (saves the 13006-line daemon proto + ipcauth work)?
3. Firewall backend available on the KN-3812 firmware (nftables vs iptables-legacy)?
4. Hand-written protobuf codecs (drift risk, byte-vector-tested) or a small `protoc` plugin?
5. Local upstream stack (management+signal+relay) for M3–M8 interop — provided, or stubs only?
6. Go toolchain (go1.27.1 present) approved for building stubs/vectors/helpers?
