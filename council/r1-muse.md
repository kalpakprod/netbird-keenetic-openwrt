# Council round 1 — Muse: porting the NetBird client (v0.79.0) to Zig 0.17

Independent proposal. Sources: `upstream/netbird` (v0.79.0 + vendor/) and Zig 0.17.0 std at
`/home/kukuruza/.local/share/mise/installs/zig/0.17.0/lib/std`. Did not read `council/r1-glm.md` or `docs/inventory.md`.
Every number below comes from the command printed next to it. Guesses are marked "guess".

## 1. Runtime path (Linux router, `service run` / `up`, userspace WireGuard)

Entry: `client/main.go` → `cmd.Execute()` (`client/cmd/root.go:110`) → cobra tree (`client/cmd/root.go:170`,
`service.go:53`). Two processes cooperate:

- Daemon (`netbird service run`, `client/cmd/service.go`): hosts `server.Server` (`client/server/server.go:70`)
  behind gRPC `DaemonService` (`client/proto/daemon.proto:13`, ~40 RPCs) on `unix:///var/run/netbird.sock`
  (`client/cmd/root.go:151`).
- CLI (`up`, `login`, `status`, …): dials the daemon over that socket (`client/cmd/root.go:278`
  `DialClientGRPCServer`).

Router flow with setup key (`NB_SETUP_KEY`), log level warning, `NB_WG_KERNEL_DISABLED=true`:

1. `up` → daemon `Server.Up` (`client/server/server.go:989`) → `connectWithRetryRuns` (`:343`) →
   `ConnectClient.run` (`client/internal/connect.go:174`).
2. Login: `mgmt.GrpcClient.Login` (`shared/management/client/grpc.go:128` `NewClient`, `client.go`) against
   `ManagementService.Login` (`shared/management/proto/management.proto:14`). Setup key + WireGuard public key
   sent inside `EncryptedMessage` (NaCl box, `encryption/encryption.go:18` `Encrypt`).
3. Sync stream: `ManagementService.Sync` (server-streaming, `management.proto:20`) handled by
   `handleSyncStream` (`shared/management/client/grpc.go:427`) → `Engine.handleSync` (`client/internal/engine.go:1006`)
   → `Engine.Start` (`engine.go:544`): creates WG interface (`newWgIface`, `:2197`), firewall, DNS, route manager.
4. Signal: `shared/signal/client` (`NewClient`, `grpc.go:105`) opens `SignalExchange.ConnectStream`
   (bidi stream, `shared/signal/proto/signalexchange.proto:13`); `peer.Signaler` (`client/internal/peer/signaler.go`)
   exchanges SDP offers/answers and ICE candidates.
5. ICE: `peer/worker_ice.go` drives pion/ice v4 (netbirdio fork, `go.mod:360`) with STUN (`updateSTUNs`,
   `engine.go:1525`) and TURN (`updateTURNs`, `:1543`) servers from the sync; UDP mux in `client/iface/bind/`.
6. Relay fallback: `shared/relay/client` (`Client`, `manager.go`) dials relay servers over QUIC and/or WebSocket
   (`dialer/quic`, `dialer/ws`, `dialer/race_dialer.go`; `github.com/coder/websocket`, `github.com/quic-go/quic-go`),
   framing with `shared/relay/messages/message.go` (`MarshalTransportMsg` etc.). Used by `peer/worker_relay.go`.
7. WireGuard userspace: `NB_WG_KERNEL_DISABLED=true` forces userspace (`client/iface/device/kernel_module_linux.go:89`);
   device from the netbirdio wireguard-go fork (`go.mod:356`, vendored under `golang.zx2c4.com/wireguard`),
   TUN via `golang.zx2c4.com/wireguard/tun`, custom binds (`client/iface/bind/ice_bind.go`, `relay_bind.go`).
8. DNS: local resolver + OS config (`client/internal/dns/`: `file_unix.go`, `network_manager_unix.go`,
   `resolvconf_unix.go`, `host_unix.go`), protocol via `github.com/miekg/dns` (`go.mod:83`).
9. Routes: `client/internal/routemanager/manager.go` (static/dynamic/exit-node, `sysctl`, `systemops` for
   `ip route` + forwarding).
10. Firewall: `client/firewall/manager/firewall.go` (`Manager` interface) with `nftables` (`github.com/google/nftables`)
    and `iptables` (`github.com/coreos/go-iptables`) backends.
11. State files: `/etc/netbird/config.json` + profiles (`client/internal/profilemanager/`, `config.go`,
    `profilemanager.go`), runtime state via `client/internal/statemanager/manager.go`; logs `/var/log/netbird/client.log`.

Out of router scope but in `./client` deps: SSO/OAuth (`client/internal/auth/`, device + PKCE flows), SSH server
(`client/ssh/`), auto-updater (`client/internal/updater/`), Rosenpass (`client/internal/rosenpass/`,
`cunicu.li/go-rosenpass`), flow exporter (`flow/`, `client/internal/netflow/`), Mobile/Windows/macOS files.

## 2. Protocols on the wire and Zig 0.17 std coverage

Std root used: `Z=/home/kukuruza/.local/share/mise/installs/zig/0.17.0/lib/std`
(`mise where zig` → `/home/kukuruza/.local/share/mise/installs/zig/0.17.0`).

| # | Protocol / format | Where the client speaks it | Zig 0.17 std provides | Gap |
|---|---|---|---|---|
| 1 | Protobuf (proto3) | `shared/management/proto/*.proto`, `shared/signal/proto/*.proto`, `client/proto/daemon.proto`, `flow/proto/flow.proto` | nothing (`find $Z/lib/std -iname '*proto*'` → no hits for protobuf) | full runtime + codegen or hand-written codecs |
| 2 | gRPC over HTTP/2 + TLS | mgmt (`shared/management/client/grpc.go:152` `nbgrpc.CreateConnection`), signal (`shared/signal/client/grpc.go:126`), daemon socket (cleartext) | nothing: `http/Client.zig` is HTTP/1.1 (`grep -in 'http/2' http/Client.zig` → empty); no grpc dir | HTTP/2 framing, HPACK, gRPC framing, streams |
| 3 | TLS 1.2/1.3 client | mgmt/signal/relay/OIDC HTTPS | `crypto/tls/Client.zig` (`init`, `eof`, `end`), `http/Client.zig` wires `crypto.Certificate.Bundle` | verify against netbird.cloud cipher needs (not verified) |
| 4 | TCP/UDP sockets | everywhere | `Io/net.zig` (`IpAddress`, `Stream`, `Server`, 1633 lines: `wc -l Io/net.zig`) | none for basics |
| 5 | STUN (RFC 8489) + TURN (RFC 5766/8656) | `client/internal/peer/ice/StunTurn.go`, pion/stun/v3, pion/turn/v3 | nothing (`find -iname '*stun*'` / `'*turn*'` → empty) | STUN binding + TURN allocate/refresh/permissions/channels |
| 6 | ICE (RFC 8445, aggressive, fork patches) | pion/ice/v4 fork (`go.mod:360`), `peer/worker_ice.go` | nothing | full ICE agent: gathering, checks, nomination, keepalives |
| 7 | Relay over QUIC | `shared/relay/client/dialer/quic` (`quic-go v0.62.0`, `go.mod:106`) | nothing (`find -iname '*quic*'` → empty) | QUIC v1 + TLS 1.3 handshake + datagrams |
| 8 | Relay over WebSocket | `shared/relay/client/dialer/ws` (`github.com/coder/websocket`) | nothing (`find -iname '*websocket*'` → empty) | RFC 6455 client + TLS |
| 9 | Relay message framing | `shared/relay/messages/message.go` | n/a (netbird format, small) | port ~10 marshal/unmarshal funcs |
| 10 | WireGuard protocol (Noise IK, ChaCha20Poly1305, UDP transport, timers, roaming) | wireguard-go fork (`go.mod:356`), binds in `client/iface/bind/` | primitives only: `crypto/chacha20.zig` (`ChaCha20Poly1305`), `crypto/25519/x25519.zig` (`X25519`), `crypto/blake2.zig` (`Blake2s256`), `crypto/hkdf.zig` (all re-exported from `crypto.zig`) | whole device: handshake state machine, queues, timers, netstack glue |
| 11 | TUN (`/dev/net/tun`, `TUNSETIFF`) | `wireguard/tun` | nothing (`grep -rn TUNSETIFF $Z/lib/std` → empty) | ioctl wrapper + struct defs |
| 12 | Netlink (`NETLINK_ROUTE`) + nftables/iptables | `google/nftables`, `coreos/go-iptables`, `client/firewall/{nftables,iptables}` | nothing (`grep -rn NETLINK_ROUTE $Z/lib/std` → empty) | netlink socket + nftables batch expressions (guess: iptables via xtables lock + `iptables` exec is simpler) |
| 13 | DNS protocol + OS resolver config | `miekg/dns`, `client/internal/dns/*_unix.go`, `routemanager/dnsinterceptor` | nothing (`find -iname '*dns*'` → empty) | DNS codec + UDP/TCP server + resolv.conf/NetworkManager editing |
| 14 | NaCl box (mgmt/signal `EncryptedMessage`) | `encryption/encryption.go:18` (`Encrypt`/`Decrypt`) | `crypto/nacl`? NOT checked — primitives (X25519, XSalsa20?) presumed present; mark as to-verify | small |
| 15 | OIDC/OAuth2 device + PKCE (SSO login) | `client/internal/auth/` (`device_flow.go`, `pkce_flow.go`), `golang-jwt/jwt/v5` | HTTP client + JSON (`json.zig`) + JWT needs hand code | flows + JWT verify; router uses setup key so deferrable |
| 16 | Rosenpass (post-quantum PSK) | `cunicu.li/go-rosenpass`, `client/internal/rosenpass/manager.go` | nothing PQ in std (guess: `crypto/` has no kyber; not run — to-verify) | whole PQ-KEM; optional, behind flag |
| 17 | JSON state files | profilemanager, statemanager | `json.zig` | none |
| 18 | Daemon UNIX socket | `unix:///var/run/netbird.sock` | `Io/net.zig` unix sockets (presumed; to-verify) | small |

Biggest std gaps, ordered by risk: gRPC/HTTP/2 (#2) → ICE (#6) → QUIC (#7) → WireGuard device (#10) →
protobuf (#1) → TURN (#5) → netlink/nftables (#12) → STUN (#5) → WebSocket (#8) → DNS (#13).

## 3. Module layout and milestones

Proposed `src/` layout (each dir one Zig module with `*_test.zig` beside it):

```text
src/
  proto/      hand-written protobuf codec + generated-equivalent structs for mgmt/signal/daemon/flow protos
  grpc/       HTTP/2 + HPACK + gRPC client (unary + server/bidi streaming), cleartext + TLS
  mgmt/       ManagementService client: login, sync loop, getServerKey (port of shared/management/client)
  signal/     SignalExchange client (port of shared/signal/client + peer/signaler.go)
  stun/       STUN binding client (pion/stun subset)
  turn/       TURN client: allocate, permissions, channel-data (pion/turn subset)
  ice/        ICE agent (pion/ice subset + netbirdio fork behavior in worker_ice.go)
  relay/      relay messages + manager + ws dialer first, quic dialer later (shared/relay port)
  wg/         WireGuard device: Noise IK handshake, transport, timers, TUN glue (wireguard-go subset)
  tun/        /dev/net/tun wrapper
  dns/        DNS codec + local resolver + unix OS-config backends
  route/      netlink routes + sysctl + ip-forward (routemanager subset)
  fw/         nftables-first firewall manager (firewall/manager + nftables backend)
  engine/     Engine + ConnectClient + connMgr (client/internal top level + peer/)
  daemon/     DaemonService server + CLI client (client/server + client/cmd subset: service/up/down/status/login)
  state/      profilemanager + statemanager (JSON)
  crypt/      NaCl-box EncryptedMessage (encryption/)
```

Milestones (router-first; each testable alone). Sizes = non-test Go lines of the ported reference,
`find <dir> -name '*.go' ! -name '*_test.go' | xargs wc -l | tail -1`:

- M0 scaffold + `state` + `crypt`: config/state JSON round-trips. Ref tests: none upstream for
  statemanager; profilemanager has `config_test.go`, `profilemanager_test.go`. Size: profilemanager 2604 +
  statemanager 539 + encryption 387 = **3530**.
- M1 `proto` codec for `management.proto` + `signalexchange.proto`: byte-exact encode/decode vectors
  captured from Go (`shared/management/client/grpc_test.go`, `shared/signal/client/client_suite_test.go`
  as behavior refs; interop: decode a real `SyncResponse`). Size of generated refs being replaced:
  part of 25634 total generated (`wc -l shared/management/proto/*.pb.go shared/signal/proto/*.pb.go
  client/proto/*.pb.go | tail -1` → 25634).
- M2 `grpc` + `mgmt` login/sync against local stub: fake `ManagementService` in Go replays
  `Login`/`Sync`; prove with `shared/management/client/grpc_test.go` vectors. Replaces grpc-go usage
  (grpc-go itself is 36678 lines, `find vendor/google.golang.org/grpc …` → 36678; protobuf runtime 50546 —
  we do NOT port those, we write a minimal client). Netbird-owned client code ported: `shared/management`
  hand-written ≈ 33284 − generated(mgmt ≈ 25634 − signal − daemon; split not measured — to-verify).
- M3 `signal` + `stun` + `turn` + `ice` with two local peers via a local signal stub: SDP offer/answer
  round-trip to a UDP hole; ref tests `client/internal/peer/*_test.go`, `client/internal/peer/ice/StunTurn_test.go`.
  Sizes: peer 6090 + shared/signal 1718 + vendored pion 60048 (subset — guess ~1/3 needed).
- M4 `relay` (messages + manager + ws dialer) against local `relay/` server (`relay/protocol/protocol.go`):
  transport a packet relay↔client; ref tests `shared/relay/client/*_test.go` (9 files). Sizes: shared/relay 4519 +
  coder/websocket 4175 (subset: client framing only).
- M5 `wg` + `tun`: handshake against wireguard-go fork locally, throughput + roaming; ref tests
  `client/iface/iface_test.go`. Sizes: client/iface 8967 + wireguard-go 21654 (subset: device + tun, no netstack).
- M6 `dns` + `route` + `fw`: recipes applied in a netns, checked with `dig`/`ip route`/`nft list`;
  ref tests `client/internal/dns_test.go`, `routemanager/manager_test.go`, `client/firewall/test/`.
  Sizes: dns 10350 + routemanager 8384 + firewall 15740 (nftables backend only — guess ~1/2 of firewall).
- M7 `engine` + `daemon` (service/up/down/status/login, setup-key only): full `up` against local
  management+signal+relay stubs, then against a local upstream stack if the lead provides one; ref tests
  `client/internal/engine_test.go`, `connect_test.go`, `client/cmd/up_test.go`, `service_test.go`.
  Sizes: engine+connect+session 3926 (`wc -l client/internal/engine.go client/internal/connect.go
  client/internal/engine_generic.go client/internal/session.go`) + server 5475 + cmd-subset of 8386 (guess ~1/3).
- M8 QUIC dialer + HPACK/H2 hardening + remaining CLI: same tests as M4/M7 over `NB_RELAY_TRANSPORT=quic`;
  quic-go vendor size 28287 (subset).

Deferred (not on router path): SSO/OIDC (`client/internal/auth` 2141), SSH (`client/ssh` 8600),
updater (`client/internal/updater` 3509), Rosenpass (582 + `cunicu.li` 2688), flow/netflow (1305+1386),
`miekg/dns` full server (21373, subset in M6), proxy service protos, mobile/Windows/macOS files.

## 4. Risks (with evidence)

1. Kernel 4.9 vs Zig 0.17 syscalls. AGENTS.md lists the missing set (statx, io_uring, clone3, openat2, …).
   New risk found: `Io/net.zig` backends include `Io/Uring.zig` and `Io/Threaded.zig` (`ls lib/std/Io/`).
   If the default `Io` backend uses io_uring syscalls unconditionally, every socket op fails on 4.9.
   Mitigation: use `Threaded` backend or raw `posix.socket`; verify with the AGENTS.md qemu-strace recipe
   against a 4.9 syscall allowlist. Evidence: `ls $Z/lib/std/Io/` shows `Uring.zig`, `Threaded.zig`.
2. Memory: 44 MB free; Go baseline RSS 24.1 MB + 6.7 swap, peak 53.6 MB (AGENTS.md). A Zig port should fit,
   but an H2+gRPC+QUIC stack with per-stream buffers needs a budget; no measurement possible before M2.
3. gRPC/HTTP-2 from scratch is the largest single risk: no std support (see table #2), must interop with
   real netbird.cloud servers; needs a local stub first, then a lead-provided upstream stack.
4. ICE fork behavior: `go.mod:360` pins a netbirdio ICE fork; its deltas vs upstream pion must be diffed
   during M3 (not done in this round).
5. firewalld/iptables fallback: router likely uses iptables-legacy or nft; `client/firewall/` has both
   backends plus `firewalld/` — target detection needed on the real device (no ssh allowed; needs lead input).
6. TLS trust: `http/Client.zig` uses `Certificate.Bundle`; the router CA bundle path must be checked
   (not verified).
7. Protobuf surface: `management.proto` is large (generated total 25634 lines incl. signal+daemon);
   hand-written codecs risk field drift — mitigate with byte-vector tests from Go in M1.

## 5. Milestone sizes (Go lines ported, non-test)

Command per row: `find <dir> -name '*.go' ! -name '*_test.go' | xargs wc -l | tail -1` (run 2026-10-03).
"Subset" rows are guesses.

| Milestone | Reference dirs | Lines |
|---|---|---|
| M0 state+crypt | profilemanager 2604 + statemanager 539 + encryption 387 | 3530 |
| M1 proto | generated mgmt+signal+daemon+flow (upper bound) | ≤25634 (hand codec will be far smaller) |
| M2 grpc+mgmt | shared/management 33284 (incl. generated) + grpc usage | hand-written ≈ 33284 − generated-share (to-verify) |
| M3 signal/ice | peer 6090 + shared/signal 1718 + pion subset of 60048 | 7808 + subset |
| M4 relay-ws | shared/relay 4519 + coder subset of 4175 | 4519 + subset |
| M5 wg+tun | iface 8967 + wireguard-go subset of 21654 | 8967 + subset |
| M6 dns/route/fw | dns 10350 + routemanager 8384 + firewall nft-subset of 15740 | 18734 + subset |
| M7 engine/daemon | engine-core 3926 + server 5475 + cmd subset of 8386 | 9401 + subset |
| M8 quic | quic-go subset of 28287 | subset |
| Deferred | auth 2141 + ssh 8600 + updater 3509 + rosenpass 582 + cunicu 2688 + flow 1305 + netflow 1386 + miekg subset of 21373 + nftables-full 9024 + go-iptables 803 | — |

Full per-dir table: client/cmd 8386, client/server 5475, client/internal/auth 2141, client/internal/peer 6090,
client/iface 8967, client/firewall 15740, client/internal/dns 10350, client/internal/routemanager 8384,
client/internal/profilemanager 2604, client/statemanager 539, client/net 1637, client/system 2047,
shared/management 33284, shared/signal 1718, shared/relay 4519, encryption 387, client/ssh 8600,
client/internal/rosenpass 582, client/internal/updater 3509, client/proto 13006 (generated),
flow 1305, client/internal/netflow 1386.

## 6. Open questions (for the lead)

1. Which firewall backend does the KN-3812 need (nftables vs iptables-legacy)? No ssh allowed to check.
2. Will the lead provide a local upstream stack (management+signal+relay) for M2–M8 interop, or only stubs?
3. Is `NB_RELAY_TRANSPORT=ws` acceptable on the router long-term (defers QUIC), or is QUIC required for parity?
4. May M1 codecs be hand-written (risk of drift) or is a small `protoc` plugin + checked-in generation wanted?
5. Go toolchain present is go1.27.1 (`go version`); is it approved for building stubs/vectors in later milestones?
