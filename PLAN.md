# PLAN (owned by the lead)

Order (owner 2026-10-03): client first, it is what runs on the router; then its libraries; then the servers.

- Phase 0, council: inventory of the client code and two independent porting proposals, then cross-review. Lead merges here.
- Phase 1+: filled from the council result.

Acceptance for the router client: joins a NetBird network, talks to peers directly and through relay,
survives restart; then RSS and binary size are measured on the router against the Go baseline in AGENTS.md.

## Merged plan
Milestones M1-M10 and the module layout: council/r3-merged.md (council r1+r2, 2026-10-03).

## Lead decisions (2026-10-03, answers to council/r3-merged.md §5-6)
1. Relay: WebSocket first (M5), QUIC at M10.
2. Foreground client first (M8), daemon and IPC at M9.
3. Firewall: first backend is iptables. Measured on the KN-3812: no nft binary, no nf_tables modules,
   /opt/sbin/iptables v1.4.21, tables nat mangle filter. nftables and uspfilter later.
4. Protobuf: a small generator in Zig (tools/protogen) for the proto3 subset in upstream .proto files, checked with Go byte vectors.
5. Local upstream stack (management, signal, relay built from upstream/) for M3-M8 interop: allowed, localhost only,
   `nice -n 19`, `go build -p 4`, stopped after the test.
6. Go toolchain for vectors and stubs: allowed, but Go helpers live in ~/.cache/netbird-zig-context/gen, not in the repo.
   The repo stays a pure Zig project; generated vectors are committed as test data.
7. TURN: port the protocol once, keep both call sites compiling.

## Scope: everything (owner 2026-10-03: «переписывают полностью», size does not matter)

Owner decision 2026-10-04: «Мы переписываем всё на язык программирования Zig, потому что он для роутера лучше…
Он должен полностью совпадать с оригинальным NetBird'ом… Массовая миграция». The Zig client must behave exactly
like upstream NetBird: same config and state files, same wire protocol, same CLI. For comparison, bc547/nanoNetBird
(NetBird on nanoKVM) only compiles the original Go client for riscv64 with a shell script; this repo's install.sh
already does the same for Keenetic, and the Zig port replaces that binary.
Nothing from NetBird is excluded. council/r3-merged.md "Deferred" and "excluded" items are later milestones, not cuts.
Order stays: what the router needs to join the network first (M1-M10), then:

| # | Scope |
|---|---|
| M11 | SSO/OIDC login (client/internal/auth), device flow and PKCE |
| M12 | NetBird SSH server and client (client/ssh) |
| M13 | Rosenpass post-quantum key exchange (client/internal/rosenpass, cunicu.li/go-rosenpass) |
| M14 | Flow logs / netflow, lazy connections (lazyconn), eBPF wgproxy (for kernels that have it) |
| M15 | Updater, Prometheus metrics, remaining CLI commands and flags |
| M16 | Userspace network stack (gVisor netstack subset used by NetBird: uspfilter forwarder, netstack mode) |
| M17 | Servers: signal, relay, then management and combined (AGPLv3 dirs, ported code stays AGPLv3) |
| M18 | Other platforms: Windows, macOS, Android, iOS client parts |
