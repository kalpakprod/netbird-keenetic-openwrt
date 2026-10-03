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
