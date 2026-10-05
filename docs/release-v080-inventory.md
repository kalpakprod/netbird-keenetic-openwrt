# NetBird v0.80.0 — full release inventory and dependency DAG for the Zig port

Card: W02-v080-20261005 · Author model: GLM (glm-5.3-flash) · Date: 2026-10-05
Upstream pin: `fca64287cf51a85552a41b022013abbfdb335452` (exact v0.80.0), at
`/home/kukuruza/.cache/netbird-zig-context/release-v080-20261005/upstream-v080` (read-only reference).

Method and evidence rules:

- Every upstream path in this document was verified to exist in the pinned tree (directory listings
  and targeted greps of the pinned sources; see appendix A for the commands).
- Feature IDs (`E-`, `C-`, `P-`, `S-`, `D-`, `W-`, `L-`, `G-`) are stable handles for lane cards.
- Zig state is mapped **only from accepted refs** (`main` = `e92cc5fdd7602ac14bec2d0213767f081fe56e5a`
  and the open feature branches named in §2). The project root checkout is dirty and is not a source.
- `upstream-v080` has **no `vendor/` directory** (top-level listing). The dependency build graph from
  `go list -mod=vendor` therefore **cannot be produced for v0.80** and is marked PENDING in §8;
  `go.mod` / `go.sum` / source imports are the only dependency evidence. The v0.79 vendor tree is
  **not** used as proof for anything in v0.80.
- "IMPLEMENTED" = module committed at the cited ref. "VERIFIED" = committed tests plus a documented
  verification run in a prior card report (§10). This card is documentation-only; no test was re-run.

Lane columns use the release run `run.json`: W01–W08 are launched cards with owned paths; W09–W12
are reserved implementation slots with no cards yet. "—" = not yet assigned by the lead.

## 1. Release executables (goreleaser `builds` + `func main()` evidence)

Executables released by `.goreleaser.yaml` and the three UI configs. All servers are Linux-only in
the release; the client is the multi-OS artifact.

| ID | Binary | Upstream dir (`dir:`) | Release targets | CGO | Notes |
|----|--------|------------------------|-----------------|-----|-------|
| E-01 | `netbird` | `client` | linux/darwin/windows × arm, amd64, arm64, 386 (windows: amd64+arm64 only) | 0 | Daemon+CLI, tag `load_wgnt_from_rsrc`; darwin shipped as `universal_binaries`; deb+rpm nfpm packages; docker amd64/arm64/arm6 (`client/Dockerfile`, `-rootless`, `-rootless.ubi`) |
| E-02 | `netbird` (static) | `client` | linux mips, mipsle, mips64, mips64le × hardfloat/softfloat | 0 | `netbird-static` build id |
| E-03 | `netbird` (js) | `client/wasm/cmd` | js/wasm | 0 | `netbird-wasm` build id; archive format `binary` |
| E-04 | `netbird-mgmt` | `management` | linux amd64, arm64, arm7 | **1** | CGO for the SQLite driver (§6); `management/Dockerfile` |
| E-05 | `netbird-signal` | `signal` | linux amd64, arm64, arm7 | 0 | `signal/Dockerfile` |
| E-06 | `netbird-relay` | `relay` | linux amd64, arm64, arm7 | 0 | `relay/Dockerfile` |
| E-07 | `netbird-server` | `combined` | linux amd64, arm64, arm7 | **1** | All-in-one mgmt+signal+relay; `combined/Dockerfile` |
| E-08 | `netbird-upload` | `upload-server` | linux amd64, arm64, arm7 | 0 | `upload-server/Dockerfile.release` |
| E-09 | `netbird-proxy` | `proxy/cmd/proxy` | linux amd64, arm64, arm7 | 0 | `proxy/Dockerfile`, `Dockerfile.ubi` (images `netbirdio/reverse-proxy`) |
| E-10 | `netbird-idp-migrate` | `tools/idp-migrate` | linux amd64, arm64, arm7 | **1** | IdP migration tool |
| E-11 | `netbird-ui` | `client/ui` | linux amd64 (GTK4/WebKitGTK 6.0), windows amd64+arm64 (mingw, `-H windowsgui`) | **1** | `.goreleaser_ui.yaml`; tag `production`; wails3 bindings + `pnpm build` frontend |
| E-12 | `netbird-ui` (darwin) | `client/ui` | darwin amd64+arm64 → universal | **1** | `.goreleaser_ui_darwin.yaml`, deployment target 11.0 |
| E-13 | `netbird-ui-gtk3` | `client/ui` | linux amd64, tag `gtk3` | **1** | `.goreleaser_ui_gtk3.yaml` for Ubuntu 22.04/Debian 12/RHEL 9; conflicts with netbird-ui |

`func main()` packages **not in goreleaser** (source-tree tools, part of full parity but not release
artifacts): `client/cmd/signer/main.go` (setup-key signer), `client/internal/metrics/infra/ingest`,
`relay/testec2`, `sharedsock/example`, `tools/gotestsummary` (CI test summarizer).

Release-adjacent extras shipped by goreleaser: `checksum.extra_files` covers
`infrastructure_files/getting-started*.sh`, `migrate-to-enterprise.sh` and `release_files/install.sh`;
brew tap `netbirdio/homebrew-tap`; deb/yum uploads to `pkgs.wiretrustee.com`.

## 2. Current accepted Zig state (refs and lanes)

Accepted refs (verified by `git rev-parse` / `git log` / `git diff --name-only` in the W02 worktree):

- `main` = `e92cc5f` (merge of PR #43). Modules: `src/main.zig`, `src/crypto/keys.zig`,
  `src/proto/wire.zig`, `src/net/h2/{frame,hpack}.zig`, `src/net/tls/{client,ca}.zig`,
  `src/relay/messages.zig`, `src/routes/routes.zig`, `src/state/profile.zig`, `src/tun/tun.zig`,
  `src/wireguard/{device,noise,cookie,timers}.zig` (+ `wgtun_test.zig`), `tools/protogen/*`,
  `build.zig` (auto-discovers every `src/**/*_test.zig`; cross-target = compile-only).
- `origin/feat/h2-conn` = `0e1ebaf` (PR #23 plus merged #104–#106): adds `src/cli.zig`,
  `src/engine.zig`, `src/mgmt/{client,messages,wgbox}.zig`, `src/net/grpc/{client,format}.zig`,
  `src/net/h2/conn.zig` (+ interop test, `testdata/conn.txt`), `src/signal/{client,messages}.zig`,
  state testdata and profile updates. Base branch of W01, W06, W07, W08.
- `origin/feat/ice-turn` = `1de6f8e` (PRs #61, #68, #69): `src/ice/{stun,ice,turn}.zig` + tests +
  `testdata/vectors.txt`. Base branch of W04.
- `origin/feat/fw-filter` = `b39d7ad` (PRs #60, #63–#65): `src/fw/{model,chains,iptables,filter,
  nat,fwmark,lock,manager}.zig` + tests. Base branch of W05.

Other open PRs carrying accepted-or-under-review Zig (from `gh pr list`): #17 crypto-box,
#26 state-manager, #37 wg-device, #38 wg-interop, #3 wireguard-noise, #71/#72 state fixes,
#73 pf NAT-PMP/PCP, #75 dns wire codec, #79 pf UPnP, #80/#82 pf fixes, #83 pf manager,
#85 dns resolver, #86/#87 protogen generator and generated codecs, #88 dns resolv.conf backend,
#89 net WebSocket client, #90 relay client, #107 docs full-release plan.

Active lanes (from `run.json` + task cards):

| Lane | Card | Owned Zig paths | Base |
|------|------|-----------------|------|
| W01 | TLS dependency (ALPN restore) | `src/net/tls/{client,ca,tls_test}.zig` | feat/h2-conn |
| W02 | full inventory (this document) | `docs/release-v080-inventory.md` | main |
| W03 | WG UDP/TUN runtime adapter | `src/wireguard/{runtime,runtime_test}.zig` | main |
| W04 | TURN >16 channel fix (review of #69) | `src/ice/{turn,turn_test}.zig` | feat/ice-turn |
| W05 | FW mangle allocator-failure fix (review of #63) | `src/fw/{filter,filter_test}.zig` | feat/fw-filter |
| W06 | main dispatch / offline CLI | `src/{main.zig,app.zig,app_test.zig}` | feat/h2-conn |
| W07 | Linux IPC peer auth (SO_PEERCRED) | `src/daemon/{ipcauth,ipcauth_test}.zig` | feat/h2-conn |
| W08 | OIDC device authorization flow | `src/auth/{device_flow,device_flow_test}.zig` | feat/h2-conn |
| W09–W12 | reserved, no cards yet | — | — |

## 3. Client subsystems (upstream `client/`) — the router-facing core

| ID | Upstream path | Role (from pinned sources) | Zig module | Lane | Dependencies | Acceptance boundary |
|----|---------------|----------------------------|------------|------|--------------|---------------------|
| C-01 | `client/main.go`, `client/cmd/` (root, up, down, login, logout, status, state, ssh, networks, profile, debug, capture, expose, forwarding_rules, jobs, kubernetes, pprof, qr, service*, system, trace, update, version, signer/) | CLI entry `cmd.Execute()`, foreground mode, service install/controller, JSON socket gateway | `src/main.zig`, `src/cli.zig` | W06 (offline dispatch first) | daemon IPC client, state | W06 card: real arg parse, exit codes, offline config behavior; production `login/up` explicitly open |
| C-02 | `client/server/server.go` (daemon) + `capture.go`, `debug*.go`, `jwt_cache.go`, `mdm.go`, `ssh_gate.go`, `state*.go`, `sleep.go`, `trace.go`, `status_stream.go`, `triggerupdate.go` | DaemonService gRPC server behind unix socket / Windows named pipe | `src/daemon/` (only ipcauth so far) | W07 (ipcauth only) | C-01, C-05, W-04 | Not yet carded; full-release bar = wire-identical DaemonService (46 RPCs, §7) |
| C-03 | `client/internal/engine.go`, `connect.go`, `conn_mgr.go`, `engine_authsession.go`, `engine_ssh.go`, `engine_sessionwatch.go`, `engine_tunsettings.go`, `state.go`, `session.go` | Engine: connects config→engine, loginToManagement, network map application, lifecycle | `src/engine.zig` (on feat/h2-conn) | — | mgmt, signal, relay, ice, wg, dns, routes, fw | PLAN router acceptance: join network, direct + relay peers, survive restart, RSS/size vs Go baseline |
| C-04 | `client/internal/peer/` (+ `peerstore/`) | Peer connection: ICE candidate exchange, WireGuard binding, handshake supervision | — | — | ice, wg, signal, relay | Not yet carded |
| C-05 | `client/internal/ipcauth/` (`identity`, `privileged`, `creds_unix`, `peercred_linux`, `self_unix`) | Kernel-authenticated IPC caller identity (SO_PEERCRED), privilege gating, owned-file open | `src/daemon/ipcauth.zig` | **W07** | raw sockets | W07 card: real SO_PEERCRED acquisition, deny-on-unknown, unix-socket peer-cred tests |
| C-06 | `client/internal/auth/` (+ `sessionwatch/`) | OIDC/PKCE/device flows, JWT validation, SSO session watch | `src/auth/device_flow.zig` (W08 in flight) | **W08** | net/tls (§2), mgmt client, W-01 | W08 card: device-flow protocol + polling semantics; production HTTP/TLS adapter explicitly open |
| C-07 | `client/internal/dns/`, `dnsfwd/`, `dns.go`, `dns_peer_activator.go`; root `dns/` codec | DNS listener/service, upstream forward, per-peer activation | — | — (PRs #75, #85, #88 open) | W-06 dns codec, routes | PR-level: codec, resolver chain, resolv.conf backend; full parity pending |
| C-08 | `client/internal/routemanager/`, `routeselector/`, `wg_iface_monitor*.go`; root `route/` | Routes: manager, HA unique IDs (route/hauniqueid.go), netlink-based route/addr management, WG interface monitor | `src/routes/routes.zig` | — | vishvananda/netlink (§8) | rtnetlink primitives merged; routemanager logic not yet carded |
| C-09 | `client/firewall/` (`iptables/`, `nftables/`, `uspfilter/`, `firewalld/`, `manager/`, `create*.go`, `allower_*.go`) | Firewall backends + manager; first backend iptables (lead decision) | `src/fw/*` (branch) | W05 (fix only) | L-08 iptables, L-09 nftables | PR #63 + W05 fix; nftables/uspfilter/firewalld backends not yet carded |
| C-10 | `client/internal/relay/`, `client/internal/lazyconn/` | Relay client mgmt, lazy connection dialing | — | — (#90 relay client open) | W-03 messages, net/ws #89, quic-go (§8) | messages codec merged; client under review; lazyconn not carded |
| C-11 | `client/internal/iface*`, `client/iface/` (`bind/`, `bufsize/`, `configurer/`, `device/`, `freebsd/`, `netstack/`, `udpmux/`, `wgaddr/`, `wgproxy/`) | WG interface: creation per OS, UAPI configurer, udpmux, wgproxy (udp/ebpf), netstack mode | `src/tun/tun.zig`, `src/wireguard/` | W03 (runtime adapter) | W03 runtime, tun (merged) | #43 merged WG-over-TUN ns test; W03 adds real UDP/TUN runtime; iface/UAPI configurator not carded |
| C-12 | `client/internal/stdnet/` | pion stdnet extension (interface selection) | — | — | ice | Not carded |
| C-13 | `client/internal/rosenpass/` | Post-quantum key exchange hook | — | — (M13) | cunicu/go-rosenpass, circl (§8) | Not carded |
| C-14 | `client/internal/netflow/`, root `flow/` | Flow logs collection + FlowService gRPC export | — | — (M14) | W-05 flow proto | Not carded |
| C-15 | `client/internal/ebpf/`, `client/iface/wgproxy/` (ebpf part) | eBPF wgproxy bypass | — | — (M14) | cilium/ebpf (§8) | Kernel 4.9 constraint: expect N/A on KN-3812, needed for modern kernels |
| C-16 | `client/internal/updater/` (+ `installer/`, `reposign/`) | Auto-update: reposign verify, installer, version staging | — | — (M15) | — | Not carded |
| C-17 | `client/internal/metrics/`, `localmetrics/` | Client metrics (incl. infra ingest tool) | — | — (M15) | prometheus (§8) | Not carded |
| C-18 | `client/internal/debug/` | Debug bundle collection | — | — | — | Not carded (DaemonService DebugBundle RPC depends on it) |
| C-19 | `client/internal/profilemanager/`, `syncstore/`, `statemanager/` | Multi-profile config, sync response persistence, state files | `src/state/profile.zig` | — | — | profile merged (#25 + fixes); statemanager under review (#26); syncstore not carded |
| C-20 | `client/internal/acl/` | Policy/ACL evaluation shared with server | — | — | management types | Not carded |
| C-21 | `client/internal/networkmonitor/`, `sleep/`, `listener/`, `templates/`, `tunnelnotifier/`, `expose/`, `ingressgw/`, `portforward/`, `daemonaddr/`, `elevate/`, `getent/`, `mobile_dependency.go`, `connect_android_*.go` | Support subsystems: network change monitor, sleep handling, service listener, config templates, tunnel notifications, expose service (proto RPCs CreateExpose/RenewExpose/StopExpose), ingress gateway, port forwarding (PRs #73/#79/#83 open), elevation, NSS lookup | — | — (portforward PRs open) | varies | Not carded; portforward at PR review stage |
| C-22 | `client/ssh/` (`server/`, `client/`, `auth/`, `config/`, `detection/`, `proxy/`) | Built-in SSH server + client, host key detection, socks proxy | — | — (M12) | gliderlabs/ssh, pkg/sftp (§8) | Not carded |
| C-23 | `client/iface/udpmux/`, `client/iface/wgproxy/udp` | UDP muxing and forwarding around the WG device | — | — | W03 boundary | Not carded beyond W03's runtime adapter |
| C-24 | `client/internal/updater` vs `client/status/`, `client/netevents/` (`netstate/`, `sweep/`), `client/anonymize/`, `client/jobexec/`, `client/errors/`, `client/grpc/` (dialer/retry), `client/net/` (dialer/listener/fwmark/env per-OS), `client/system/` (`detect_cloud/`, `detect_platform/`), `client/mdm/` | Status reporting, network events, log anonymization, job exec, errors, gRPC dialing with retry, socket env handling (fwmark, interface binding, socket protection), system info (per-OS incl. freebsd/js/android/ios), MDM policy (darwin/windows dconf/registry) | — | — | varies | Not carded |

## 4. Platform surfaces (upstream source targets)

| ID | Platform | Upstream evidence | Release vehicle | Zig state | Lane |
|----|----------|-------------------|-----------------|-----------|------|
| P-01 | linux (kernel WG mode) | `client/iface/device/kernel_module_linux.go`, netlink, iptables/nftables dirs | E-01, E-02, docker | W03 targets aarch64-linux-musl; arm/6, arm7, 386, mips* unaddressed | W03 |
| P-02 | linux (userspace WG) | wireguard-go device + TUN (`client/iface`) | E-01 | TUN merged, runtime W03 | W03 |
| P-03 | linux (netstack mode, no TUN) | `client/iface/netstack/`, `client/embed/` (gVisor netstack listeners) | E-01, E-03 | Not carded (M16) | — |
| P-04 | windows | `iface_*windows.go`, `allower_windows.go`, `wincmd/`, `winregistry/`, named-pipe IPC (`service_pipe_windows.go`), wintun (`load_wgnt_from_rsrc` tag), `netbird.wxs`, `installer.nsis` | E-01, E-11 | Not carded | — |
| P-05 | darwin/macOS | `client/iface/iface_create_darwin.go`, `dock_darwin.go`, `system/info_darwin.go`, UI darwin universal, network extension paths | E-01 (universal), E-12 | Not carded | — |
| P-06 | freebsd | `client/iface/freebsd/`, `client/iface/iface_destroy_bsd.go`, `system/info_freebsd.go` | source-level only (no goreleaser target) | Not carded | — |
| P-07 | android | `client/android/` (gomobile `client.go`, session, ssh_client, preferences, split_tunnel), `client/mobile/`, `internal/connect_android_*.go`, `system/info_android.go`, `protectsocket_android.go` | gomobile bind (not goreleaser) | Not carded | — |
| P-08 | ios | `client/ios/NetBirdSDK/`, `iface_new_ios.go`, `system/info_ios.go`, `dial_ios.go` | gomobile bind (not goreleaser) | Not carded | — |
| P-09 | js/wasm | `client/wasm/{cmd,internal}`, `client/iface/iface_new_js.go`, `client/iface/iface_destroy_js.go`, `system/info_js.go`, `engine_js.go`, `debug_js.go`, `ssh_js.go` | E-03 | Not carded | — |
| P-10 | desktop UI | `client/ui/` Wails v3 Go backend (services/, tray*, frontend/ React, i18n, guilog, preferences, authsession, autostart, xembed tray for linux incl. C shim upstream-side) | E-11, E-12, E-13 | Not carded; UI stack decision open (CGO/gtk, §9) | — |

## 5. Servers and service tools

| ID | Upstream path | Role | Zig module | Lane | Notes |
|----|---------------|------|------------|------|-------|
| S-01 | `management/` (`main.go`, `cmd/`, `server/` incl. `http/` REST handlers+middleware, `account.go`, `peer.go`, `user.go`, `group.go`, `route.go`, `policy.go`, `nameserver.go`, `setupkey.go`, `posture*`, `networks/`, `permissions/`, `settings/`, `idp/`, `integrations/`, `telemetry/`, `cache/`, `geolocation/`, `instance/`, `job/`, `metrics/`, `mock_server/`, `internals/` incl. `agentnetwork` pricing and `network_map_db`) | Control plane: gRPC + REST (OpenAPI) + events | — | — (M17) | AGPLv3 dir; ported files stay AGPLv3 |
| S-02 | `management/server/store/` (`store.go`, `sql_store*.go`, `file_store.go`) + §6 | Persistence (SQLite/Postgres/MySQL/file) | — | — | See §6 |
| S-03 | `management/server/migration/` (`migration.go`, `migration_agentnetwork.go`, `migration_custom_domain.go`) | Store migrations, both GORM and pgx paths | — | — | One-way in the field; parity requirement |
| S-04 | `signal/` (`main.go`, `cmd/`, `server/`, `peer/`, `metrics/`) | Handshake broker (SignalExchange, 2 RPCs) | — | — (M17) | Stateless, first server milestone candidate |
| S-05 | `relay/` (`main.go`, `cmd/`, `server/`, `protocol/`, `healthcheck/`, `metrics/`) | Relay server (WS/QUIC), health checks | — | — (M17) | Client-side codec already merged |
| S-06 | `combined/` (`main.go`, `cmd/`, `config.yaml.example`) | All-in-one server binary | — | — (M17) | CGO |
| S-07 | `proxy/` (`cmd/proxy`, `server.go`, `inbound.go`, `middleware_*.go`, `lifecycle.go`, `internal/` incl. `llm/`, `auth/`, `acme/`, `accesslog/`, `crowdsec/`, `middleware/`, `tcp/`, `udp/`, `geolocation/`, `conntrack/`, `k8s/`, `metrics/`, `health/`, `web/`) | Identity-aware proxy for Agent Network, LLM routing | — | — (M17) | Depends on W-02 proxy_service proto |
| S-08 | `upload-server/` (`main.go`, `server/`, `types/`) | S3-compatible bundle upload service | — | — (M17) | aws-sdk-go-v2/s3 |
| S-09 | `idp/` (`dex/`: config, connector, provider, logrus handler, sqlite cgo/nocgo variants, `web/`; `sdk/sdk.go`) | Embedded Dex IdP integration | — | — (M17) | dex is a netbirdio fork (§8) |
| S-10 | `tools/idp-migrate/` | IdP migration CLI (E-10) | — | — (M17) | Uses S-02 store |

## 6. Server stores and migrations (every backend)

Evidence: `management/server/store/sql_store.go` imports `gorm.io/driver/{sqlite,postgres,mysql}`
and `github.com/jackc/pgx/v5/pgxpool` (lines 17–21); `connectToPgDb` (line 248) opens a raw pgx
pool beside the GORM handle; seed helpers `NewPostgresqlStoreFromSqlStore` (342) and
`NewMysqlStoreFromSqlStore` (408) seed from SQLite; `file_store.go` keeps the legacy file store.

| ID | Backend | Driver (go.mod) | Evidence | Port prerequisite |
|----|---------|-----------------|----------|-------------------|
| D-01 | SQLite (default) | `gorm.io/driver/sqlite` v1.5.7 → `github.com/mattn/go-sqlite3` (cgo) | `gorm.Open(sqlite.Open(connStr))` line 221; DSN PRAGMA note line 201; max-conns note line 98 | **CGO conflict** with repo no-C rule (§9-2) |
| D-02 | PostgreSQL (GORM) | `gorm.io/driver/postgres` v1.5.7 | line 231, 362 | pure-Zig pg wire client or external decision |
| D-03 | PostgreSQL (raw pgx path) | `github.com/jackc/pgx/v5` v5.10.0 | `pgxpool` lines 69, 248–259, 383–394; parity test `sql_store_pgx_parity_test.go` | same as D-02 |
| D-04 | MySQL | `gorm.io/driver/mysql` v1.5.7 | line 274 (+`parseTime` DSN), backtick quoting line 48, DSN env line 305 | same as D-02 |
| D-05 | File store (legacy) | none | `file_store.go` | plain Zig |
| D-06 | Migrations | — | `migration.go` (24 KB), `migration_agentnetwork.go`, `migration_custom_domain.go` | must cover GORM + pgx dual paths |
| D-07 | IdP-embedded store | sqlite cgo and nocgo variants | `idp/dex/sqlite_cgo.go`, `sqlite_nocgo.go` | follows D-01 decision |

## 7. Wire protocols and schemas (exact RPC surfaces)

| ID | Schema | Service / RPCs | Consumers |
|----|--------|----------------|-----------|
| W-01 | `shared/management/proto/management.proto` | `ManagementService`: Login, Sync (stream), GetServerKey, isHealthy, GetDeviceAuthorizationFlow, GetPKCEAuthorizationFlow, SyncMeta, Logout, Job (bidi stream), ExtendAuthSession, CreateExpose, RenewExpose, StopExpose — 13 RPCs | C-03 engine, S-01 management |
| W-02 | `shared/management/proto/proxy_service.proto` | `ProxyService`: GetMappingUpdate, SyncMappings, SendAccessLog, Authenticate, SendStatusUpdate, CreateProxyPeer, GetOIDCURL, ValidateSession, ValidateTunnelPeer, CheckLLMPolicyLimits, RecordLLMUsage — 11 RPCs | S-07 proxy ↔ S-01 management |
| W-03 | `shared/relay/messages/` (binary codec: `message.go`, `peer_state.go`, `id.go`) | Relay client/server messages, not protobuf | C-10, S-05 — **codec merged** (`src/relay/messages.zig`, PR #84) |
| W-04 | `client/proto/daemon.proto` | `DaemonService`: 46 RPCs (Login, WaitSSOLogin, Up, Status, SubscribeStatus, Down, GetConfig, ListNetworks, SelectNetworks, DeselectNetworks, ForwardingRules, DebugBundle, GetLogLevel, SetLogLevel, ListStates, CleanState, DeleteState, SetSyncResponsePersistence, TracePacket, StartCapture, StartBundleCapture, StopBundleCapture, SubscribeEvents, GetEvents, RegisterUILog, SwitchProfile, SetConfig, AddProfile, RenameProfile, RemoveProfile, ListProfiles, GetActiveProfile, Logout, GetFeatures, TriggerUpdate, GetPeerSSHHostKey, RequestJWTAuth, WaitJWTToken, RequestExtendAuthSession, WaitExtendAuthSession, DismissSessionWarning, StartCPUProfile, StopCPUProfile, GetInstallerResult, ExposeService, WailsUIReady); grpc-gateway `daemon.pb.gw.go` present | C-01 CLI, P-10 UI, P-07/08 mobile |
| W-05 | `flow/proto/flow.proto` | `FlowService`: Events (stream) / FlowEventAck | C-14, S-01 |
| W-06 | `shared/signal/proto/signalexchange.proto` | `SignalExchange`: Send, ConnectStream (bidi) | C-03, S-04 |
| W-07 | `shared/management/http/api/openapi.yml` (500 KB) + `types.gen.go` (273 KB), `cfg.yaml` | REST management API (oapi-codegen) | S-01 http handlers, SDK consumers |
| W-08 | NaCl box encryption of mgmt/signal payloads | `encryption/encryption.go` (box.Seal) — council-verified | W-01, W-06 wrapping |

## 8. Used library APIs (used-by-NetBird scope only)

Per the card: enumerate what NetBird actually uses; no demand for unused full third-party APIs.
Version pins are `go.mod` (go 1.26.0 / toolchain go1.26.7). Usage call-sites for the core groups
were verified by the council with line cites (council/r3-merged.md §1) and re-listed here.

### 8.1 In-repo shared libraries (root packages)

| ID | Upstream path | Contents (verified by listing) |
|----|---------------|--------------------------------|
| L-01 | `encryption/` | NaCl box encrypt/decrypt (`encryption.go`), cert, letsencrypt, message, route53 helpers |
| L-02 | `dns/` | shared DNS types (`dns.go`, `nameserver.go`) |
| L-03 | `route/` | route types (`route.go`), HA unique ID (`hauniqueid.go`) |
| L-04 | `stun/` | STUN server helpers (`server.go`) |
| L-05 | `sharedsock/` | shared UDP socket with pluggable packet filters: `filter.go`, `sock_linux.go`/`sock_nolinux.go`, `src_probe_linux.go`, `stun_filter_linux.go`, `example/` |
| L-06 | `formatter/` | log formatting: `hook/`, `levels/`, `logcat/`, `syslog/`, `txt/`, `set.go` |
| L-07 | `monotime/` | monotonic clock wrapper (`time.go`) |
| L-08 | `base62/` | base62 codec (`base62.go`) |
| L-09 | `trustedproxy/` | trusted reverse-proxy header handling (`trustedproxy.go`), used by HTTP servers |
| L-10 | `version/` | version compare, update URL per OS (`compare.go`, `update.go`, `url_{linux,darwin,windows,freebsd}.go`), feeds C-16 updater |
| L-11 | `util/` | shared utilities: file/log/logrotate, serviceurl, retry, permission, membership, capture, crypt, embeddedroots, netrelay, semaphore-group, `wsproxy/` (JS-only browser transport; council rule: not ported) |

### 8.2 Third-party used libraries

| Group | Module (version) | Used by (upstream paths) | Fork/replace |
|-------|------------------|---------------------------|--------------|
| WireGuard | `golang.zx2c4.com/wireguard` (20231211 snapshot) | `client/iface/device/`, conn state | → `netbirdio/wireguard-go` (replace) |
| WG control | `golang.zx2c4.com/wireguard/wgctrl`, `.../wireguard/windows` v0.5.3 (+wintun), `mdlayher/{netlink,socket,genlink}` | UAPI, wintun, netlink | — |
| ICE/STUN/TURN | `pion/ice/v4`, `pion/{stun/v2,stun/v3,turn/v3,turn/v4,transport,mdns,dtls}` | `client/internal/peer/`, relay client dialer | ice/v4 → `netbirdio/ice/v4` (replace); turn v3 direct + v4 via ice fork |
| QUIC | `quic-go/quic-go` v0.62.0 | relay QUIC dialer (M10), maybe proxy | — |
| gVisor | `gvisor.dev/gvisor` (20260219 snapshot) | `client/iface/netstack/`, uspfilter forwarder (`client/net`, `client/firewall/uspfilter`) | subset used: tcpip/stack/buffer per council cite |
| NAT traversal extras | `netbirdio/go-nat`, `huin/goupnp`, `jackpal/go-nat-pmp` | `client/internal/portforward/` | go-nat already netbirdio |
| DNS | `miekg/dns` v1.1.72 | DNS forwarder/interceptor | — |
| WebSockets | `coder/websocket`, `gobwas/ws` | relay WS dialer, proxy web | — |
| netlink/firewall | `vishvananda/netlink`, `google/nftables`, `coreos/go-iptables`, `ti-mo/{netfilter,conntrack}`, `lrh3321/ipset-go` | routes, fw backends | — |
| TUN | `songgao/water` | non-Linux/mobile TUN paths | Zig side: raw /dev/net/tun already merged |
| Routing selection | `libp2p/go-netroute` | interface binding (`client/net`) | — |
| gRPC stack | `google.golang.org/grpc` v1.80.0, `protobuf` v1.36.11, `grpc-gateway/v2`, grpc middleware v2, otel grpc instrumentation | W-01…W-06 transports | — |
| AuthN/Z | `golang-jwt/jwt/v5`, `go-jose/v4`, `coreos/go-oidc/v3`, `golang.org/x/oauth2` | C-06 auth, S-01 | — |
| IdP SDKs | `okta/okta-sdk-golang/v2`, `goauthentik.io/api/v3`, `dexidp/dex` (+api/v2), `go-ldap/ldap` (indirect) | `management/server/idp/`, `idp/` | dex → netbirdio/dex fork (replace) |
| Stores | `gorm.io/gorm` + drivers sqlite/postgres/mysql, `jackc/pgx/v5`, `mattn/go-sqlite3` (indirect cgo), `go-sql-driver/mysql` (indirect) | S-02 | §6 |
| Cache/queue | `eko/gocache` (+redis store), `redis/go-redis/v9`, `patrickmn/go-cache` | S-01 caching | — |
| Service/OS | `kardianos/service` → netbirdio/service fork, `godbus/dbus/v5`, `ebitengine/purego`, `shirou/gopsutil/v4`, `zcalusic/sysinfo`, `yusufpapurcu/wmi`, `go-ole/go-ole`, `Microsoft/go-winio`, `howett.net/plist`, `skratchdot/open-golang` | service install, system info, MDM | replace for kardianos |
| SSH | `gliderlabs/ssh`, `pkg/sftp`, `creack/pty`, `xanzy/ssh-agent`, `skeema/knownhosts` (indirect) | C-22 | — |
| UI | `wailsapp/wails/v3` v3.0.0-beta.3 → netbirdio/wails fork, `getlantern/systray` → netbirdio/systray fork | P-10 | replaces |
| Mobile | `golang.org/x/mobile` | P-07, P-08 | — |
| Crypto support | `cunicu.li/go-rosenpass` v0.5.42, `cloudflare/circl` → codeberg cunicu/circl (replace), `awnumar/memguard` | C-13, key handling | replaces |
| Observability | `prometheus/client_golang`, otel (otel, sdk/metric, exporters/prometheus), `grafana/pyroscope-go`, `rs/xid`, zap, logrus | metrics in client+servers | — |
| Proxy service support | `caddyserver/certmagic` (+zerossl, acmez), `libdns/{route53,libdns}`, `aws-sdk-go-v2` (s3, route53, config, credentials), `pires/go-proxyproto`, `things-go/go-socks5`, `oschwald/maxminddb-golang`, `crowdsecurity/{crowdsec,go-cs-bouncer}`, `DeRuina/timberjack` | S-07, S-08, geolocation, access log | — |
| Misc | `spf13/cobra`+`pflag`, `gorilla/mux`, `rs/cors`, `google/uuid`, `gopacket` (+gopacket fork), `vmihailenco/msgpack/v5`, `caarlos0/env/v11`, `cenkalti/backoff/v4`, `hashicorp/{go-multierror,go-version,base62}`, `mdp/qrterminal/v3`, `oapi-codegen/runtime`, `mitchellh/hashstructure/v2`, `c-robinson/iplib`, `netbirdio/management-integrations`, `netbirdio/signal-dispatcher`, `petermattis/goid`, `cilium/ebpf`, `fsnotify/fsnotify` | CLI, REST mux, codecs, misc | two netbirdio module replacements |

Scope note: membership in this table is go.mod/go.sum fact (direct requires = used dependencies);
the "Used by" cells outside the council-verified core groups are name-level glosses. Call-site
tracing per module follows when the v0.80 vendor graph lands (below).

Dependency build-graph status: **PENDING** — no `vendor/` for v0.80 (see §0), so
`go list -mod=vendor` cannot enumerate the v0.80 closure. All rows above are go.mod/go.sum +
source-import evidence, not a built closure.

## 9. Packaging, CI and repo-level release config

| ID | Path | Content |
|----|------|---------|
| G-01 | `.goreleaser.yaml` | E-01…E-10 builds, nfpm deb/rpm (post_install/pre_remove scripts, sysconfig), docker_v2 images, brew, checksums, signing pipeline notes (`make_latest: false`) |
| G-02 | `.goreleaser_ui.yaml`, `.goreleaser_ui_darwin.yaml`, `.goreleaser_ui_gtk3.yaml` | UI builds E-11…E-13, polkit policy, desktop file |
| G-03 | `client/Dockerfile*`, per-server Dockerfiles, `client/netbird-entrypoint.sh`, `collect-licenses.sh` (client+proxy) | Container release path |
| G-04 | `client/installer.nsis`, `client/netbird.wxs`, `client/manifest.xml`, `resources.rc` | Windows installers |
| G-05 | `release_files/` (install.sh, post_install.sh, pre_remove.sh, netbird.sysconfig, ui-post-install.sh) | packaged scripts |
| G-06 | `infrastructure_files/` (getting-started*.sh, migrate.sh, migrate-to-enterprise.sh, docker-compose templates, management.json.tmpl, turnserver.conf.tmpl, nginx.tmpl.conf, configure.sh, observability/) | self-hosted deployment templates |
| G-07 | `Makefile` (lint/test-unit/test-privileged), `magefiles/` (magefile.go, test.go), `.github/workflows/`, `e2e/` (agentnetwork, harness, remotejobs), `integration_tests/`, `.devcontainer/`, `crowdin.yml` | build/CI/test orchestration; port-relevant only as reference for the Zig repo's own scripts |

## 10. IMPLEMENTED vs VERIFIED ledger (Zig side)

Verification basis: prior card reports in `~/.cache/netbird-zig-context/results/` (all cited files
end with `STATUS: DONE` unless noted); this card did not re-run any test.

| Zig module | Ref | Status | Verification evidence |
|------------|-----|--------|------------------------|
| `src/proto/wire.zig` | main e92cc5f (PR #22 era work, merged via #76 toolchain) | IMPLEMENTED | impl-proto-glm.md DONE |
| `tools/protogen` (lexer/ast/parser) | main e92cc5f (PR #76) | IMPLEMENTED | impl-protogen-glm.md DONE; generated codecs not yet (PRs #86/#87 open) |
| `src/crypto/keys.zig` | main e92cc5f (PR #16) | IMPLEMENTED | impl-crypto-muse.md DONE; NaCl-box parity PR #17 open |
| `src/state/profile.zig` | main e92cc5f (PR #25 + 5 fix PRs) | IMPLEMENTED | impl-state-muse.md DONE, fix-state-raw-muse.md DONE, m8-profile-dependency-muse.md DONE |
| `src/net/h2/{frame,hpack}.zig` | main e92cc5f (PRs #21/#22) | IMPLEMENTED | impl-h2-muse.md DONE + h2 fix swarm reports |
| `src/net/h2/conn.zig`, `src/net/grpc/*`, `src/mgmt/*`, `src/signal/*`, `src/cli.zig`, `src/engine.zig` | feat/h2-conn 0e1ebaf (PR #23, #104–#106) | UNDER REVIEW (base lane for W01/W06/W07/W08) | impl-grpc-muse.md, impl-m8-*-jcode.md, fix-engine-*.md, review-engine-*.md DONE |
| `src/net/tls/{client,ca}.zig` | main e92cc5f (PR #70) | IMPLEMENTED, **re-verify in flight** | m8-tls-dependency-muse.md was BLOCKED (shared-gate contention, not a defect); W01 card re-runs it |
| `src/relay/messages.zig` | main e92cc5f (PR #84) | IMPLEMENTED | impl-relay-glm.md DONE; relay client #90 open |
| `src/routes/routes.zig` | main e92cc5f (PR #42) | IMPLEMENTED | merged after review; report in results/ (PR #42) |
| `src/tun/tun.zig` | main e92cc5f (PR #41) | IMPLEMENTED | impl-tun-muse.md DONE |
| `src/wireguard/{noise,device,timers,cookie}.zig` + `wgtun_test.zig` | main e92cc5f (PRs #27, #56, #43) | IMPLEMENTED | impl-wg-noise-muse.md, impl-wgdev-muse.md DONE; interop test #38 open |
| `src/ice/{stun,ice,turn}.zig` | feat/ice-turn 1de6f8e (PRs #61/#68/#69) | UNDER REVIEW | impl-ice-muse.md DONE; known >16-channel bug → W04 |
| `src/fw/{model,chains,iptables,filter,nat,fwmark,lock,manager}.zig` | feat/fw-filter b39d7ad (PRs #60/#63–#65) | UNDER REVIEW | impl-fw-muse.md DONE; mangle leak → W05 |
| DNS suite (PRs #75/#85/#88), portforward (PRs #73/#79/#83), ws (#89), relay client (#90), protogen gen (#86/#87) | open PRs | UNDER REVIEW | impl-dns-glm.md, impl-portforward-muse.md DONE |
| `src/main.zig` full dispatch + `src/app.zig` | W06 in flight | NOT STARTED at main (stub only) | W06 card defines the offline boundary |
| `src/daemon/ipcauth.zig` | W07 in flight | NOT STARTED | W07 card |
| `src/auth/device_flow.zig` | W08 in flight | NOT STARTED | W08 card |
| `src/wireguard/runtime.zig` | W03 in flight | NOT STARTED | W03 card |

## 11. Dependency DAG (port order)

Arrow = "must be accepted before". Lane names in parentheses.

```
proto/wire (merged) ──> protogen generated codecs (#86/#87) ──> W-01..W-06 message codecs
crypto/keys (merged) ──> NaCl box (#17) ──> W-08 mgmt/signal payload crypto
net/tls (merged, W01 re-verify) ──> net/h2 frame+hpack (merged) ──> net/h2 conn (#23)
  ──> net/grpc (#23 feat/h2-conn) ──> mgmt client + signal client (#23)
net/ws (#89) ──> relay client (#90) ──> relay manager
tun (merged) + wireguard device/noise/timers/cookie (merged) ──> W03 wg runtime ──> iface/UAPI (C-11)
ice/stun (#61) ──> ice/ice (#68) ──> ice/turn (#69 + W04) ──> peer ICE (C-04)
routes (merged) ──> routemanager (C-08)
fw model/chains (#60) ──> fw filter (#63 + W05) ──> fw nat (#64) ──> fw manager
dns codec (#75) ──> dns resolver (#85) ──> dns resolv.conf backend (#88) ──> dns service (C-07)
state/profile (merged) + state-manager (#26) ──> W06 main/app dispatch ──> CLI surface (C-01)
W08 device flow ──> auth full (C-06) ──> login
mgmt+signal+relay+ice+wg+dns+routes+fw ──> engine (C-03, feat/h2-conn) ──> daemon server (C-02)
daemon/ipcauth (W07) ──> daemon server privilege boundary
daemon server ──> DaemonService 46 RPCs (W-04) ──> CLI parity (M15) ──> UI/mobile SDK surfaces (P-07/08/10)
[server track M17] W-01/W-06 servers: signal (S-04) -> relay (S-05) -> management (S-01 + D-01..D-07)
  -> combined (S-06) -> proxy (S-07 + W-02) -> upload (S-08) -> idp (S-09)
[platforms M18] P-04 windows / P-05 darwin / P-06 freebsd / P-07 android / P-08 ios / P-09 wasm
[M13] rosenpass, [M14] netflow/lazyconn/ebpf, [M15] updater/metrics, [M16] gVisor netstack
```

Milestone map (PLAN.md M1–M18) ↔ sections: M1→W-01..W-08+protogen; M2→crypto/state; M3→tls/h2/grpc/mgmt/signal;
M4→wg+tun+W03; M5→relay (#90/#89); M6→ice (#61/#68/#69+W04)+portforward (#73/#79/#83); M7→dns (#75/#85/#88)+
routes+fw (#60/#63+W05); M8→engine+CLI+W06; M9→daemon+W07; M10→QUIC dialer; M11→W08+PKCE; M12→C-22 SSH;
M13→C-13; M14→C-14/C-15/lazyconn; M15→C-16/C-17/CLI parity; M16→P-03/C-24 uspfilter forwarder;
M17→S-01…S-10+§6; M18→P-04…P-10.

## 12. Unresolved prerequisites (concrete)

1. **v0.80 vendor absent** — dependency build graph PENDING (§8). Needed: lead-approved
   `fetch-upstream.sh` update to pin v0.80.0 and vendor it, then `go list -mod=vendor` for the
   exact per-binary dependency closure (client linux/arm64 first, then servers).
2. **CGO vs no-C rule** — E-04 (management), E-07 (combined), E-10 (idp-migrate), E-11…E-13 (UI)
   build with `CGO_ENABLED=1` because of `mattn/go-sqlite3` (D-01), Dex sqlite (D-07) and Wails/GTK
   (P-10). The repo hard rule forbids C code and `-lc`. Decision required before M17: pure-Zig
   SQLite (port), Postgres-only server, or a scoped exception. This also gates D-02/D-03/D-04.
3. **Arch breadth** — release ships arm/6, armv7, 386, mips/mipsle/mips64(le) hard+softfloat; the
   Zig port only has an aarch64-linux-musl path today. Cards needed for each extra GOARCH if release
   parity is wanted; KN-3812 itself needs only arm64.
4. **Kernel 4.9 (KN-3812)** — statx/io_uring workaround already in AGENTS.md; `cilium/ebpf`-based
   wgproxy (C-15) is expected N/A on 4.9 (no usable eBPF in the stock Keenetic kernel); lazyconn and
   netstack paths need a 4.9 syscall audit when carded.
5. **Windows/macOS/mobile/WASM** — no Zig cards yet (P-04…P-09). Named-pipe IPC, wintun loading,
   gomobile bindings and js/wasm build are net-new Zig surface, each needs its own card.
6. **UI stack** — Wails v3 + React + GTK3/GTK4 cgo (P-10) has no Zig decision recorded; treat as a
   separate lane decision (system webview, rewrite, or defer), independent of the daemon.
7. **proto generated surface** — daemon.pb.gw.go (167 KB REST gateway over IPC) and the 500 KB
   OpenAPI schema (W-07) must be generated, not hand-ported; protogen (#86/#87) needs to cover
   grpc-gateway output or the REST surface needs a scoping decision.
8. **signal-dispatcher and management-integrations** — netbirdio-owned Go modules consumed by
   management (§8); treat as upstream sources to port, not vendored black boxes.

## Appendix A — evidence commands (this card)

- `git rev-parse HEAD` in upstream-v080 → `fca64287cf51a85552a41b022013abbfdb335452`; in W02 → `e92cc5fdd7602ac14bec2d0213767f081fe56e5a`.
- `grep '^func main('` over upstream-v080 → the 16 main packages listed in §1.
- Directory listings of every path cited above (client/**, management/**, signal, relay, combined,
  proxy, upload-server, idp, shared/**, flow, dns, route, encryption, stun, sharedsock, trustedproxy,
  infrastructure_files, e2e, magefiles).
- RPC extraction: `grep '^service |^  rpc '` on management.proto, proxy_service.proto, daemon.proto,
  signalexchange.proto, flow.proto (§7).
- Store evidence: grep on `management/server/store/sql_store.go` (§6).
- Release matrix: read `.goreleaser.yaml`, `.goreleaser_ui*.yaml` (§1, §9).
- Zig state: `git log --oneline -60` at e92cc5f; `git diff --name-only main...origin/{feat/h2-conn,
  feat/ice-turn,feat/fw-filter}`; `gh pr list --state open` (§2, §10).
- Lane table: run.json + tasks/W0*.md cards (§2).
