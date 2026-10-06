# Full stable NetBird v0.80.0 release — approved 2026-10-05

## Fixed acceptance contract

Port all NetBird v0.80.0 functionality to Zig: clients, every used library behavior, servers, desktop/mobile/WASM/platform code, tools, installation and upgrade. Unused third-party APIs are outside scope. No alpha/beta releases. No feature is deferred past this release. Compatible CLI/IPC/wire/config/state/server data; real scenarios on final artifacts. Go is a test/reference tool only, never a shipped implementation fallback. Keep Zig 0.17.0 and pure Zig/no C/cgo/-lc constraints, especially aarch64-linux-musl on Linux 4.9.

Reference: v0.80.0 commit fca64287cf51a85552a41b022013abbfdb335452; original v0.79.0 396795ebb6822402ad4eff88c90682d99f77d987 retained read-only. Pin dependency versions from v0.80 go.mod/go.sum. Existing inventory and reports are not proof of full v0.80 acceptance.

## Execution and ownership

Lead owns scope/interfaces/PLAN/review/acceptance and does not implement modules. Pool: W01 transport Muse; W02 protobuf/state GLM; W03 WG/TUN Muse; W04 ICE/NAT Muse; W05 DNS/routes/firewall GLM; W06 engine/peers/integration Muse; W07 CLI/daemon/updater/metrics GLM; W08 crypto/auth/SSH/Rosenpass Muse; W09 netstack/forwarding/eBPF/flow/proxy/WASM Muse; W10 stores/drivers/migrations Muse; W11 management/API/tools GLM; W12 test stand/package/CI/docs GLM. Start W01-W08; expand to 12 ready disjoint cards, max 5 GLM. Separate worktrees, one writer per file, explicit owned paths per card. User approved Muse Contributor variant on 2026-10-05. Model identifiers come from harness/contour/models.json.

Lead reviews all normal PRs; add one Sol6.1 reviewer at 3 ready PRs or a dependency waiting on review. At 6 ready PRs prioritize fixes/review preparation over new work. No duplicate reviews of every PR. New author fixes are separate PRs into the reviewed branch; two failed rounds escalate to lead, defect remains open. Reviewed PRs merge through scripts/merge-pr.sh from a clean coordinator copy; never reset/overwrite dirty shared checkout. Worker DONE closes only its card.

## Release DAG

0. Full source/feature/dependency/platform inventory; accepted PR disposition; early SQLite-without-C and compiler/platform feasibility checks.
1. Real router client: accepted TLS/H2/gRPC/mgmt/signal plus WG/TUN/ICE/relay/DNS/routes/firewall, actual CLI/engine and daemon IPC. Full local up/login/status/down + direct/relay traffic + restart acceptance; internal build only.
2. All remaining client/library capabilities: QUIC, SSO/OIDC, SSH/SFTP, Rosenpass, netstack/uspfilter/SOCKS, lazyconn, flow/netflow/eBPF, complete CLI/daemon, metrics/updater/diagnostics. Zero runtime stubs in accepted feature scope.
3. All server functions: management/signal/relay/combined/proxy/upload, IdP/certificates/DNS provider integration/tools, SQLite/PostgreSQL/MySQL storage + transaction/migration/data compatibility. Validate Zig client with Go servers, Go client with Zig servers, then all-Zig stack.
4. Every supported upstream target: Linux/router archs, Windows/macOS, Android/iOS, WASM and other supported targets identified from actual source/build/release configurations. W03 Windows, W04 macOS, W05 Linux/POSIX/router, W06 Android, W07 iOS, W08 desktop UI/tray Go backends, W09 WASM, W12 packages/runners. Native behavior checks required; compile-only is not runtime acceptance.
5. Usable packages: real installation, autostart, upgrade, Go-to-Zig identity/config migration, uninstall/rollback, updater uses port artifacts, licenses/source notices/checksums. W12 cards explicitly authorize relevant installer/tests/.github changes. No hidden Go fallback.
6. Fresh Sol6.1 whole-product review on pinned commit and final packaged artifacts. Final sequential test gate, 24h normal local traffic/reconnect soak, platform execution, router Linux4.9/RAM/flash acceptance. Fix findings with targeted reruns; re-run full gate only when shared changes invalidate its evidence.
7. Stable publication only after owner approves the concrete reviewed artifacts. No production/router access by workers or real keys/accounts; test hardware/physical actions remain owner's authority.

## Verification and release gate

Every feature maps upstream path → Zig owner/module → prerequisites → scenario → command/output + exact source/artifact SHA. States: not_started/implementation/review/integration/verified. No claimed verified state from file presence, mocks replacing the subject, skipped live tests or cross-compilation. Protobuf/crypto/JSON vectors come from upstream; integration uses isolated local upstream stack. Kernel tests must preflight isolation before host changes. QEMU user strace inventories calls but does not emulate kernel4.9: test on actual test router or full VM with that kernel. Record RSS/peak/swap/binary/flash and require usable installation without OOM.

All heavy work serialized with existing sh ~/.cache/netbird-zig-context/swarm-heavy.sh; load1<=12 and IO full avg10<=5. Authors run only owned tests. Final full gate is lead-controlled, sequential. Required missing runners/SQLite compatibility/toolchain targets stay blockers, not exclusions.

Release requires 100% accepted feature inventory implemented and verified, all required checks on final artifact, no known unresolved in-scope defect, working installation/migration/update/rollback, Sol6.1 whole-product DA, complete licensing/artifacts. Calendar forecast follows full inventory and two accepted implementation batches; update from measured critical-path throughput.

## Initial execution (2026-10-05)

Coordinator run data/tasks/reports: /home/kukuruza/.cache/netbird-zig-context/release-v080-20261005. Exact v0.80 upstream fetched and isolated without touching old reference. New writer worktrees created on committed refs, dirty root retained. First cards: accepted TLS dependency, full inventory, WG UDP/TUN runtime, TURN channel capacity fix (#69), firewall mangle lifetime fix (#63), executable dispatch prerequisite, Linux IPC peer credentials, OIDC device flow. Feature completion and first PRs remain pending; no whole-product readiness claimed.
