$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Three parts in order. A: fix the latent compile error in PR #25. B: make `zig build test` compile and run every test file under src/, so CI catches what it misses today. C: M4 (#7) second part: TUN device and minimal rtnetlink (link up, address, route), then WireGuard over TUN between two network namespaces.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Plan: PLAN.md and council/r3-merged.md. Reference: upstream/netbird (with vendor/).</workspace>
  <authority>
    A: branch feat/state-profile (PR #25) only: src/state/profile.zig and its test. Your own finding: it calls std.process.getEnvVarOwned, which Zig 0.17 std does not have.
    B: build.zig only, new branch build/test-discovery through scripts/pr.sh. The test step must discover every src/**/*_test.zig (no hand list that PRs must edit) and run it natively; `zig build test -Dtarget=aarch64-linux-musl` must compile the same set. Tests that need a Go helper return error.SkipZigTest when the helper is absent and show as skipped, never as passed.
    C: may create src/tun/** and src/routes/** and a glue file under src/wg/ if needed. Go helpers only under ~/.cache/netbird-zig-context/gen/.
    All parts: PRs through scripts/pr.sh, one PR per logical step, each with passing tests; body 'Part of #7' for C. Namespaces only through unshare -Urn (user + network namespace, no root). Must not: commit on main, merge your own PR, install anything, ssh anywhere, use sudo/pkexec/root, touch the host network, touch other files.
  </authority>
  <context>Router facts (verified by the lead): kernel 4.9 aarch64, no nft, /opt/sbin/iptables v1.4.21. Go NetBird there runs the userspace WireGuard device over TUN. Upstream refs: client/iface/device/device_usp_unix.go, client/iface/iface_new_linux.go, client/iface/wgaddr/, client/internal/routemanager/systemops/systemops_linux.go. Kernel 4.9 has rtnetlink and TUNSETIFF; do not use syscalls newer than 4.9 (list in AGENTS.md).</context>
  <steps>
    1. A: gh pr view 25 for the branch; git fetch origin; worktree on origin/feat/state-profile; replace getEnvVarOwned with the 0.17 environment API; zig test the state files; push to that branch; comment on #25 what changed.
    2. B: test discovery in build.zig; run `zig build test` and `zig build test -Dtarget=aarch64-linux-musl` on origin/main plus on one open PR branch merged locally (not pushed) to show discovery picks its tests; PR.
    3. C1: src/tun/: open /dev/net/tun, TUNSETIFF with IFF_TUN|IFF_NO_PI, read/write packets, set MTU. Test inside unshare -Urn: create tun, write an ICMP echo request to the tun address, read the kernel's echo reply back. PR.
    4. C2: src/routes/: rtnetlink over a raw NETLINK_ROUTE socket: link up/down, add/delete IPv4 address, add/delete route. Test inside unshare -Urn, read back with `ip -j addr` and `ip -j route`. PR.
    5. C3: WireGuard over TUN: Zig device (src/wg) on a tun in namespace A, wireguard-go with a real tun in namespace B (veth or UDP over a shared namespace, your choice, write it in the PR), ping from A to B's tunnel address and back succeeds. PR.
  </steps>
  <rules>Real changes only, no empty commits. Before pushing to an existing branch: git fetch origin and base on origin/&lt;branch&gt;. Load limits from AGENTS.md: check /proc/loadavg before heavy builds, one heavy command at a time. Facts from commands you ran. If a step is impossible, write BLOCKED with the reason and continue with the next independent step.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/impl-tun-muse.md: one-line result, files, PR URLs, commands with output, Not verified list, author model, a progress line after each step (never starting with STATUS:). Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
