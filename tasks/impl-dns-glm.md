$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>M7 (#10) DNS part: DNS wire codec, the local resolver NetBird runs on the tunnel address, upstream forwarding, and the Linux resolv.conf backend.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Plan: PLAN.md and council/r3-merged.md. Reference: upstream/netbird (with vendor/).</workspace>
  <authority>May create src/dns/** only. Go helpers only under ~/.cache/netbird-zig-context/gen/. Tests on 127.0.0.1 high ports or inside unshare -Urn; never edit the host /etc/resolv.conf (use a temp file path in tests). PRs through scripts/pr.sh, body 'Part of #10'. Must not: commit on main, merge your own PR, install anything, ssh anywhere, use sudo/pkexec/root, touch the host network or other files.</authority>
  <context>Upstream: client/internal/dns/ (server.go, server_unix.go, handler_chain.go, upstream.go, local/, file_unix.go, resolvconf_unix.go, host_unix.go), client/internal/dnsfwd/. Router: Keenetic has its own dnsmasq-like resolver and no systemd-resolved or NetworkManager; port the file/resolvconf path only, other backends are M14+. Wire vectors from vendor/github.com/miekg/dns.</context>
  <steps>1. DNS message codec (header, questions, A/AAAA/CNAME/TXT/SRV/PTR, compression pointers, EDNS0), vectors from miekg/dns both ways, malformed input tests. PR. 2. Handler chain + local records + upstream forwarder with timeout and fallback; test with dig against the Zig server on a high port. PR. 3. resolv.conf file backend with backup and restore on a temp path. PR.</steps>
  <rules>Real changes only, no empty commits, one PR per logical step. Review fixes follow AGENTS.md (a fix PR per finding into the reviewed branch). Load limits from AGENTS.md: before zig/go builds check /proc/loadavg and wait while the 1-min load is above 12; one heavy command at a time. Facts from commands you ran. If a step is impossible, write BLOCKED with the reason and continue with the next independent step.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/impl-dns-glm.md: one-line result, files, PR URLs, commands with output, Not verified list, author model, a progress line after each step (never starting with STATUS:). Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
