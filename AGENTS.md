# AGENTS.md — rules for every worker in this repo

Goal: a complete port of NetBird to Zig, written from the Go sources. First the client
(everything that runs on a router), then its Go libraries (wireguard-go, ICE, gRPC, protobuf),
then the servers (management, signal, relay). Owner order 2026-10-03: port everything, size does not matter.
Repo = kalpakprod/netbird-keenetic-openwrt (installer install.sh + Zig client). Do not touch install.sh, uninstall.sh, tests/, .github/ unless a card says so.
The lead (Claude session) owns PLAN.md, decisions, commits and pushes. Workers execute task cards in tasks/.

## Target
- Zig 0.17.0 (pinned in mise.toml). No C code, no `-lc`, no cgo. Build: `zig build-exe ... -target aarch64-linux-musl`.
- Main device: Keenetic KN-3812, aarch64, Linux 4.9, no 32-bit mode, ~44 MB RAM free, flash tight.
- Zig officially supports Linux 5.10+. Kernel 4.9 lacks syscalls newer than 4.9: statx (4.11), io_uring (5.1),
  clone3 and pidfd_* (5.3), openat2 (5.6), faccessat2 (5.8), close_range (5.9), epoll_pwait2 (5.11).
  Checked 2026-10-03: Zig std calls statx from File.stat and File.Reader.getSize. Workaround used on the router:
  get the size with `std.os.linux.lseek(fd, 0, SEEK.END)` and set `reader.size` (see docs/kernel-4.9.md when written).
- Find the syscalls of an arm64 build: `qemu-aarch64-static -strace ./bin 2>&1 | grep -oE '^[0-9]+ [a-z_0-9]+' | sort -u`.
- Baseline to beat (Go NetBird 0.79.0 on the router, measured 2026-10-03): RSS 24.1 MB + 6.7 MB swap, peak 53.6 MB, binary 40 MB.

## Sources
- `scripts/fetch-upstream.sh` puts NetBird v0.79.0 in `upstream/netbird` with every Go dependency in `upstream/netbird/vendor`.
  `upstream/` is read-only reference and is not committed.
- Packages compiled into the Linux arm64 client:
  `cd upstream/netbird && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go list -mod=vendor -deps -f '{{if not .Standard}}{{.ImportPath}} {{.Dir}}{{end}}' ./client`
- License: this repo is MIT (installer); ported NetBird code is BSD-3-Clause (LICENSES/netbird-BSD-3-Clause.txt); management/, signal/, relay/, combined/ are AGPLv3. Ported files keep the
  origin path in a header comment: `// Port of netbird <path> (v0.79.0), BSD-3-Clause` (or AGPL-3.0 for server dirs).

## Council (GLM and Muse consult each other)
- Round 1: each agent writes its own proposal `council/r1-<agent>.md` without reading the other's.
- Round 2: each reads the other's proposal and writes `council/r2-<agent>-on-<other>.md`: agree, disagree with evidence, merged proposal.
- Implementation: every change by one agent is reviewed by the other agent (different model family) before the lead accepts it.
- Disagreements go to the lead with evidence. Workers never decide scope.

## Hard rules
- Never touch production: no ssh to routers or servers, no NetBird accounts, no real setup keys, no netbird.cloud logins.
  Integration tests run only against local stubs or a local upstream stack the lead provides.
- No commits, pushes, branch switches or worktrees. The lead commits.
- No new tools or packages (pip, npm, pacman, go install) without the lead. `go list`, `go test` on upstream code, zig, qemu are allowed.
- Machine load: before any heavy command check `/proc/loadavg` and `/proc/pressure/io`; wait if 1-min load > 12 or IO full avg10 > 5.
  One heavy command at a time. Test only your own files, never a whole suite.
- Every claim of "done/works" carries the command and its output. Anything not run goes to "Not verified".
- Reports: `~/.cache/netbird-zig-context/results/<card>.md`, progress line after each step, last line `STATUS: DONE` or `STATUS: BLOCKED`.
