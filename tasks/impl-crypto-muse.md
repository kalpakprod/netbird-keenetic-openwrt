$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>M2 crypto: NaCl box encrypt/decrypt and WireGuard key types in pure Zig, interoperable with netbird encryption/ and wgtypes.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first (PR rules changed: every change goes through scripts/pr.sh). Plan: PLAN.md and council/r3-merged.md. Reference: upstream/netbird (with vendor/), Zig std at `mise where zig`/lib/std.</workspace>
  <authority>May create or change only: src/crypto/box.zig, src/crypto/keys.zig, src/crypto/box_test.zig, src/crypto/keys_test.zig, src/crypto/testdata/*. May run gh for this repo (pr, issue, review). Must not: commit on main, push main, install anything, ssh anywhere, touch other files. Load limits from AGENTS.md apply.</authority>
  <steps>1. Read upstream/netbird/encryption/*.go (non-test) and vendor/golang.zx2c4.com/wireguard/wgctrl/wgtypes/types.go. 2. Port: key generation, base64 parse/format, public from private (X25519), and EncryptMessage/DecryptMessage semantics (nonce layout, encoding) using std.crypto.nacl.Box. Header comments per AGENTS.md. 3. Vectors: a Go helper in ~/.cache/netbird-zig-context/gen/ (not in repo) using the upstream encryption package prints key pairs and ciphertexts; save them as src/crypto/testdata/vectors.json. Tests: decrypt Go ciphertext in Zig, encrypt in Zig and decrypt in Go (helper reads Zig output), key round-trips. 4. Run: zig test src/crypto/box_test.zig and zig test src/crypto/keys_test.zig; paste output. 5. Open two PRs (keys first, then box): scripts/pr.sh feat/crypto-keys ... and feat/crypto-box ... , body 'Part of #<M2 issue>' using the issue table from /home/kukuruza/.cache/netbird-zig-context/results/issues-muse.md.</steps>
  <rules>Real changes only, never empty or cosmetic commits to inflate activity. Facts from files and commands you ran. If a step is impossible, write BLOCKED with the reason. Every "works" claim carries the command and its output.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/impl-crypto-muse.md: one-line result, files, PR/issue URLs, commands with output, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
