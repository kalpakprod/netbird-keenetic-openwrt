$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Review Muse's M2 crypto PRs #16 (keys) and #17 (NaCl box) against upstream and merge each on approval.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Reference: upstream/netbird/encryption/*.go, vendor/golang.zx2c4.com/wireguard/wgctrl/wgtypes/types.go.</workspace>
  <authority>GitHub review comments and scripts/merge-pr.sh for PRs #16 and #17 only. Temporary worktrees under ~/.cache/netbird-zig-context/. No other file changes, no installs, no ssh.</authority>
  <steps>1. git fetch origin; for each PR make a temporary worktree of origin/<branch> (gh pr view N --json headRefName). 2. Compare the Zig code with the Go sources: nonce layout, encoding, key clamping, base64 forms, error cases. 3. In the worktree run zig build test and zig test on the PR's test files; paste output. 4. gh pr review N --comment -b '<ДА/НЕТ + findings file:line>'. 5. On ДА run scripts/merge-pr.sh N (keys #16 first, then box #17). On НЕТ leave it for Muse (max two rounds). 6. Remove the worktrees.</steps>
  <rules>Facts from files and commands you ran. If a step is impossible, write BLOCKED with the reason.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/xreview-glm2.md: verdict per PR, findings, test output, merge result, author model, progress lines. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
