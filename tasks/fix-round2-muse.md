$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>Second (last) round on your PRs that got НЕТ: fix every blocking finding, push to the same branch, answer on the PR. Then make CI run the namespace tests instead of skipping them.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first. Reference: upstream/netbird (with vendor/).</workspace>
  <authority>Only the files each PR already changes, through fix PRs into that PR's branch, plus .github/workflows/zig.yml on a new branch for step 3. Must not: commit on main, merge your own PR, force-push except --force-with-lease on your own feature branch, install anything, ssh anywhere, use root, touch other files.</authority>
  <context>
    PRs with НЕТ and their reviewers: #17 crypto box (GLM), #3 WireGuard noise (GLM), #21 HPACK, #22 frames, #23 h2 connection, #25 profile, #26 state manager, #27 WG timers (Codex). Read the LAST verdict comment on each (gh pr view N --comments); earlier comments may be superseded.
    #25: your report said Zig 0.17 std has no public env API. That is wrong: std.process.Init carries environ_map (lib/std/process.zig:45), and Environ.Map.get exists (lib/std/process/Environ.zig:286), under ~/.local/share/mise/installs/zig/0.17.0/lib/std. Pass the map from main down to the profile code; remove the /proc/self/environ scan.
  </context>
  <steps>
    1. Order: #17, #3, #21, #22, #23, #25, #26, #27. For each: git fetch origin; worktree on origin/&lt;branch&gt;; fix only the blocking findings; findings the reviewer marked Backlog stay out. Add or extend a test that fails before the fix and passes after, and show both runs. Run every *_test.zig the PR touches natively and with -target aarch64-linux-musl -fno-emit-bin. Each finding is its own fix PR into that branch (owner 2026-10-04), never a push to the reviewed branch: `BASE=&lt;branch&gt; SRC=&lt;worktree&gt; scripts/pr.sh fix/&lt;short-name&gt; "fix(&lt;module&gt;): &lt;finding&gt; (review of #N)" &lt;paths&gt;`. If PR #40 (test discovery) is merged by then, a separate PR merging origin/main into the branch lets CI run the tests. Comment on the original PR: finding → fix PR URL → test output.
    2. Rebase or merge #37 and #38 onto the fixed #27 if they contain its files, so they do not reintroduce the old code.
    3. New branch ci/namespace-tests: in .github/workflows/zig.yml run the tests that need a network namespace under `unshare -Urn` on the GitHub runner (if the runner blocks unprivileged user namespaces, allow them with the documented sysctl via sudo inside the CI job only). CI log must show those tests passed, not skipped. PR through scripts/pr.sh.
  </steps>
  <rules>Real changes only, no empty commits. If a finding is wrong, say why on the PR with evidence instead of changing code. Load limits from AGENTS.md. Facts from commands you ran. If a step is impossible, write BLOCKED with the reason and continue with the next PR.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/fix-round2-muse.md: per PR: findings, changes, test before/after, comment URL; CI PR URL with the log line showing namespace tests passed; Not verified; author model; a progress line after each PR (never starting with STATUS:). Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
