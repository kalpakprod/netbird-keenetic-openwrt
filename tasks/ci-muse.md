$stop-that-shit change -- Execute this task card exactly.

```xml
<task>
  <goal>GitHub Actions CI for the Zig project: build and test on every push and PR.</goal>
  <workspace>/home/kukuruza/orca/projects/netbird-zig-keenetic-openwrt. Read AGENTS.md first (PR rules changed: every change goes through scripts/pr.sh). Plan: PLAN.md and council/r3-merged.md. Reference: upstream/netbird (with vendor/), Zig std at `mise where zig`/lib/std.</workspace>
  <authority>May create or change only: .github/workflows/zig.yml. May run gh for this repo (pr, issue, review). Must not: commit on main, push main, install anything, ssh anywhere, touch other files. Load limits from AGENTS.md apply.</authority>
  <steps>1. Write .github/workflows/zig.yml: triggers push to main and pull_request; ubuntu-latest; install Zig 0.17.0 with mlugg/setup-zig (pin a release tag, version 0.17.0); run 'zig build test' and 'zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSmall'; upload zig-out/bin/netbird as an artifact. Do not touch the existing ci.yml. 2. Check the YAML locally: python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/zig.yml"))'. 3. Open the PR with scripts/pr.sh ci/zig-build "ci: build and test the Zig client" .github/workflows/zig.yml. 4. Wait for the PR checks (gh pr checks <n> --watch, max 15 min) and paste the result. If the Zig job fails, fix the workflow on the same branch (push to it from a worktree like scripts/pr.sh does) up to two times.</steps>
  <rules>Real changes only, never empty or cosmetic commits to inflate activity. Facts from files and commands you ran. If a step is impossible, write BLOCKED with the reason. Every "works" claim carries the command and its output.</rules>
  <deliverable>Report /home/kukuruza/.cache/netbird-zig-context/results/ci-muse.md: one-line result, files, PR/issue URLs, commands with output, Not verified list, author model, progress line after each step. Last line: STATUS: DONE or STATUS: BLOCKED.</deliverable>
</task>
```
