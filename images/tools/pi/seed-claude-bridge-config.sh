#!/bin/sh
# First-boot seed hook (run.rs's RUN_IMAGE_SEED_HOOKS runs every executable
# under /opt/agent-vm/seed.d/ before exec'ing the agent).
#
# Point the image-owned pi-claude-bridge at the image's own Claude Code binary.
# agent-vm created this condition itself: images/tools/pi/Dockerfile installs
# the bridge with `--omit=optional`, deliberately dropping the Claude Agent
# SDK's platform packages (each carries a whole second Claude Code; see
# docs/adr/0023-image-owned-pi-extension-packages.md for the guest-platform
# size) in favour of the one the claude layer already ships at
# /opt/agent/.local/bin/claude. So agent-vm is the one that repairs it -- the
# parity principle (ADR-0021), not a policy agent-vm is imposing on Pi.
# Without this the SDK throws "Native CLI binary for <platform>-<arch> not
# found" on every bridge turn.
#
# The bridge reads the key from `~/.pi/agent/claude-bridge.json`, i.e. the
# project-scoped state dir this guest maps `~/.pi` onto (ADR-0021). Merge only
# that one key and preserve everything else, so a user's own edits -- including
# the bridge's own `startupNoticeShown` -- survive. There is no once-marker:
# run.rs runs every seed.d hook on every boot, so a user who CHANGES the value
# has their change honoured, but a user who REMOVES it gets it re-added -- the
# bridge cannot run without it (USAGE.md says so too).
#
# seed.d hooks are verb-agnostic (run.rs's RUN_IMAGE_SEED_HOOKS), so this writes
# `claude-bridge.json` on every verb, not just `pi`. That is intended: the state
# dir is per project, and the file is a path, not a credential.
#
# Best-effort throughout: this must never fail a launch. It exits 0 without
# writing when the claude layer is absent (a custom catalog), when Pi state has
# not been provisioned -- a defensive guard for running this image outside
# agent-vm; under agent-vm GENERIC_EAGER_STATE_DIRS creates `<state>/pi` before
# every launch, so that branch is not taken -- when node is unavailable, or when
# the file already carries a path. A file that does not parse is left
# byte-identical rather than clobbered -- the same care the bridge's own
# `markStartupNoticeShown` takes. The write goes to a sibling temp file that is
# renamed into place, so a write that fails part-way (ENOSPC, SIGXFSZ, an OOM)
# leaves the original intact rather than truncated.
CLAUDE=/opt/agent/.local/bin/claude
CONFIG=/agent-vm-state/pi/agent/claude-bridge.json
[ -x "$CLAUDE" ] || exit 0
[ -d /agent-vm-state/pi ] || exit 0
command -v node >/dev/null 2>&1 || exit 0
mkdir -p /agent-vm-state/pi/agent 2>/dev/null || exit 0
# shellcheck disable=SC2016  # the JS must reach node verbatim, not expand here
node -e '
const fs = require("fs");
// With `node -e CODE a b`, user args start at argv[1] (no script path slot).
const [, path, claude] = process.argv;
let cfg = {};
if (fs.existsSync(path)) {
  try { cfg = JSON.parse(fs.readFileSync(path, "utf8")); }
  catch (e) { process.exit(0); }              // unparseable: leave it alone
}
if (typeof cfg !== "object" || cfg === null || Array.isArray(cfg)) process.exit(0);
if (cfg.provider !== undefined
    && (typeof cfg.provider !== "object" || cfg.provider === null || Array.isArray(cfg.provider))) {
  process.exit(0);                            // unexpected shape: leave it alone
}
cfg.provider = cfg.provider || {};
if (cfg.provider.pathToClaudeCodeExecutable) process.exit(0);
cfg.provider.pathToClaudeCodeExecutable = claude;
// Write to a sibling temp file and rename: rename() is atomic within a
// directory on POSIX, so a partial write cannot leave a truncated config.
const tmp = path + ".agent-vm.tmp";
// The rename swaps the inode, so the temp file would otherwise take its mode
// from the process umask instead of the original -- carry that mode across.
const mode = fs.existsSync(path) ? fs.statSync(path).mode & 0o777 : undefined;
fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + "\n");
if (mode !== undefined) fs.chmodSync(tmp, mode);
fs.renameSync(tmp, path);
' "$CONFIG" "$CLAUDE" 2>/dev/null || true
exit 0
