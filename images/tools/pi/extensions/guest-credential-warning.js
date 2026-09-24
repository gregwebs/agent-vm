// The one Pi extension the agent-vm wrapper always loads explicitly, so
// `--no-extensions` cannot silence it and no project state can remove it. See
// docs/adr/0012-stable-pi-image-customization-seam.md.
//
// Plain ESM, zero imports, zero npm dependencies, on purpose: Pi loads it
// through jiti with no `node_modules` beside it and no writable directory (the
// file lives under a root-owned /opt).
//
// This is an advisory, not a boundary. The microVM is the boundary; a guest
// that wants to can invoke the Pi entry point directly. The mixed-ownership
// rationale the text summarises is [#93](https://github.com/gregwebs/agent-vm/issues/93);
// the Pi-`auth.json` host-import half it reserves room for is
// [#91](https://github.com/gregwebs/agent-vm/issues/91), still open.
//
// The text is scoped to what #95 and #96 deliver: signing in writes a
// credential into THIS project's persistent guest state (the project-scoped
// <state>/pi mapping from #96), any process in this guest can read it, and the
// microVM is the boundary. It deliberately does NOT claim host-credential
// precedence or host import: those clauses would describe *Pi's own*
// `~/.pi/agent/auth.json`, and #94 (Anthropic through host Pi) was closed as
// superseded by #164 -- which imports a **different** credential (Claude Code's)
// into a **different** file (`~/.claude/.credentials.json`) through the `pi ->
// claude` provisioning edge. #91 (OpenAI and Codex credentials through host Pi)
// is still open, so those clauses stay reserved for it. Since #164 a `pi`
// launch does provision the Anthropic/Claude-Code credential, but this warning
// is about Pi's own sign-in and says nothing about it; see
// docs/adr/0023-image-owned-pi-extension-packages.md.
//
// #93 added a *separate*, host-side surface: `agent-vm` reports EXISTING
// guest-managed Pi state on every launch, and `agent-vm doctor` shows the same
// facts. That report is complementary to this future-sign-in advisory, runs
// whether or not Pi starts, and does not inherit this `hasUI` gate -- so the
// two must not be merged into one message.

const WARNING = [
  "agent-vm: signing in here (for example with /login) writes a credential into",
  "THIS project's persistent guest state, where any process in this guest can",
  "read it. The microVM -- not this warning -- is the boundary.",
].join(" ");

export default function (pi) {
  pi.on("session_start", (_event, ctx) => {
    // hasUI is true exactly for the two modes a human reads (tui, rpc) and
    // false for print and json, whose stdout is consumed by programs. One
    // predicate, so "suppress in print/json" is not a second mechanism.
    if (!ctx.hasUI) {
      return;
    }
    ctx.ui.notify(WARNING, "warning");
  });
}
