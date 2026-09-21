// The one Pi extension the agent-vm wrapper always loads explicitly, so
// `--no-extensions` cannot silence it and no project state can remove it. See
// docs/adr/0012-stable-pi-image-customization-seam.md.
//
// Plain ESM, zero imports, zero npm dependencies, on purpose: Pi loads it
// through jiti with no `node_modules` beside it and no writable directory (the
// file lives under a root-owned /opt).
//
// This is an advisory, not a boundary. The microVM is the boundary; a guest
// that wants to can invoke the Pi entry point directly. See issue #94 for the
// mixed-ownership rationale the text summarises.
//
// The text is scoped to what #95 and #96 deliver: signing in writes a
// credential into THIS project's persistent guest state (the project-scoped
// <state>/pi mapping from #96), any process in this guest can read it, and the
// microVM is the boundary. It deliberately does NOT claim host-credential
// precedence or host import -- #94/#91 still owe those clauses to this message
// and to script/test/pi-layer-runtime.sh's assertions, which will restore them
// together with their behaviour.

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
