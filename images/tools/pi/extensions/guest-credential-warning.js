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
// The text is scoped to what issue #95 actually delivers: signing in writes a
// credential any process in this guest can read, and the microVM is the
// boundary. It deliberately does NOT claim persistence, host-credential
// precedence, or host import -- none of those behaviours exist yet. #96 lands
// the ~/.pi persistence mapping (and the root-mode case), #94/#91 land
// host-Pi reconciliation; each of those tickets restores the matching clause
// to this message and to script/test/pi-layer-runtime.sh's assertions.

const WARNING = [
  "agent-vm: signing in here (for example with /login) writes a credential that",
  "any process in this guest can read. The microVM -- not this warning -- is the",
  "boundary.",
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
