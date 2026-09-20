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

const WARNING = [
  "agent-vm: signing in here (for example with /login) stores that credential",
  "in THIS project's persistent guest state. Any process in this guest can read",
  "it, and it takes precedence over a host-held credential for the same",
  "provider. Credentials imported from your host stay on the host and never",
  "appear in guest files.",
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
