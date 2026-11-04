//! `agent-vm tools …` — the tool definitions built into this binary.
//!
//! `print` writes them as user-config TOML (#510). Its output is this release's
//! definitions, so the renderer reads only embedded data and the dispatched result
//! never reaches it: `main` dispatches it before credential preflight, the MSB
//! prologue and the runtime, and ignores the carried catalog whether it is ready or
//! broken. Configuration is still *discovered* on the ordinary entry path, because
//! the catalog decides which verbs exist.

use anyhow::{Context as _, Result};
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) cmd: ToolsCmd,
}

#[derive(Subcommand)]
pub(crate) enum ToolsCmd {
    /// Print built-in tool definitions as TOML for your user config.
    ///
    /// With no NAME, prints every built-in tool: declaring any tool in a config
    /// file replaces the whole built-in catalog. Named tools print in the order
    /// given. The output is this binary's definitions, never a config file's, and
    /// it is a complete `tools` section for ~/.config/agent-vm/config.toml: it
    /// replaces a file's declarations, so a file that already declares tools
    /// should get only the names it lacks. `[[tools]]` blocks may follow existing
    /// `[[tools]]` blocks; a top-level `tools = …` assignment cannot be extended
    /// and must be replaced with the printed blocks.
    Print(PrintArgs),
}

#[derive(ClapArgs)]
pub(crate) struct PrintArgs {
    /// Built-in tools to print, in this order [default: all]
    #[arg(value_name = "NAME")]
    pub(crate) names: Vec<String>,
}

pub(crate) fn run(args: Args) -> Result<()> {
    use std::io::Write as _;
    match args.cmd {
        ToolsCmd::Print(PrintArgs { names }) => {
            // Rendered whole first, so a rejected name leaves stdout empty.
            let text = crate::config::builtin_tools_toml(&names)?;
            std::io::stdout()
                .lock()
                .write_all(text.as_bytes())
                .context("writing the built-in tool definitions")
        }
    }
}
