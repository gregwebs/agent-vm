use clap::Parser;

fn main() {
    // Parsing is all this entry point owes until the first port adds a command;
    // clap exits on `--help`, `--version` and a usage error.
    let _ = agent_vm_harness::Cli::parse();
}
