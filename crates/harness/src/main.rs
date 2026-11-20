use clap::Parser;

fn main() {
    let cli = agent_vm_harness::Cli::parse();
    let label = cli.failure_label();
    match agent_vm_harness::run(cli) {
        Ok(output) if !output.is_empty() => println!("{output}"),
        Ok(_) => {}
        Err(error) => {
            // A command that reports its own verdict prints it unchanged.
            if error.starts_with("provenance: ") || error.starts_with("usage: ") {
                eprintln!("{error}");
            } else {
                eprintln!("{label}: FAIL: {error}");
            }
            std::process::exit(1);
        }
    }
}
