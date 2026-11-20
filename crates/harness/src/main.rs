use clap::Parser;

/// Prefixes a command prints itself, unchanged. Everything else is an
/// unexpected failure and carries the label of the command that ran, because a
/// single shared prefix named whichever port was written first and mislabelled
/// every later one.
const OWN_VERDICTS: [&str; 3] = ["provenance: ", "usage: ", "FAIL: "];

fn main() {
    let cli = agent_vm_harness::Cli::parse();
    let label = cli.failure_label();
    match agent_vm_harness::run(cli) {
        Ok(output) if !output.is_empty() => println!("{output}"),
        Ok(_) => {}
        Err(error) => {
            if OWN_VERDICTS.iter().any(|prefix| error.starts_with(prefix)) {
                eprintln!("{error}");
            } else {
                eprintln!("{label}: FAIL: {error}");
            }
            std::process::exit(1);
        }
    }
}
