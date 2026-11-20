use clap::Parser;

/// Prefixes a command prints itself, unchanged. Everything else is an
/// unexpected failure and carries the label of the command that ran, because a
/// single shared prefix named whichever port was written first and mislabelled
/// every later one.
const OWN_VERDICTS: [&str; 8] = [
    "provenance: ",
    "usage: ",
    "FAIL: ",
    "select: ",
    "manifest: ",
    "released-image-launch: ",
    "detached-run: ",
    "standin: ",
];

fn main() {
    let cli = agent_vm_harness::Cli::parse();
    let label = cli.failure_label();
    let error = match agent_vm_harness::run(cli) {
        Ok(agent_vm_harness::Outcome::Report(output)) => {
            if !output.is_empty() {
                println!("{output}");
            }
            return;
        }
        Ok(agent_vm_harness::Outcome::Exit(status)) => std::process::exit(status),
        Err(error) => error,
    };
    if OWN_VERDICTS.iter().any(|prefix| error.starts_with(prefix)) {
        eprintln!("{error}");
    } else {
        eprintln!("{label}: FAIL: {error}");
    }
    std::process::exit(agent_vm_harness::failure_status(&error).unwrap_or(1));
}
