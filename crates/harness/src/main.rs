use clap::Parser;

fn main() {
    let cli = agent_vm_harness::Cli::parse();
    let label = cli.failure_label();
    match agent_vm_harness::run(cli) {
        Ok(output) if !output.is_empty() => println!("{output}"),
        Ok(_) => {}
        Err(error) => {
            eprintln!("{label}: FAIL: {error}");
            std::process::exit(1);
        }
    }
}
