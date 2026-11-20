use clap::Parser;

fn main() {
    match agent_vm_harness::run(agent_vm_harness::Cli::parse()) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("config-dir guard: FAIL: {error}");
            std::process::exit(1);
        }
    }
}
