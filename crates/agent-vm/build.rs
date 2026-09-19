fn main() {
    // `include_dir!` registers the *files* it embeds as rebuild inputs but not
    // the directory, so a newly ADDED layer source would otherwise leave a
    // stale snapshot in the binary — the exact drift
    // `tool_layer::tests::embedded_sources_match_the_on_disk_tree` catches.
    // Emit the directory here so the test fails ~never in practice.
    println!("cargo:rerun-if-changed=../../images/tools");
}
