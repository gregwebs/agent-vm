# Verus build cost: the `verus!` macro vs the attribute syntax

> **Note added 2026-09-18 (adopting Verus for issue #124).** This document is a
> dated research record, kept as written; the following is what has changed since.
>
> - This repo has since moved to the **1.98.1** pin (issue #123, commit
>   `9fb5ca9`), so every "this repo pins 1.94" passage below is history, not
>   current fact. The Verus release adopted by
>   `.github/workflows/verus.yml` (`0.2026.09.16.7325eee`) names
>   `1.98.1-aarch64-apple-darwin` in its `version.json`, so one toolchain now
>   serves both the build and the verification.
> - The plain-build cost of the `vstd` dependency stack, measured on the
>   adopting host for **both** profiles, is **10.1 s** (`cargo build`) and
>   **49.4 s** (`cargo build --release`), one-off per target dir and zero for
>   crates with no Verus code. The release figure is the one that recurs on a
>   cold build, and three paths pay it: `ci.yml`'s
>   `cargo build --release -p agent-vm`, `release-npm.yml`'s two release legs,
>   and `script/build/macos.sh`.
> - See [`docs/adr/0018-machine-checked-boundary-contracts.md`](../adr/0018-machine-checked-boundary-contracts.md)
>   for the decision, the verified surface, and the trusted boundary.

**Research date:** 2026-09-17

**Local snapshot:** `verus-lang/verus` `main` [`7325eee`](https://github.com/verus-lang/verus/commit/7325eeead56f7879303b2fa7af9c2a1b1bcd987e) (2026-09-16);
Verus release [`0.2026.04.12.f1166c4`](https://github.com/verus-lang/verus/releases/tag/release%2F0.2026.04.12.f1166c4) (commit [`f1166c4`](https://github.com/verus-lang/verus/commit/f1166c42c3decd42c1cca2916ef2880d27cfb7d9)) used for the measurements below,
because it is the Verus release whose own pinned Rust toolchain (1.94.0) matches this repo's 1.94 line. Measurements on macOS arm64, 8 CPUs, `rustc` 1.94.0/1.94.1.

## The two questions, answered

**1. Does the `verus!` macro slow down a plain `cargo build`?** No, it does not force the Verus driver, but it is not free. `verus!` is an ordinary `#[proc_macro]` in the `verus_builtin_macros` crate. With no `verus_keep_ghost` cfg set — i.e. any plain `cargo build` — it erases every spec/proof/ghost construct and emits plain Rust, which stock stable rustc then compiles. I compiled a `verus!` block containing `requires`/`ensures`, `spec fn`, `proof fn`, `let ghost`, and a `proof { ... }` block on stable 1.94 with `vstd` from crates.io: it builds and runs. The absolute cost is small and mostly fixed, not per-build:

* **Cold builds only:** adding the macro's dependency stack (`verus_builtin_macros` → `syn`/`verus_syn`/`prettyplease`) costs about **+5.8 s**; depending on `vstd` as well raises the total to about **+7.9 s** on this machine (debug). A no-op or dependency-unchanged rebuild pays **0**.
* **Every crate that contains a `verus!` block:** the block is re-expanded and the emitted tokens re-parsed whenever that crate recompiles. Measured on one file: 5,000 plain functions compile in 1.00 s; the *same* functions wrapped in `verus!` (no ghost code at all) take 2.05 s; with `requires`/`ensures` and ghost code, 3.5 s. Touch-rebuild of a 5,000-function file: 0.22 s plain vs 2.74 s with Verus annotations. 300 functions: 0.05 s → 0.21 s. The cost scales with the whole `verus!` block, not with the size of the edit.

An independent re-measurement at review time (same machine, identical bodies and specs across variants, `CARGO_INCREMENTAL=0` full-crate rebuild, 3,000 functions, best of three) reproduces the ~2x and places the attribute syntax's function-level form next to it:

| Variant (3,000 functions in one crate) | Full-crate rebuild |
|---|---|
| plain Rust | 0.93 s |
| `verus!` with `requires`/`ensures` | 2.04 s |
| `verus!` with `requires`/`ensures` plus `while`/`invariant` | 2.15 s |
| `#[verus_spec]` carrying the same `requires`/`ensures` | 0.97 s |

The multiplier is not a constant: `verus!` re-emits every item in the block (injecting `#[verifier::…]` attributes as it goes), so its cost is O(block size) — about 2x for the bodies above, and up to ~6x for loop-heavy bodies in a smaller re-run (500 functions 0.08 s → 0.43 s, 2,000 functions 0.20 s → 1.33 s). `#[verus_spec]` at function level stays within noise of plain Rust (+0.04 s, ~4%) for a verified reason, not a measurement artefact: in the erasing configuration its expansion is literally `if erase.erase_all() { return input; }` — an identity passthrough with no parsing or rewriting ([`source/builtin_macros/src/attr_rewrite.rs:504-507`](https://github.com/verus-lang/verus/blob/7325eee/source/builtin_macros/src/attr_rewrite.rs#L504)).

So: a normal `cargo build`/`cargo clippy`/`cargo test` loop stays on stable rustc and keeps working, at the price of a 2–6x per-crate compile for files that are mostly Verus code (sub-second to low-single-digit seconds in absolute terms at the scales measured), plus a one-time ~8 s dependency build.

**Small-N check — a 100-function file with 5 functions in `verus!`.** The numbers above are all at 1,000+ functions, where the cost is easy to see. Measured at the scale a real file has, compiling the file directly with `rustc --emit=metadata` (min of 25 runs, so cargo's own overhead does not mask the difference):

| 100-function file | min | median |
|---|---|---|
| plain functions | 54.1 ms | 56.3 ms |
| plus `use vstd::prelude::*` | 56.1 ms | 58.0 ms |
| plus 5 of the 100 functions in one `verus!` block | 59.3 ms | 62.7 ms |
| plus the same 5 functions in five separate `verus!` blocks | 59.5 ms | 60.4 ms |

So the wrapped functions cost **~3 ms** (≈0.6 ms each at this size), depending on `vstd` at all costs **~2 ms**, and splitting one block into five costs nothing measurable (~0.2 ms total), because the per-invocation overhead is negligible next to the per-item rewrite. The same delta survives a `cargo` rebuild, where it is at the edge of the noise: 170 ms vs 173 ms for a touched crate. Cold, this file still pays the ~+6–8 s dependency build once per workspace, and 0 for every crate that does not contain Verus code.

The scaling rule that follows is the useful one: cost is O(size of the `verus!` block), around **0.2–0.7 ms per wrapped function** depending on how much Verus-only syntax is inside, not O(file size). A file with 5 of 100 functions wrapped pays roughly 1/20th of what a fully wrapped 100-function file would, and the unwrapped 95 functions are irrelevant to it.

How to reconcile this with the earlier "5,000 plain functions compile in 1.00 s → 2.05 s wrapped" figure: that is the same slope at 50x the volume. The reason a mass-wrapped crate looks alarming and a 5-function block does not is volume of wrapped code, not any fixed startup cost in the macro.

**2. What about the attribute syntax?** There are two different things called that, and they behave oppositely — and the first one splits further, between the function form (free) and the loop form (not buildable at all without Verus):

* `#[verus_spec(...)]`, `#[verus_verify(...)]`, and `proof! { }` are `#[proc_macro_attribute]` / `#[proc_macro]` items in `verus_builtin_macros`, re-exported from `vstd::prelude` ([`source/vstd/prelude.rs:15,33,35`](https://github.com/verus-lang/verus/blob/7325eee/source/vstd/prelude.rs#L15)). At **function level** these are **plain-cargo safe**: the guide says "[w]hen Rust builds the code (without using Verus), the `#[verus_spec(...)]` attribute will ensure all proof code is erased" ([exec_attr.md](https://verus-lang.github.io/verus/guide/exec_attr.html)). I verified this on stable 1.94 — including a `proof!` block containing deliberately invalid Rust, which was erased and the crate compiled.
  This is not the whole story for the attribute style, though: the **loop** form is not plain-cargo safe. The documented spelling for a loop invariant is an attribute on the loop — `#[verus_spec(invariant acc >= x)] while j < 10 { … }` — and plain stable rustc rejects it before any macro can run:

  ```
  error[E0658]: attributes on expressions are experimental
  error[E0658]: custom attributes cannot be applied to expressions
  ```

  I reproduced both errors on stable 1.94.1 with a `while` loop and with a bare `loop`. The reason is on the Verus side: the driver injects `-Zcrate-attr=feature(stmt_expr_attributes)` ([`source/rust_verify/src/config.rs:221,232`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/config.rs#L221)), and that is what makes the syntax legal. So function-level `#[verus_spec]` is free under plain cargo, but the first loop invariant puts the crate back behind the Verus driver — the attribute style is plain-cargo compatible exactly up to the point where the proofs start.
* `#[verifier::exec]`, `#[verifier::spec]`, `#[verifier::proof]` on **native Rust items** (outside `verus!`) are not proc macros. They are inert tool attributes that only the Verus rustc driver understands, and **plain stable rustc rejects them**. I get:

  ```
  error[E0433]: failed to resolve: use of unresolved module or unlinked crate `verifier`
  ```

  This is the scenario you asked about: the moment one such attribute appears on native Rust code, **every** build of that crate must go through the Verus driver, because there is no plain-rustc path that accepts the source. Making `register_tool(verifier)` available requires `#![feature(register_tool)]`, which is nightly-only — on stable 1.94 the crate fails with `error[E0554]` ("`#![feature]` may not be used on the stable release channel"). (It compiles under `RUSTC_BOOTSTRAP=1`, but then the attributes are silently ignored, so the annotations do nothing.)

  One nuance: the same attributes written *inside* a `verus!` block are consumed by the macro and are harmless under plain cargo. The breakage is specifically attribute-on-native-Rust-item.

## A. Syntax mechanics

`verus!` is a proc macro, not a rustc special case:

* `source/builtin_macros/src/lib.rs:100-102` defines `#[proc_macro] pub fn verus(input) -> ... { syntax::rewrite_items(input, cfg_erase(), true) }`. The published crate name is `verus_builtin_macros` ([`source/builtin_macros/Cargo.toml`](https://github.com/verus-lang/verus/blob/7325eee/source/builtin_macros/Cargo.toml), `[lib] proc-macro = true`). `vstd::prelude` re-exports it as `verus`.
* Whether it erases is decided by `cfg_erase()` ([`source/builtin_macros/src/lib.rs:136-159`](https://github.com/verus-lang/verus/blob/7325eee/source/builtin_macros/src/lib.rs#L136)): with the `verus_keep_ghost` cfg unset, the `#[cfg(not(verus_keep_ghost))]` version returns `EraseGhost::EraseAll`. `verus_keep_ghost` is set by `vargo` in `RUSTFLAGS` ([`tools/vargo/src/commands/mod.rs:104-110`](https://github.com/verus-lang/verus/blob/7325eee/tools/vargo/src/commands/mod.rs#L104)) and by the Verus driver for its verify pass ([`source/rust_verify/src/driver.rs:288-291`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/driver.rs#L288)). So plain rustc always gets the erasing expansion.
* The driver does wrap the macro path with extra flags: `-Zcrate-attr=feature(register_tool)`, `-Zcrate-attr=register_tool(verus|verifier|verusfmt)`, and lint allowances for `unused_parens`, `unused_braces`, `unconditional_panic`, `arithmetic_overflow`, `irrefutable_let_patterns`, `unused_imports`, `unused_mut` — the source comment says these exist because "syntax macro adds superfluous parentheses and braces" ([`source/rust_verify/src/config.rs:200-238`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/config.rs#L200)). A plain `cargo build` gets none of these allowances, so lint output can differ between the two paths; in my test crate `cargo clippy` under plain cargo reported only lints on my own source lines, not on generated code, so this is a plausible nuisance rather than a demonstrated one.
* `#[verifier::…]` attributes: parsed by the driver at [`source/rust_verify/src/attributes.rs:153-161`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/attributes.rs#L153) into an `AttrPrefix::Verifier` tree, and `spec`/`proof`/`exec` are turned into `Attr::Mode(...)` at [`attributes.rs:458-466`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/attributes.rs#L458). Tool registration comes from the driver's `-Z` flags, not from your crate.
* The older *unprefixed* form is gone: bare `#[spec]`, `#[proof]`, `#[exec]` now produce `"attributes spec, proof, exec are not supported anymore; use the verus! macro instead"` ([`attributes.rs:183-190`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/attributes.rs#L183)).
* `#[verus_spec]` / `#[verus_verify]` are defined at [`source/builtin_macros/src/lib.rs:343-355`](https://github.com/verus-lang/verus/blob/7325eee/source/builtin_macros/src/lib.rs#L343).

## B. What plain, unmodified rustc can compile

Verbatim, from the guide:

> "Note that you can still use normal `cargo` commands (e.g., `cargo build`) on crates and projects that include Verus annotations."
> — [cargo_verus.md:66](https://verus-lang.github.io/verus/guide/cargo_verus.html)

> "Note that Verus-annotated code can also be built with a normal `cargo build` command, if you prefer."
> — [cargo_verus.md:161](https://verus-lang.github.io/verus/guide/cargo_verus.html)

> "Crates without that setting are compiled normally and are not passed through the Verus prover."
> — [cargo_verus.md:217-218](https://verus-lang.github.io/verus/guide/cargo_verus.html)

> "Verus performs ghost erasure: ghost code that exists for verification purposes is removed when building the executable artifacts, ensuring they are minimally disturbed."
> — [erasure.md:3-4](https://verus-lang.github.io/verus/guide/erasure.html)

> "Verus erases all ghost code before compilation so that it imposes no run-time overhead."
> — [requires_ensures.md:205](https://verus-lang.github.io/verus/guide/requires_ensures.html)

> "When Rust builds the code (without using Verus), the `#[verus_spec(...)]` attribute will ensure all proof code is erased."
> — [exec_attr.md:52-53](https://verus-lang.github.io/verus/guide/exec_attr.html)

The published `vstd` crate is explicitly built for this: its manifest header says "[t]his toml file is not part of the standard Verus workspace, and is not required to build and use Verus. Instead, it may optionally be used for compiling an erased vstd library for linking with non-Verus Rust code" ([`source/vstd/Cargo.toml:1-4`](https://github.com/verus-lang/verus/blob/7325eee/source/vstd/Cargo.toml#L1)). Verus's own CI has a `cargo-tests/unverified/` suite that runs plain `cargo check` and `cargo build` on crates containing `verus!` blocks ([`source/rust_verify_test/tests/cargo.rs:78-96,164`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify_test/tests/cargo.rs#L78), e.g. `unverified/structural/src/main.rs`).

For `#[verifier::exec|spec|proof]` the docs are **silent**: neither the guide nor `reference-attributes.md` documents them as user-facing syntax, and there is no sentence saying they need the driver. The evidence is the source and my compiler run, above. The guide does show how the driver itself supplies the necessary `-Z` flags for a comparable case, using rustdoc: `'-Zcrate-attr=feature(register_tool)'`, `'-Zcrate-attr=register_tool(verifier)'` ([verusdoc.md:36-39](https://verus-lang.github.io/verus/guide/verusdoc.html)).

None of the three `-Z`/nightly escapes you asked about (`#![register_tool]`, `-Z` flags, `RUSTC_WORKSPACE_WRAPPER`) is usable from a stable downstream repo. The integration point the docs actually name is `RUSTC_WRAPPER` — not `RUSTC_WORKSPACE_WRAPPER`, which appears nowhere in Verus (the only hit in the repo is inside the vendored `syn`):

> "cargo-verus is a thin wrapper that translates Cargo metadata and user arguments into environment variables, then invokes `cargo build` with the `RUSTC_WRAPPER` environment variable set to the `verus` binary. The verus driver performs the actual verification."
> — [CARGO-VERUS.md:13](https://github.com/verus-lang/verus/blob/7325eee/source/docs/CARGO-VERUS.md#L13)

There is no `verus-rustc` binary and no `vargo`/`cargo-verus` distinction that avoids the driver. `vargo` is Verus's *own* repo build tool — it refuses to run unless it finds `workspace.metadata.vargo` in `Cargo.toml` and its own `rust-toolchain.toml` ([`tools/vargo/src/context.rs:87-105`](https://github.com/verus-lang/verus/blob/7325eee/tools/vargo/src/context.rs#L87)) — so it is not the tool for a downstream repo. `cargo verus` is.

## C. Build-time cost model, and the toolchain

**Toolchain: one specific stable Rust release per Verus release, not nightly, and not yours.** Verus's own `rust-toolchain.toml` pins `channel = "1.98.1"` with components `rustc, rust-std, cargo, rustfmt, rustc-dev, llvm-tools` ([`rust-toolchain.toml`](https://github.com/verus-lang/verus/blob/7325eee/rust-toolchain.toml)); the `1.98.1` form is a stable release number, and the git history of that file is a straight walk through stable releases: 1.93.0 (2026-01-26) → 1.93.1 (02-24) → **1.94.0 (2026-03-17, "Support Rust 1.94.0" [#2248](https://github.com/verus-lang/verus/pull/2248)), 1.95.0 (04-19) → 1.96.0 (06-08) → 1.97 (07-25) → 1.98.0 (09-04) → 1.98.1 (09-08)**. Verus also *embeds* forked copies of `rustc_hir_analysis`, `rustc_mir_build`, `rustc_hir_typeck` rather than patching your toolchain ([`source/tools/update-rustc-forks.sh`](https://github.com/verus-lang/verus/blob/7325eee/source/tools/update-rustc-forks.sh), [`source/rustc_hir_analysis/Cargo.toml`](https://github.com/verus-lang/verus/blob/7325eee/source/rustc_hir_analysis/Cargo.toml)), so no `rustup toolchain link` of a patched compiler is needed.

The required toolchain is discoverable, and the released binary refuses to run without it. A downloaded release contains `version.json` with `"toolchain": "1.94.0-aarch64-apple-darwin"`, and `verus` shells out to `rustup run <TOOLCHAIN> -- rust_verify` ([`source/verus/src/main.rs:42,195-200`](https://github.com/verus-lang/verus/blob/7325eee/source/verus/src/main.rs#L195)). `rust_verify` is a `rustc_driver` (`#![feature(rustc_private)]`, [`source/rust_verify/src/main.rs:1-7`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/main.rs#L1)) that dynamically links the *exact* `librustc_driver` of that toolchain — I confirmed the linkage is hash-specific, since 1.94.1 ships `librustc_driver-f9c8b388b33f1d3d.dylib` while Verus 0.2026.04.12 demands `librustc_driver-5f49f7b34315e8f1.dylib` and fails to load with 1.94.1 present. **So: current Verus cannot run on stable 1.94; a 1.94-era Verus release can, and one exists** (I ran Verus 0.2026.04.12 on Rust 1.94.0 successfully). Edition 2024 works: `verus --edition 2024` verified a `verus!` file cleanly. One trap: the match is to the exact *patch* release. Verus 0.2026.04.12 pins `1.94.0`, and this repo's `channel = "1.94"` resolves to **1.94.1** (confirmed from the repo root: `rustc 1.94.1 (e408947bf 2026-03-25)`, `cargo 1.94.1`) — a different `librustc_driver` hash, so adopting that Verus release means installing 1.94.0 as a second toolchain rather than reusing the pinned one.

**Where the time goes.** The driver runs rustc twice in-process for a verified crate — once keeping ghost code to build VIR and verify, once erasing ghost code to produce the artifact ([`source/rust_verify/src/driver.rs:91-120`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/driver.rs#L91)). It reports the split itself: `--time` prints `rust-time` (init-and-types / trait-conflicts / `compile-time`) separately from `verification-time` (`vir-time`, `verify-crate-time`, `total air-time`, `total smt-time`), and the `Stats` struct documents the intent ([`driver.rs:155-165`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/driver.rs#L155)).

Concrete numbers, one file of 500 exec functions each with a `while` loop and an invariant, Verus 0.2026.04.12 release build, macOS arm64:

| Command | Wall |
|---|---|
| `rustc -O` on the plain-Rust equivalent (no specs) | 1.06 s |
| `verus --no-verify --compile` (parse, typecheck, VIR build, erase, codegen — no SMT) | 1.13 s |
| `verus --compile` (verify **and** produce the artifact) | 2.55 s |
| `verus --time` (verify only, no artifact) | 2.54 s |

and the `--time` breakdown of that 2.45 s: `rust-time` 0.67 s (init-and-types 0.27, trait-conflicts 0.03, compile 0.37); `verification-time` 1.70 s (VIR 0.29, verify-crate 1.41, of which SMT 0.63 and AIR encoding 0.60). Compiling the same code *without* verification costs about the same as plain rustc (1.13 s vs 1.06 s). Verification roughly doubles it, and SMT is only about a quarter of the total — the largest single bucket is the VIR/AIR pipeline. This is a cheap-proof workload; proofs that are actually hard are solver-bound.

Verification is parallel per *module*, not per function: buckets are one per module unless `#[verifier::spinoff_prover]` splits a function out ([`source/rust_verify/src/buckets.rs:85-118`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/buckets.rs#L85)), and `--num-threads` defaults to `available_parallelism() - 1`. A single-module crate therefore verifies on **one** thread — my 500-function single-module file reported `(1 threads)`. Eight modules × 200 functions took 4.65 s wall at 7 threads vs 7.45 s at `--num-threads 1`.

Verus does not publish per-function verification times. What it publishes is the budget model: "[t]he default `rlimit` is 10. The rlimit is roughly proportional to the amount of time taken by the solver before it gives up. The default, 10, is meant to be around 2 seconds" ([reference-attributes.md:255](https://verus-lang.github.io/verus/guide/reference-attributes.html)) — i.e. per-function solver timeouts of ~2 s by default, firable with `--rlimit`. The upper end is documented in a warning about LLM-generated proofs: "Some models … tend to give Verus huge resource limits (e.g., 2000) … and hence wait for many hours for Verus to finish" ([llmforverusproof.md:145](https://verus-lang.github.io/verus/guide/llmforverusproof.html)). The guide treats slow verification as the normal case to be managed, not an exception ([smt_perf_overview.md](https://verus-lang.github.io/verus/guide/smt_perf_overview.html)).

The only end-to-end numbers Verus itself produces are CI job durations. On the most recent successful `ci` run I sampled (`34119161476`, 2026-09-07) the `basic-test` job's single `build` step — `cargo clean; cargo build` of Verus itself, *then* `cargo run -p cargo-verus -- build --manifest-path vstd/Cargo.toml`, which builds **and verifies** `vstd` ([`ci.yml:242-249`](https://github.com/verus-lang/verus/blob/7325eee/.github/workflows/ci.yml#L242)) — took 4.4 min on `ubuntu-24.04`, 6.8 min on macOS, 7.0 min on Windows; `full-test`'s build step took 7.3 min. These are upper bounds for "verify vstd" because they include building the Verus toolchain itself, which I could not separate out from the API. Treat them as an order of magnitude, not a measurement.

## D. Keeping verification out of the ordinary build path

Every documented mechanism assumes the *default* build path is the verified one, and you opt out. The gates are:

* **Cargo metadata opt-in.** Only crates with `[package.metadata.verus] verify = true` are verified; "Crates without that setting are compiled normally and are not passed through the Verus prover" ([cargo_verus.md:217-218](https://verus-lang.github.io/verus/guide/cargo_verus.html)). Plain `cargo build` ignores this metadata entirely.
* **Separate subcommands.** `cargo verus verify` verifies and produces no binary; `cargo verus build` "Verifies all opted-in crates **and** compiles them to native artifacts"; `cargo verus focus` skips re-verifying dependencies ([cargo_verus.md:118-161](https://verus-lang.github.io/verus/guide/cargo_verus.html)). This is the closest thing to `vargo build` vs `vargo verify`.
* **Driver flags.** `--no-verify` ("Do not run verification"), `--verify-root`, `--verify-module MODULE`, `--verify-only-module MODULE`, `--verify-function MODULE`, `--no-erasure-check`, `--compile` ("Run Rustc compiler after verification") — verbatim from the released `verus --help`, matching [`config.rs:459-564`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/config.rs#L459).
* **Incremental verification is crate-granular.** "Incremental builds mean that only changed crates are re-verified" ([cargo_verus.md:128](https://verus-lang.github.io/verus/guide/cargo_verus.html)); `.vir` files are stored next to `.rlib`s and cargo fingerprinting picks up their change ([CARGO-VERUS.md, "VIR File Management"](https://github.com/verus-lang/verus/blob/7325eee/source/docs/CARGO-VERUS.md)).
* **No cargo feature is documented for this.** The guide does not describe a `feature = "verus"` toggle. `exec_attr.md` suggests the *opposite* pattern for the attribute syntax — "projects to define custom stub macros and control Verus dependencies via feature flags" ([exec_attr.md:24](https://verus-lang.github.io/verus/guide/exec_attr.html)) — but that is advice, not a shipped mechanism.

Does the erasing build produce the same artifact? The docs promise only that artifacts are "minimally disturbed" and incur "no run-time overhead" (quoted in §B). They never claim MIR/codegen identity, so **that is not stated in the docs**. I checked it directly: a `verus!`-wrapped `add_one`/`scale` pair versus hand-written equivalents, `-O --emit=llvm-ir` on stable 1.94, produced byte-identical LLVM IR for both functions (only the module hash differs). That is one trivial example, not a general guarantee — but it is consistent with the erasure model, in which the exec syntax tree is re-parsed from erased tokens.

Note the sharp edge that *is* documented and that I reproduced: a spec fn referenced from exec code disappears in the erasing build, giving "cannot find function `triple` in this scope" ([erasure.md](https://verus-lang.github.io/verus/guide/erasure.html) shows the same failure and prescribes `#[cfg(verus_only)]` guards). Ghost code referenced from exec code needs `#[cfg(verus_only)]`, which in turn needs a `check-cfg` suppression in `Cargo.toml` (or your `verus_only` cfg warns).

## E. Which syntax Verus recommends, and the attribute syntax's warts

Verus recommends the macro. From the guide's own tutorial:

> "**Alternate syntax.** Verus also supports an alternate, [attribute-based syntax](exec_attr.md). This syntax may be helpful when you want to minimize changes to an existing Rust project. However, because the `verus!` syntax is cleaner and simpler, we'll stick to that in this tutorial."
> — [verus_macro_intro.md:41-45](https://verus-lang.github.io/verus/guide/verus_macro_intro.html)

> "The default way to write Verus code is by using the `verus!` macro."
> — [exec_attr.md:8](https://verus-lang.github.io/verus/guide/exec_attr.html)

The attribute syntax's stated motivations are exactly the incremental-adoption case — minimize changes to existing code, avoid rewriting function signatures, keep the code readable to non-Verus readers ([exec_attr.md:10-24](https://verus-lang.github.io/verus/guide/exec_attr.html)). It also has concrete gaps:

* Mixing the two is not seamless: `proof_with!` with `#[verus_spec(with ...)]` "has compatibility issues with executable functions defined in `verus!`" and fails with `[E0425]: cannot find function _VERUS_VERIFIED_xxx`; the documented workaround is a trusted wrapper function ([exec_attr.md:95-125](https://verus-lang.github.io/verus/guide/exec_attr.html)).
* `#[verus_verify(dual_spec)]` "currently does not support executable functions verified via the `verus!` macro", and fails on unsupported exec features such as `&mut` inputs ([exec_to_spec.md](https://verus-lang.github.io/verus/guide/exec_to_spec.html)).
* The recommended split is hybrid anyway: "[t]he preferred way to use `#[verus_spec]` and `verus!` is to use `#[verus_spec]` for all executable functions, and use `verus!` for spec/proof functions" ([exec_attr.md:95](https://verus-lang.github.io/verus/guide/exec_attr.html)).

## So what for this repo

`agent-vm` pins stable **1.94** via `rust-toolchain.toml`, is edition 2024, and builds on macOS + Linux CI. Concretely:

* **`verus!` alone, plain builds only.** Ordinary `cargo build`/`test`/`clippy` keep working on 1.94 with no Rust flag, no wrapper, no `-Z`, no Verus installation. Cost: ~+5.8 s cold for the macro dependency stack and ~+7.9 s if you also depend on `vstd`, then ~2x the compile time of each Verus-annotated crate on any rebuild, and ~0 on no-op builds. `cargo clippy` and `rustfmt` see ordinary expanded Rust. The risk is not build time; it is that the crate's `verus!` block is single-threaded macro work in the critical path of every rebuild of that crate, so keeping `verus!` blocks modest (not one 5,000-function block) is worth real wall-clock.
* **`verus!` plus verification.** You must add a Verus installation as a CI prerequisite on both macOS and Linux, plus a Z3 binary, and Verus wants *its* Rust toolchain installed (`rustup install 1.98.1` for current Verus). You cannot verify on 1.94 with current Verus, and pinning the 1.94-era Verus release does not avoid a second toolchain either, because it hash-links `librustc_driver` from **1.94.0** while this repo's `1.94` resolves to 1.94.1 (see the toolchain paragraph in §C). Either way, verification runs on a toolchain that is not the pinned one. `script/check-rust-toolchain.sh` currently enforces a single toolchain literal across the repo, so a second toolchain for verification needs an explicit carve-out. Verification is also where the "N minutes" lives: on this machine 500 loop-invariant functions verified in 2.5 s, but SMT time is dominated by proof difficulty, defaults to ~2 s per function before giving up, and is only parallel across modules — and a single-module crate verifies on one thread.
* **`#[verus_spec]` at function level: adopt freely; `#[verifier::exec|spec|proof]` on native Rust items: do not adopt.** Function-level `#[verus_spec]` measured within noise of plain Rust (§1) and is source-verified as an identity passthrough in the erasing configuration, so it is the cheapest way to add annotations without rewriting a file. But `#[verifier::exec|spec|proof]` on a native item would put *every* build — `cargo build` in a dev sandbox, `cargo clippy` in CI, `cargo test` — behind the `verus` driver, which means behind Verus's pinned Rust toolchain rather than your 1.94, an installed Verus release, and Z3 availability, on both CI platforms. That is a much larger blast radius than the build-time question implies: it removes your ability to build the workspace without Verus installed. It would also add one extra process spawn plus dylib load per rustc invocation for crates that are not even being verified, since non-opt-in crates are still compiled by the driver ([CARGO-VERUS.md:247](https://github.com/verus-lang/verus/blob/7325eee/source/docs/CARGO-VERUS.md#L247)). If you want incremental adoption, use `#[verus_spec]`/`#[verus_verify]`/`proof!` instead — they are proc macros, erase under plain cargo, and give the same "don't rewrite the file" benefit without the driver dependency. That holds for function-level specs only: annotating a loop with `#[verus_spec(invariant …)]` does not compile under plain rustc at all (§2), so the attribute style still lands you back on the driver as soon as a loop invariant is needed. Note the guide's own example of that pattern, `#[verus_spec]` on all exec fns with `verus!` for spec/proof fns, keeps `verus!` in the tree either way.

Wall-clock bottom line for a plain `cargo build` of this repo: `verus!` costs roughly +6–8 s on a cold build and roughly +1–3 s per rebuild of a Verus-heavy crate, and 0 for everything else; the verifying build costs an additional ~1x on top of compiling the same code, plus SMT time on top of that. The attribute syntax outside `verus!` costs you both of those *and* the requirement that Verus be installed for every build.

## Measured on this repo, 2026-09-17: in-place works on current Verus, at a cost

All measurements on macOS arm64, Z3 bundled with Verus, branch `verus-inline-experiment`.

### Version matters enormously: the April release cannot verify this crate, the September one can

| Verus release | Rust it pins | In-place `verus!` in `crates/agent-vm` |
|---|---|---|
| `0.2026.04.12.f1166c4` (25.6 MB zip, sha256 `915ab5bd3c2a522363dd73da0cf51a3102160414aaab914a50829dfac6180987`) | 1.94.0 | **blocked**: `thread 'rustc' panicked at rust_to_vir_base.rs:186:28: unhandled name DefId(... tokio_util[e19f]::io::read_buf::read_buf::{closure#0}::ReadBufFn)`. `--verify-only-module` does not help; VIR translation is crate-wide. |
| `0.2026.09.16.7325eee` (449 MB zip — this one ships a raw cargo build dir, ~1.0 GB of `deps`) | 1.98.1 | **works**: `2059 verified` (vstd) + `4 verified` (agent-vm), 0 errors |

So the blocker is version-specific, not a property of the crate. The old release is the one that pairs with this repo's Rust 1.94 line; the working one needs Rust 1.98.1 installed **alongside** the pinned 1.94 toolchain (the driver runs `rustup run 1.98.1-aarch64-apple-darwin -- rust_verify`, so `rust-toolchain.toml` itself does not have to move).

### In-place timings (Verus 0.2026.09.16, `cargo verus verify -p agent-vm`)

| Scenario | Wall | Detail |
|---|---|---|
| **A.** First verification | **209.6 s** | compiles the vstd chain, verifies vstd (2059 fns), driver-checks the ~437-crate dep graph |
| **B.** No change | **1.1 s** | cargo freshness, no verification work |
| **C.** Edit inside the `verus!` block | **3.4 s** | re-verifies agent-vm's proofs; vstd stays cached |
| **C2.** Edit *anywhere else* in `crates/agent-vm` | **3.4 s** | same — the crate is re-verified as a unit, so proof cost is per-crate, not per-edit-site |

The plain build is untouched: `cargo check -p agent-vm` succeeds with no Verus on PATH, and `cargo test -p agent-vm --bin agent-vm intercept_hook::` passes 49/49 with the function wrapped in place. Cost scales with the number and difficulty of proofs *in the crate*, not with its ordinary code size — ~3.4 s at 4 proven items.

### What still has to be rewritten (September release vs April)

Fixed upstream: **byte literals** (`b'%'`), **`let-else`**, and **`.get(range)`** now translate; those were the April failures.

Still required for this function:

1. **`decreases` on exec loops** (termination is proven by default) and an `invariant` for indexed access.
2. **No specs for `from_utf8` / `from_str_radix` / `Utf8Error` / `ParseIntError`**: `` `core::str::converts::from_utf8` is not supported ... may be able to add a specification with `assume_specification` ``. Unchanged from April. Either `assume_specification` them or decode by hand.
3. **Arithmetic must be proved safe.** The obvious hand-rolled decode fails: `b - b'0'` → `error: possible arithmetic underflow/overflow` (the `if b <= b'9'` branch does not establish `b >= b'0'`), as do `index + 1..index + 3` and `hex_val(hi) * 16 + hex_val(lo)`. What verifies is a version that avoids arithmetic: compare hex digit *pairs* against the three escape encodings (`2e`/`2E`, `2f`/`2F`, `5c`/`5C`) and bound the slice with `bytes.len() - index < 3` instead of `index + 2 >= bytes.len()`.

Net: a ~20-line function becomes ~45 lines, restructured but behaviour-identical (including `from_str_radix`'s tolerance of one leading `+`). That is the per-function cost to budget.

### CI pinning note

The `vstd` requirement must be **exact**. `vstd = "0.0.0-2026-04-12-0118"` resolves to `0.0.0-2026-09-16-0054`, which fails to compile under Verus's 1.94.0 toolchain (`could not find \`intrinsics\` in \`alloc\``); `=0.0.0-...` works. The release zip is ~25 MB on the April line but 449 MB on the September line, so cache the unpacked directory, not just the download.

## The leaf-crate alternative, measured (April release)

Before the September release was tested, the same predicate was moved into a new workspace member `crates/agent-vm-verified` (vstd only, `verify = true`) with `agent-vm` re-exporting it (`pub(super) use agent_vm_verified::contains_escaped_path_escape;`). `cargo verus verify -p agent-vm-verified` on Verus 0.2026.04.12: **26.4 s** cold, **0.6 s** no-change, **1.0 s** after editing the verified code. That is ~8x cheaper cold and ~3x cheaper per edit than in-place, and it keeps the verification unit small as proofs accumulate — the trade is that the predicate must live in (or be duplicated into) a dependency-light crate.

## Where the docs are silent or out of step



* Incremental cost of `verus!` expansion: **not stated in the docs.** The numbers above are my measurements on stable rustc, not a documented claim.
* MIR/codegen identity of the erased build: **not stated in the docs** beyond "minimally disturbed" / "no run-time overhead". My LLVM-IR comparison is one example, not a guarantee.
* `#[verifier::spec|proof|exec]` semantics and their plain-rustc behaviour are **not documented in the guide at all**; `reference-attributes.md` lists only the `#[verifier::…]` *config* attributes. The only documentation of the old attribute syntax is an archive page ([internal/wiki-archive/Deprecated-and-recommended-syntax-and-upcoming-changes.md](https://github.com/verus-lang/verus/blob/7325eee/source/docs/internal/wiki-archive/Deprecated-and-recommended-syntax-and-upcoming-changes.md)) that predates the macro and is explicitly "just an archive".
* Doc drift worth naming: `verus_macro_intro.md` links the phrase "attribute-based syntax" to `exec_attr.md`, but `exec_attr.md` (added 2025-10-28, [PR #1910](https://github.com/verus-lang/verus/pull/1910)) documents `#[verus_spec]`, not `#[verifier::exec]`. The two have opposite plain-cargo behaviour, so that link is easy to misread. Also, `INSTALL.md`'s sample error text still shows toolchain `1.86.0` while `main` pins `1.98.1`; the mechanism it describes (install the toolchain the binary asks for) is current.
* Verus publishes no per-function or per-crate verification times, and no "how long does verifying vstd take" number. I could not find one, so I have not guessed at one.

## How the numbers were produced

Verus release 0.2026.04.12.f1166c4 with Rust 1.94.0 and its bundled Z3, on macOS arm64 (8 CPUs), debug profile for the `cargo` timings and `-O`/release Verus for the verify-vs-compile table. `cargo` timings are the minimum of three runs (variance under 5%) with `CARGO_INCREMENTAL=0` for full-crate numbers and `CARGO_INCREMENTAL=1` for the touch-one-file dev-loop numbers; the "cold" figures are fresh `CARGO_TARGET_DIR`s. Plain-rustc tests used stable 1.94.1 from `rustup` with `vstd 0.0.0-2026-09-16-0054` and `verus_builtin_macros 0.0.0-2026-09-06-0133` from crates.io and no `RUSTC_BOOTSTRAP`. Generated benchmark files are not committed.

**Independent reproduction at review time** (same machine, on the maintainer's own toolchains rather than the agent's): a `verus!` block containing `spec fn`, `proof fn`, `requires`/`ensures`, built and run with plain `cargo run` on stable 1.94.1 against `vstd 0.0.0-2026-09-16-0054` from crates.io, with no Verus installed — 8.48 s cold, and it printed the expected result, confirming the erasure path end to end. `#[verus_spec(...)]` on a native function with a `proof!` block whose body was deliberately invalid Rust likewise compiled and ran. On the same stable toolchain, `#[verifier::exec]` on a native item failed with `E0433`, and `#![feature(register_tool)]` failed with `E0554`. The per-crate multiplier was re-measured as reported in §1, together with the 3,000-function plain/`verus!`/`#[verus_spec]` comparison. Not re-checked at review time: the `librustc_driver` hash-linkage claim, the `--time` breakdown, the LLVM-IR comparison, and the CI job durations.

**Second review pass (attribute-style loop invariants).** Added after the numbers above, because it changes the practical recommendation: `#[verus_spec(invariant …)]` on a `while` loop and on a bare `loop` both fail to compile under plain stable 1.94.1 with `E0658` ("attributes on expressions are experimental" / "custom attributes cannot be applied to expressions"). The mechanism is source-verified rather than inferred from the error — the driver adds `-Zcrate-attr=feature(stmt_expr_attributes)` ([`config.rs:221,232`](https://github.com/verus-lang/verus/blob/7325eee/source/rust_verify/src/config.rs#L221)) — and the cheapness of function-level `#[verus_spec]` is the early return at [`attr_rewrite.rs:504-507`](https://github.com/verus-lang/verus/blob/7325eee/source/builtin_macros/src/attr_rewrite.rs#L504). The documented spelling for attribute-style loop invariants comes from the guide's embedded test source (`#[verus_spec(invariant i <= 10, invariant_except_break i <= 9, ensures i == 10, ret == 10)] loop { … }`).
