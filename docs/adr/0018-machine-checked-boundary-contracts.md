# ADR-0018: Machine-checked contracts on the pure sandbox-boundary predicates

## Status

Accepted. Implementation decision for [agent-vm #124](https://github.com/gregwebs/agent-vm/issues/124). Builds on the terms **Boundary contract** in [CONTEXT.md](../../CONTEXT.md) and **Layer image contract**, and pairs with the pinned-toolchain invariant enforced by `script/check-rust-toolchain.sh`.

## Context

A handful of **pure** functions in `crates/agent-vm` decide what the sandbox boundary allows:

- whether a request target contains a percent-escape that changes which path it means (`%2e` → `.`, `%2f` → `/`, `%5c` → `\`), which is what keeps an OAuth refresh target exact against an allowlist;
- whether a Unix-domain socket path fits the platform's `sun_path` budget before boot;
- which Chrome-MCP capability policy applies to a booted image;
- how an untrusted byte stream is parsed into a request, and where its body starts.

Those decisions are pure, so the property that matters is *for all inputs* — something a sampling test cannot establish.

[Verus](https://verus-lang.github.io/verus/guide/) verifies Rust. A `verus! { ... }` block holds ordinary Rust plus `requires`/`ensures`/`invariant`/`decreases` annotations. Under a plain `cargo build` the macro **erases** every annotation and emits ordinary Rust, so `cargo build`/`test`/`clippy` keep working with no Verus installed; under `cargo verus verify` the same source is checked by an SMT solver. That asymmetry is what makes verification possible as an optional, CI-only tool rather than a build prerequisite.

The two constraints that shaped the decision:

- **The crate is the verification unit.** In-place verification requires Verus to translate `crates/agent-vm`'s HIR to VIR, so a contract cannot be checked in isolation from its module. Measured cost on the adopting host: **209.6 s** for the first verification, **1.1 s** with no change, **3.4 s** after an edit anywhere in `crates/agent-vm`. The cold cost is dominated by verifying `vstd` itself (2059 functions) plus checking the ~440-crate dependency graph; both cache.
- **Version sensitivity is real.** Verus `0.2026.04.12` — the release pairing with the 1.94 line — cannot verify this crate at all (it panics translating `tokio_util`'s `ReadBufFn` closure). The release that can needs Rust 1.98.1, which issue #123 made this repo's pin, so one toolchain now serves build and verification.

## Decision

### The rule

**A new pure function that decides a security boundary, a resource limit, or the parse of untrusted input carries a `verus!` contract. Existing pure predicates acquire one when next touched for another reason.** Nothing else changes: this is not a proposal to prove the codebase, and no I/O, FFI, async or lock path is in scope.

### The rule's companion: extract the decision, not the I/O

A pure predicate that cannot be verified usually cannot be verified because it does its own I/O. The verifiable form takes the **already-measured** value — bytes, a length, an index — and the untranslatable shell that produces it stays outside the `verus!` block as a thin trusted adapter. Preserving verifiability is therefore a design act at the seam, not a proof technique. This PR's own pairs are the worked example:

| decision (proved kernel) | I/O or untranslatable shell (trusted adapter) |
|---|---|
| `http::contains_escaped_path_escape_bytes(&[u8])` | `http::contains_escaped_path_escape(&str)` — `str::as_bytes` |
| `msb_install::socket_path_fits(usize)` | `check_socket_path_len` — `Path` → `as_os_str().len()`, `anyhow::bail!` |
| `oauth_refresh::path_is_exact(&[u8])` | `validated_target` — `url::Url::parse` and the scheme/host/port/userinfo checks |
| `http::header_block_end` / `is_token_bytes` / `has_no_crlf` | `Request::parse` — `anyhow` context, `String`/`Vec` assembly, `str::from_utf8` |

The interface stays narrow: `contains_escaped_path_escape` takes `&str`, so no verification detail leaks into its call sites.

### Syntax: `verus!` only

The attribute style is excluded. Function-level `#[verus_spec]` measures free but cannot carry a loop invariant, and `#[verus_spec(invariant …)]` on a loop does not compile under plain stable rustc at all (`E0658`, attributes on expressions), because that spelling depends on the driver's `-Zcrate-attr=feature(stmt_expr_attributes)`. Every site here needs a loop invariant.

### The verified surface

One `verus!` block per owning module, in place, no new crate and no moved code. `cargo verus verify --locked -p agent-vm` reports a non-zero `verified` count with `0 errors` across them.

| Site (module) | Contract that is machine-checked |
|---|---|
| `intercept_hook/http.rs` — `contains_escaped_path_escape_bytes` | **No false negatives.** If it returns `false`, no byte position `i` in the target begins a `%` followed by a pair that is malformed, truncated, or decodes to `.`/`/`/`\` (`escape_at`). The loop invariant is "every position behind the cursor is clean", so the postcondition follows from the exit condition. |
| `image_capabilities.rs` — `chrome_mcp_policy`, `ChromeMcpDecision::enabled` | **Precedence is total.** Each of the five `ensures` clauses covers one region of the three-input space; `OptedOut` dominates, nothing but `opted_out` can produce it, and `enabled()` holds exactly for `Legacy`/`Advertised`. |
| `msb_install.rs` — `socket_path_fits` | **The accept/reject comparison, including at the boundary** (`len <= SUN_PATH_USABLE_LEN`). Stated plainly: the exec body restates the spec, so what is proved is that the decision *is* that comparison — **not** that the socket-path invariant holds end to end. |
| `intercept_hook/oauth_refresh.rs` — `path_is_exact` | **An accepted path target contains no `?`, `#` or `\`, and no escaping `%XX`.** The escape half is re-derived from the already-proved `contains_escaped_path_escape_bytes` `ensures`, not re-proved. |
| `intercept_hook/http.rs` — `header_block_end`, `is_token_bytes`, `has_no_crlf` | **The body starts exactly at the separator** (`Some(i)` gives `separator_at` *and* firstness, which is what makes `raw[i + 4..]` a non-panicking slice), **header names are non-empty tokens**, and **values contain no CR or LF**. |
| `config.rs` — `byte_paths_overlap` | **Two normalized guest paths overlap iff equal or one is a component-wise ancestor of the other** (`is_separator_prefix`): `.cache` overlaps `.cache/x` but not `.cachex`. A single loop invariant — "every position behind the cursor is equal" — supplies both the equal case and the separator check at the shorter length. It is now the *symmetric wrapper* around the directional kernel below, so the two decisions cannot drift. Byte-level, so it is the decision only; the `Path` → bytes measurement is the trusted adapter `guest_paths_overlap`. |
| `config.rs` — `byte_path_contains` | **The directional kernel `byte_paths_overlap` is built from, and the containment half of ADR-0020's protected-host-file decision:** `a` is `b` itself, or a component-wise separator-prefixed prefix of it — `/a/pi` contains `/a/pi` and `/a/pi/x`, but not `/a/pistachio` and not its own parent. The sibling-prefix property is stated twice (`byte_path_contains_is_directional_and_component_wise`, plus a proptest against a `Vec<String>` component-prefix oracle), and the property holds for host paths as well as guest ones — hence the separator constant is named `PATH_SEPARATOR`, not `GUEST_PATH_SEPARATOR`. |
| `secrets.rs` — `exact_bytes_equal` | **Whole-value placeholder equality (#93).** If it returns `true`, the two byte sequences are equal (`a@ =~= b@`) — so the "is this an agent-vm placeholder" check can never be satisfied by a *prefix*, *suffix*, substring or placeholder-embedded value. Byte-level, so the `&str` → bytes measurement and the `ALL_PLACEHOLDERS` iteration are the trusted adapter `is_known_placeholder`. |
| `secret_store.rs` — `service_name_is_valid_bytes` | **The service-name decision (#160).** Accepted iff the byte sequence is 1..=64 bytes, starts with an ASCII letter (either case) or digit, and every byte is `[a-zA-Z0-9._-]`. The rejected raw string is never rendered — a user may have typed a *value* in the name slot — so the `&str` → bytes measurement is the trusted adapter `ServiceName::parse`. Under the accepted alphabet a realistic API key *is* a valid name, so this predicate bounds what is storable but is not a credential detector; `ServiceName`'s module note records that trade-off. |
| `secret_store.rs` — `service_name_canonical_bytes` | **Canonicalization preserves acceptance (#160).** The ASCII-lowercased form of a *valid* name is valid, with the length preserved and each byte mapped by `service_name_lower_byte`. That is what makes "canonicalize, then key" equivalent to "validate, then canonicalize": the canonical form is the keychain account and the inventory key, so `Anthropic`/`anthropic` cannot become two entries, and it can be stored and printed without a second acceptance check. The per-byte lemmas `lemma_lower_byte_is_allowed_both_ways` / `..._first_allowed_both_ways` are the kernel, stated as equalities so they hold in both directions. |
| `secret_store.rs` — `secret_value_is_acceptable_bytes` | **The accepted value shape (#160).** Accepted iff 1..=4096 bytes, every byte printable ASCII `0x20..=0x7E`, and neither the first nor the last byte is a space. The value's destination is an HTTPS request header, where CR/LF is a header-injection primitive, so rejection happens at storage — a product constraint on which credentials are supported, not a security claim. A label-only classifier chooses the message, and a proptest pins it to this predicate. |
| `pi_credential_inspection.rs` — `provider_id_is_safe_bytes` | **The safe-provider-label decision (#93).** Accepted iff the byte sequence is non-empty, at most `MAX_PROVIDER_ID_LEN` (64) bytes, and every byte is an ASCII lowercase letter, digit, `-`, `_` or `.`. Anything else is rendered `<unrecognized-provider>` rather than escaped and printed, so an arbitrary guest-controlled key is never echoed. The `&str` → bytes measurement is the trusted adapter `provider_id_is_safe`. |
| `pi_credential_inspection.rs` — `finding_budget_allows_impl` | **The bounded-report predicate (#93).** One more finding may be retained iff the count is strictly below `MAX_RETAINED_FINDINGS` (128); past that the report appends one fixed truncation notice and drops the rest, so a hostile 8 MiB file cannot make the launch notice grow without bound. Stated plainly: what is proved is that the decision *is* that comparison, not that the retained count is what the caller intends. |
| `pi_credential_inspection.rs` — `container_item_budget_allows_impl` | **The bounded-parse predicate, shared by both container shapes (#93; extended to sequences by #146).** One more JSON object member *or array element* may be parsed iff the count so far is strictly below `MAX_CONTAINER_ITEMS` (4096); past that the whole document is rejected, so a guest-controlled 8 MiB file cannot grow the retained member/element list or the duplicate-member check without limit. Objects and arrays share one constant and one contract deliberately: the decision is the same one, and two literals could drift apart. The shapes differ only in *where* the count is checked, and serde forces that difference. On the object side `MapAccess::next_key` yields the next member's key before the budget check runs, so the over-limit member's key is read (itself bounded only by the same 8 MiB read) while its value is never read. On the array side `SeqAccess` offers no way to ask whether an element exists without parsing one, so `next_element` parses the element past the cap and it is then dropped, never retained — and that dropped element can itself be a large subtree, so the cap bounds the *retained* item list, not the process's peak transient memory. This decision is load-bearing precisely because the parse of untrusted input is otherwise trusted (see *The trusted boundary*): the limit is the one part of the visitor that can carry a pure contract. Stated plainly: what is proved is that the decision *is* that comparison; what it bounds is one container, and the total a document may retain is still the 8 MiB read. |
| `cli.rs` — `token_equals`, `route_is_secret_tokens` | **The `secret`-route predicate (#160, review finding N6).** `route_is_secret_tokens` returns `true` iff `argv[1]` is exactly the bytes `secret`, or `argv[1]`/`argv[2]` are exactly `help secret` — and `token_equals` proves the comparison is whole-value equality, never a prefix or substring, so `agent-vm secretx …` cannot select the scrub. The decision is load-bearing: a `secret`-route parse error can carry a supplied value, and only this predicate decides whether the fixed scrub replaces it before clap renders. Byte-level, so the `OsString` → `OsStrExt::as_bytes` measurement is the trusted adapter `is_secret_route`. |
| `secret.rs` — `hidden_line_byte_step` | **The hidden-line resource bound and its sticky overflow (#160, review finding N6).** One more input byte is stored iff the buffer is under `MAX_SECRET_VALUE_LEN` (4096) and no overflow has already happened; the returned pair is exactly the specified `(length, overflow)`, and the overflow flag never clears — a dropped prefix cannot be recovered by a later backspace. This is the resource limit on the bytes an interactive paste may deliver; the terminal I/O is the trusted adapter `HiddenLine::push_byte`. |
| `secret.rs` — `hidden_line_backspace_len` | **Index safety for the backspace path (#160, review finding N4/N6).** The post-backspace byte count is one less than the pre-backspace count, floored at zero and never greater than the buffer, so the caller's `Vec::truncate` can never go past the front. The previous hand-rolled UTF-8 index arithmetic underflowed for a one-byte continuation byte and panicked; the verified kernel makes the accepted *byte* policy total. |

### The trusted boundary

Stated so that nobody reads more into the surface than is there. Verified code calls into, and trusts, the following; **none of it is proved**:

- `str::as_bytes` (total and infallible; the escape property is a property of bytes either way);
- `OsStr::as_bytes` (`OsStrExt`) in `cli::is_secret_route` and `config::guest_paths_overlap`; the route decision is proved, the `OsString` → bytes measurement is not. In `config` it also trusts the *invariant* that a normalized `PersistPath`'s `Path` rendering is its components joined by single `/` (established by `normalize_persist`, not proved), and that a compiled `HomeLink::home_relative` is likewise `/`-joined. The launch-time mount check (`guest_home::mount_conflicts`) extends the same precondition to the guest mount paths it feeds the predicate: each is normalized by `resolve_project_guest_path` / `mount::normalize_guest` before it arrives;
- `OsStr::len` — the socket-path decision is proved, the *byte measurement* of the path is not;
- `url::Url::parse`, and the scheme/host/port/userinfo/query/fragment checks in `validated_target`;
- `anyhow` context and error formatting, and the `String`/`Vec` assembly and `str::from_utf8` calls in `Request::parse`;
- `pi_credential_inspection`'s `serde_json` parsing and its duplicate-rejecting visitor. This is trusted for a **structural** reason, argued rather than asserted: serde's `Deserialize`/`Visitor` API is a callback protocol threaded through `serde_json`'s tokenizer and allocator, so the parse is not a pure `Seq<u8> -> Json` function that a contract could quantify over — the shell is `deserialize_any`, `MapAccess`, `String` allocation and shape dispatch, none of which Verus translates. The decision the parse makes *about untrusted input* is its **resource limit**, and that part *is* proved (`container_item_budget_allows_impl` per object and per array; `finding_budget_allows_impl` for the report), with the duplicate-member check reduced from an O(n²) scan to set membership so the limit is the only remaining unbounded input. That limit is per *container*, not per document: the total a document may retain is still bounded only by the 8 MiB read (JSON spends at least one input byte per value), so #146 closed the shape asymmetry an object-only cap left rather than the global residual, which is the read bound's job. What stays trusted is the shape dispatch, allocation, formatting and redaction around those decisions.
- `secrets::is_known_placeholder`'s `str::as_bytes` and `ALL_PLACEHOLDERS` iteration — the trusted adapter around the proved `exact_bytes_equal`; the scanner module's I/O, rendering and redaction are **not** formally verified;
- all syscalls, and everything with I/O, FFI, async or locks;
- `vendor/microsandbox` and every other dependency.

### The gate asserts that something was verified

`cargo verus verify` **exits 0 while verifying nothing**, in three situations: the manifest lacks `[package.metadata.verus] verify = true`; the crate opts in but contains no `verus!` macro; and — with a warm target dir — cargo's fingerprint hits so the crate is not re-checked and no results line is printed at all. Measured, more than once: a bare `run: cargo verus verify` is therefore not a gate, and a PR that deletes the mechanism would leave CI green.

The gate therefore lives in `script/test/verus-verification.sh`, which CI runs:

- `--repo-gate` cleans just `agent-vm` (`cargo clean -p agent-vm`, leaving `vstd`'s 2059 proofs cached so the re-check stays in the seconds), runs `cargo verus verify --locked -p agent-vm`, and then requires **this crate's own** results line to match `[1-9][0-9]* verified, 0 errors`. A future maintainer who "simplifies" `.github/workflows/verus.yml` back to `run: cargo verus verify` would silently disarm CI.
- `--controls` runs two throwaway fixture crates — one whose contract holds, one whose postcondition is deliberately false — and asserts the verifier passes the first and **fails** the second with `postcondition not satisfied`. Without this, a misconfigured invocation is indistinguishable from a passing gate.

`cargo verus verify`, never `cargo verus build`: the latter would compile shipped binaries with the Verus toolchain rather than the pinned one.

### Going forward

- **A Verus bump is a deliberate change.** The release, its sha256 digest, the `vstd` pin in `crates/agent-vm/Cargo.toml`, the `toolchain:` literal in `.github/workflows/verus.yml` and the digest quoted in `CONTRIBUTING.md` all move together. The literal is doubly constrained: it must equal `rust-toolchain.toml`'s channel *and* the toolchain named in the pinned release's `version.json`, so `check_verus_yml` in `script/check-rust-toolchain.sh` now enforces it exactly like `ci.yml`'s copy.
- **`vstd` is pinned exactly** (`=0.0.0-2026-09-16-0054`). A loose prerelease requirement resolves to a newer `vstd` that fails to compile under the Verus toolchain it is meant to pair with (`could not find intrinsics in alloc`).
- **Fallback if verification cost grows:** a leaf crate `crates/agent-vm-verified` (measured 26.4 s cold, 1.0 s per edit) holding the kernels, to be taken only if re-verification cost grows with the number of contracts. The crate is the verification unit today, so an edit *anywhere* in `crates/agent-vm` re-verifies its contracts (~3.4 s at four contract items); that cost grows with the count and difficulty of contracts, not with the crate's ordinary code size. Do not extract it preemptively.

## Consequences

- **The plain build is only slightly more expensive.** `cargo build`, `cargo test` and `cargo clippy` work with no Verus on `PATH`. The `vstd` dependency stack costs a one-off, per-target-dir **10.1 s** for `cargo build` and **49.4 s** for `cargo build --release`, and zero for crates with no Verus code. Three paths pay the release figure on a cold build: `ci.yml`'s `cargo build --release -p agent-vm`, `release-npm.yml`'s two release legs, and `script/build/macos.sh`.
- **The property is stated twice, on purpose.** Each predicate is asserted as a `#[test]`/proptest on the erased build *and* as a Verus spec. Tests complement the proofs rather than being replaced by them, and the existing tests are the regression check that the in-place contract preserved behaviour. The escape scanner's proptest pins the verified rewrite against an independent oracle.
- **Measured evidence is recorded**, not remembered: `docs/research/verus-build-cost.md` (the write-up, plus a dated note on the 1.98.1 pin and the two plain-build figures above) and the verification figures in *Context*.
- **Verification cost is bounded per-contract, not per-edit.** Warm re-verification after an edit is ~5 s. The cold first run (2–4 min) is the ~440-crate graph plus `vstd`, both cached. Use `CARGO_TARGET_DIR=target/verus` locally: `cargo verus` sets `RUSTC_WRAPPER`, which is part of cargo's fingerprint, so sharing one `target/` with ordinary builds makes every switch a full rebuild.
- **How the verifier reaches CI.** `.github/workflows/verus.yml` downloads the pinned release asset, checks it against its sha256 before unpacking, and caches the **unpacked** tree (measured 1.63 GB / 4617 files, *larger* than the ~1.0 GB the issue estimated) under a key containing both the release and the digest. A restored tree is therefore by construction the tree that digest names, so a Verus bump can never restore a stale verifier. `actions/cache` is the one action this repo did not already pin; it is pinned by commit SHA like every other, because `zizmor` audits the workflows.
- **Accepted risk: the cache entry shares GitHub's 10 GB per-repo cache budget** with `ci.yml`'s `Swatinem/rust-cache` entries. This workspace's Rust cache is on the order of 1–2 GB, so the budget has room; the eviction concern is speculative. The inverse trigger, for a future maintainer, is measured rather than guessed: if runs show near-constant cache misses (restores failing while the cache is cold each time), or a restore measurably slower than download plus unpack, delete the `Cache Verus` step, remove the `if:` guard from `Install Verus`, and record the measurement here. Do not drop it on speculation.
- **`verus.yml` cannot be a step in `ci.yml`.** `script/check-rust-toolchain.sh`'s `check_ci_yml` collects *every* `toolchain: "…"` line in `ci.yml` into one value and compares it to the channel; a second copy there fails the checker. A separate workflow also keeps the ~450-crate verification build off `ci.yml`'s critical path.

## Alternatives

- **Keep tests and prose as the only guard.** Rejected: that is the status quo the issue documents, and a test can only sample the input space.
- **A leaf crate `crates/agent-vm-verified` now**, moving the decisions out of their modules. Rejected for now: the issue asks for in-place contracts with no new crate and no moved code, and the measured leaf-crate win is a cost win only. It stays documented as the fallback.
- **The attribute syntax (`#[verus_spec]`).** Rejected: it cannot carry a loop invariant, and its loop spelling does not compile under plain stable rustc (`E0658`).
- **A bare `cargo verus verify` as the CI step.** Rejected: measured to exit 0 while verifying nothing in three distinct situations (see *The gate asserts that something was verified*).
- **Run `cargo verus build` for release artifacts.** Rejected: shipped binaries must be compiled by the pinned toolchain, not the Verus one.
- **Pin the rolling release measured here vs the nearest tagged release.** The rolling release (`0.2026.09.16.7325eee`) is pinned, with its digest recorded, because it is the one measured on both the planning host and an independent reviewer's run, and `vstd` is pinned to the version that pairs with it. Either choice is acceptable as long as the digest is recorded and the job is green before merge.
