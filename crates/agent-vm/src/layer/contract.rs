//! The layer image contract (issue #97): the clauses every built chain step
//! must satisfy, and the pure checks that enforce C1–C4 against a built
//! image's OCI config.
//!
//! Split out of `layer.rs` because its **checks** are 100% policy — facts in,
//! violation out, no I/O of their own. (The `#[ignore]`d e2e suite below *does*
//! drive real Docker; the constraint is on the code that ships.) `layer.rs`
//! still owns the two producers that turn a `docker image inspect` document or
//! an msb cache record into [`ImageFacts`]. See
//! `docs/adr/0003-project-tooling-layers.md`, "The layer image contract", for
//! the normative text (all eight clauses, which four are enforced, and where).
//!
//! This module owns both halves of the contract — the pure clause checks above
//! and the live end-to-end suite below, which proves them against real
//! `docker buildx` output and the msb cache. Run recipe and its rationale:
//! see the *real docker buildx build* e2e section header in `layer.rs`.
//!
//! Only clauses C1–C4 are represented here: they are the four whose
//! violations are visible in the image *config* and *manifest* — both tiny
//! JSON blobs already flowing past the build path. C5–C8 (don't touch
//! agent-vm's files, keep `/bin/bash` and passwd/group appendable, install
//! tools readable by any uid, advertise a capability only when it works)
//! stay documented-only, because checking them means decompressing every
//! built layer. A clause that cannot be checked must not look checkable, so
//! they deliberately have no [`Clause`] variant.

use anyhow::{Context, bail};

use super::ChainStep;

/// The canonical place the whole contract is written down. Every violation
/// points here so a reader lands on the normative text plus the design
/// rationale, not on a second, drift-prone copy. `pub(crate)` so `layer.rs`'s
/// `load_derived_image` hint can point at it too, rather than hand-spelling
/// the path in a second string.
pub(crate) const ADR: &str = "docs/adr/0003-project-tooling-layers.md";

/// One *enforced* clause of the layer image contract. Numbered exactly as in
/// `docs/adr/0003-project-tooling-layers.md` so an error message, a test and
/// the ADR all name the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clause {
    /// C1: the built image still contains, unchanged and in order, every
    /// filesystem layer of the step it was built `FROM`.
    BuildsOnPredecessor,
    /// C2: every directory on the predecessor's `PATH` is still on the
    /// built image's `PATH` (membership, not order).
    PathIsAdditive,
    /// C3: the *final* derived image's config `User` is unset, `root` or
    /// `0`, so a `--root` launch is not silently demoted.
    EndsAsRoot,
    /// C4: the chain targets the host's platform, so the guest never hits
    /// `Exec format error` (or `load_archive`'s platform-selection failure on
    /// the final step). Enforced as C4a (the base link — [`check_base_image`]),
    /// C4b (a pinned `--platform` on the final `FROM` — `lint_step_dockerfile`
    /// rule 3) and C4c (the export assertion — [`check_export_matches_host`]).
    TargetsHostPlatform,
}

impl Clause {
    /// `"C1"` … `"C4"`.
    pub fn id(self) -> &'static str {
        match self {
            Clause::BuildsOnPredecessor => "C1",
            Clause::PathIsAdditive => "C2",
            Clause::EndsAsRoot => "C3",
            Clause::TargetsHostPlatform => "C4",
        }
    }

    /// The clause's short human name, as it appears in the ADR table.
    pub fn title(self) -> &'static str {
        match self {
            Clause::BuildsOnPredecessor => "builds on its predecessor",
            Clause::PathIsAdditive => "keeps PATH additive",
            Clause::EndsAsRoot => "ends as root",
            Clause::TargetsHostPlatform => "targets the host platform",
        }
    }
}

/// A contract violation by one chain step.
///
/// Carries the clause, the step and the two text fields so the caller never
/// re-assembles the message, and so tests assert on `clause` rather than on
/// message substrings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub clause: Clause,
    /// `step 2/3 (.agent-vm/layers/20-b)` — position and label, rendered
    /// once at construction because `ChainStep` is not `'static`.
    pub step: String,
    /// What was observed, in the step's own terms.
    pub detail: String,
    /// One actionable sentence: what to change in the Dockerfile.
    pub fix: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tooling layer {} violates the layer image contract, clause {} ({}): {}\n\
             Fix: {}\n\
             See {ADR}, \"The layer image contract\".",
            self.step,
            self.clause.id(),
            self.clause.title(),
            self.detail,
            self.fix,
        )
    }
}

impl std::error::Error for Violation {}

/// Whether a step's image is the one that will actually boot. C3 applies
/// only to `Final` (a mid-chain `USER chrome` reset by a later `USER root` is
/// legitimate — the shipped chrome example's shape). A bare `bool` argument
/// would not say that at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepRole {
    Intermediate,
    Final,
}

/// The facts the contract is checked against: everything C1–C4 need, and
/// nothing that requires opening a layer blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageFacts {
    /// `rootfs.diff_ids`, bottom-to-top — digests of the *uncompressed*
    /// layer tars, which is why they survive the zstd/gzip recompression the
    /// OCI exporter applies and are directly comparable between docker's
    /// store and the msb cache. Never the manifest's (compressed) blob
    /// digests.
    pub diff_ids: Vec<String>,
    /// OCI config `Env`, verbatim (`KEY=VALUE`).
    pub env: Vec<String>,
    /// OCI config `User`; an empty string is normalized to `None` so the two
    /// producers agree (docker reports `""`, an OCI config may omit it).
    pub user: Option<String>,
    /// `"<os>/<architecture>"`, e.g. `linux/arm64` — the same shape
    /// [`super::host_oci_platform`] produces, so C4 is a string equality
    /// against one source of truth.
    ///
    /// For an image agent-vm **built**, this restates the `--platform`
    /// agent-vm requested (`layer::run_buildx`), so it is not evidence about
    /// the image's contents; only a *base link*'s value is evidence about
    /// content. See [`check_base_image`] (C4a) and [`check_export_matches_host`]
    /// (C4c).
    pub platform: String,
}

/// The pair every C1/C2 comparison needs, in the only order that is
/// meaningful. Bundled so the two `&ImageFacts` cannot be transposed at a
/// call site (CODING_STANDARDS.md: "don't use the same type multiple times in
/// a row" — the same reasoning that produced [`super::BaseImage`]).
#[derive(Debug, Clone, Copy)]
pub struct BuiltOn<'a> {
    /// What the step was built `FROM`.
    pub predecessor: &'a ImageFacts,
    /// What the step actually produced.
    pub built: &'a ImageFacts,
}

impl ImageFacts {
    /// Parse the output of `docker image inspect <tag> --format '{{json .}}'`.
    ///
    /// Unknown fields are ignored, so a docker version that adds fields (or
    /// the containerd image store, which adds `Descriptor`) still parses.
    /// Every consumed field has an explicit emptiness check naming itself
    /// (see F12 in the plan): a renamed field must fail as a named error, not
    /// as a silently empty layer list.
    pub fn from_docker_inspect(stdout: &str) -> anyhow::Result<Self> {
        let source = stdout.trim();
        if source.is_empty() {
            bail!("`docker image inspect` produced empty output");
        }
        let inspect: DockerInspect = serde_json::from_str(source)
            .with_context(|| "parsing `docker image inspect` output as JSON")?;

        let diff_ids = inspect.root_fs.layers.unwrap_or_default();
        if diff_ids.is_empty() {
            bail!(
                "`docker image inspect` reported no .RootFS.Layers; the image has no filesystem \
                 layers, or this docker renamed the field"
            );
        }
        let os = inspect.os.unwrap_or_default();
        let architecture = inspect.architecture.unwrap_or_default();
        if os.is_empty() || architecture.is_empty() {
            bail!(
                "`docker image inspect` reported no .Os/.Architecture (os={os:?}, \
                 architecture={architecture:?})"
            );
        }
        // A document with *no* `Config` object at all means docker renamed or
        // dropped it, and reading that as "no Env, no User" would silently
        // disable C2 and satisfy C3 without anyone noticing (F12). An empty
        // `Config` object is fine — that is a legitimate image.
        let config = inspect.config.context(
            "`docker image inspect` reported no .Config object; the layer image contract cannot \
             read this image's Env or User (has docker renamed the field?)",
        )?;

        Ok(ImageFacts {
            diff_ids,
            env: config.env.unwrap_or_default(),
            user: normalize_user(config.user),
            platform: format!("{os}/{architecture}"),
        })
    }

    /// Facts from the record `microsandbox_image::load_archive` returned (or
    /// `GlobalCache::read_image_metadata_async` read back).
    ///
    /// `layers[].diff_id` is the config's `rootfs.diff_ids` verbatim (see
    /// `vendor/microsandbox/crates/image/lib/archive/docker.rs`'s early-gate
    /// metadata construction), so these facts are comparable, digest for
    /// digest, with the docker ones above. `architecture`/`os` are not on
    /// `ImageConfig`, so they are read structurally out of `raw_config_json`
    /// (mirroring that file's own private `raw_config_platform`).
    ///
    /// Unlike [`Self::from_docker_inspect`], no `.Config` emptiness check is
    /// needed: `md.config` is a typed `ImageConfig`, so a missing config is
    /// structurally impossible.
    pub fn from_cached_metadata(
        md: &microsandbox_image::CachedImageMetadata,
    ) -> anyhow::Result<Self> {
        let diff_ids: Vec<String> = md.layers.iter().map(|l| l.diff_id.clone()).collect();
        if diff_ids.is_empty() {
            bail!("the loaded image metadata records no layers");
        }
        let platform = raw_config_platform(&md.raw_config_json).with_context(|| {
            format!(
                "the loaded image's config records no os/architecture \
                 (raw_config_json = {:?})",
                md.raw_config_json
            )
        })?;

        Ok(ImageFacts {
            diff_ids,
            env: md.config.env.clone(),
            user: normalize_user(md.config.user.clone()),
            platform,
        })
    }
}

/// `""` means "unset" for both producers, so the two agree.
fn normalize_user(user: Option<String>) -> Option<String> {
    user.filter(|u| !u.is_empty())
}

/// `<os>/<architecture>` out of a raw OCI config document, if both are
/// present and non-empty. Mirrors the vendored `archive/docker.rs`'s private
/// `raw_config_platform`, which reads the same two fields — `ImageConfig`
/// itself does not carry them.
fn raw_config_platform(raw_config_json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(raw_config_json).ok()?;
    let architecture = value.get("architecture")?.as_str()?;
    let os = value.get("os")?.as_str()?;
    if architecture.is_empty() || os.is_empty() {
        return None;
    }
    Some(format!("{os}/{architecture}"))
}

/// The subset of `docker image inspect`'s document this module reads. Every
/// field is `#[serde(default)]` so a docker version that drops or renames
/// something fails in *our* named emptiness check rather than in serde, and
/// so unknown fields (`Descriptor`, `RepoDigests`, `GraphDriver`, …) are
/// ignored.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct DockerInspect {
    #[serde(rename = "RootFS")]
    root_fs: DockerRootFs,
    /// `Option`, unlike the other fields: a document with **no** `Config`
    /// object at all means docker renamed or dropped it, and silently reading
    /// that as "no Env, no User" would disable C2 and satisfy C3 without
    /// anyone noticing (F12). An empty `Config` object is fine — that is a
    /// legitimate image.
    #[serde(rename = "Config")]
    config: Option<DockerConfig>,
    #[serde(rename = "Architecture")]
    architecture: Option<String>,
    #[serde(rename = "Os")]
    os: Option<String>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct DockerRootFs {
    #[serde(rename = "Layers")]
    layers: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct DockerConfig {
    /// `null` is a legal docker value (and older daemons emit it), so this
    /// is an `Option` rather than a `Vec` with a default.
    #[serde(rename = "Env")]
    env: Option<Vec<String>>,
    #[serde(rename = "User")]
    user: Option<String>,
}

/// Enforce C1's image half, C2 and C4 on any built step, plus C3 when the
/// step is the one that will boot.
///
/// `host_platform` is passed rather than read from `std::env::consts` inside,
/// so the check is pure and both host families are unit-testable on either.
///
/// Check order is C1 → C4 → C2 → C3, first failure wins. C1 first because
/// "you did not build on your predecessor" makes the other three meaningless
/// (the observed config belongs to an unrelated image); C4 next because a
/// wrong-platform image explains everything downstream.
pub fn check_built_image(
    step: &ChainStep,
    role: StepRole,
    images: BuiltOn<'_>,
    host_platform: &str,
) -> Result<(), Violation> {
    let step = step_label(step);
    check_builds_on_predecessor(&step, images)?;
    check_export_matches_host(&step, images, host_platform)?;
    check_path_is_additive(&step, images)?;
    if role == StepRole::Final {
        check_ends_as_root(&step, images)?;
    }
    Ok(())
}

/// C4a: the base image a chain is built on must target the host platform.
///
/// This is the only image-level platform fact a chain has. Every image
/// agent-vm builds is exported with an explicit `--platform` (see
/// `layer::run_buildx`), and BuildKit stamps the exported config from that
/// *request* rather than from the layers' contents — so a built image's
/// `platform` restates what agent-vm asked for and can never contradict it
/// (that comparison survives as [`check_export_matches_host`], an assertion on
/// agent-vm's own pipeline, not a check on the layer).
///
/// The base link is different: it is a `docker pull <repo>@<digest>` or an
/// `import-image.sh` tag, so its `.Os`/`.Architecture` are the producer's
/// declaration about real content. An `amd64` base link on an `aarch64` host
/// makes every layer above it contain foreign binaries; buildx warns
/// (`InvalidBaseImagePlatform`) and builds anyway, and the guest dies with
/// `Exec format error` on the first exec. That is the failure issue #97 names
/// as C4's reason for existing.
///
/// Called once, from `layer::execute_chain`, after the base link's facts are
/// read and before the first build — and only when step 0 actually builds. A
/// change of base moves every step's tag (`plan_chain` anchors step 0's hash
/// on the base manifest digest), so a new base always re-runs this; above a
/// cached prefix it is skipped, which is the already-accepted grandfathering
/// hole (see the ADR amendment).
pub fn check_base_image(
    step: &ChainStep,
    base: &ImageFacts,
    host_platform: &str,
) -> Result<(), Violation> {
    if base.platform == host_platform {
        return Ok(());
    }
    Err(Violation {
        clause: Clause::TargetsHostPlatform,
        step: step_label(step),
        detail: format!(
            "the base image this chain builds on is a {} image on a {host_platform} host, so \
             every layer built on it would contain foreign binaries and the guest would fail \
             with `Exec format error`",
            base.platform
        ),
        fix: format!(
            "re-import the base image for this host: `./script/build/import-image.sh` (or point \
             AGENT_VM_IMAGE_TAG at a {host_platform} base)"
        ),
    })
}

/// `step 2/3 (.agent-vm/layers/20-b)`.
fn step_label(step: &ChainStep) -> String {
    format!("step {} ({})", step.id.position.human(), step.label)
}

/// C1: the built image's diff ids must start with the predecessor's, in order.
/// A hardcoded `FROM debian:bookworm` produces a completely different list, so
/// index 0 mismatches; a metadata-only step has an identical list and passes;
/// a step that *removes* a predecessor layer is shorter and fails.
fn check_builds_on_predecessor(step: &str, images: BuiltOn<'_>) -> Result<(), Violation> {
    let predecessor = images.predecessor.diff_ids.as_slice();
    let built = images.built.diff_ids.as_slice();
    if built.len() >= predecessor.len() && built[..predecessor.len()] == *predecessor {
        return Ok(());
    }

    let detail = match built.iter().zip(predecessor).position(|(b, p)| b != p) {
        Some(i) => format!(
            "the built image's filesystem layers do not extend the step it was built on: they \
             first differ at position {i} (predecessor {}, built {}), and the predecessor has \
             {} layers while the built image has {}",
            predecessor[i],
            built[i],
            predecessor.len(),
            built.len(),
        ),
        None => format!(
            "the built image has only {} filesystem layers but the step it was built on has {}; \
             a layer must keep every layer of its predecessor",
            built.len(),
            predecessor.len(),
        ),
    };
    Err(Violation {
        clause: Clause::BuildsOnPredecessor,
        step: step.to_string(),
        detail,
        fix: "make the last Dockerfile stage build FROM the previous step (`FROM ${BASE_IMAGE}` \
              with a global `ARG BASE_IMAGE`), not from a hardcoded image"
            .to_string(),
    })
}

/// C4c: an internal assertion that the image agent-vm exported carries the
/// platform agent-vm requested.
///
/// This **cannot detect a foreign layer**: `run_buildx` passes `--platform
/// <host_oci_platform()>` on every build, BuildKit stamps the exported config
/// from that *request*, and `load_archive` selects the host manifest — so all
/// three agree by construction and this comparison is unfalsifiable while they
/// do. It is kept as a tripwire for a future change that makes the build
/// platform configurable. The real platform checks are [`check_base_image`]
/// (C4a, the base link) and [`lint_step_dockerfile`]'s rule 3 (C4b, a pinned
/// `--platform` on the final `FROM`).
fn check_export_matches_host(
    step: &str,
    images: BuiltOn<'_>,
    host_platform: &str,
) -> Result<(), Violation> {
    let built = &images.built.platform;
    if built == host_platform {
        return Ok(());
    }
    Err(Violation {
        clause: Clause::TargetsHostPlatform,
        step: step.to_string(),
        detail: format!(
            "agent-vm built this step for {host_platform} but the exported image config says \
             {built}"
        ),
        fix: "this is an agent-vm bug, not a layer problem: report it with the Dockerfile and \
              `docker buildx version`"
            .to_string(),
    })
}

/// C2: every predecessor `PATH` directory must still be on the built `PATH`.
/// Set containment, not equality and not order — prepending a shadowing
/// directory stays legal (overriding a tool is a legitimate thing for a layer
/// to do); *removing* a directory is not.
fn check_path_is_additive(step: &str, images: BuiltOn<'_>) -> Result<(), Violation> {
    // A predecessor that declares no `PATH` imposes no directories on its
    // successor, so C2 is vacuously satisfied — this is the OCI semantics, not
    // a skipped check. Reaching here with a document that merely failed to
    // parse is impossible: `from_docker_inspect` rejects a missing `.Config`
    // outright.
    let Some(predecessor_path) = path_from_config_env(&images.predecessor.env) else {
        return Ok(());
    };
    let built_path = path_from_config_env(&images.built.env);
    let built_entries: Vec<&str> = built_path.as_deref().map(path_entries).unwrap_or_default();

    let missing: Vec<&str> = path_entries(&predecessor_path)
        .into_iter()
        .filter(|dir| !built_entries.contains(dir))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(Violation {
        clause: Clause::PathIsAdditive,
        step: step.to_string(),
        detail: format!(
            "the built image's PATH no longer contains {}, which the step it was built on \
             provided",
            missing.join(", ")
        ),
        fix: "prepend or append to $PATH (`ENV PATH=/opt/x/bin:$PATH`) instead of replacing it"
            .to_string(),
    })
}

/// C3: the final image's config `User` (before any `:group`) must be unset,
/// `root` or `0`. The group half is deliberately not checked: it cannot
/// demote a uid, uid 0 has full permissions regardless of gid, and agent-vm's
/// own guest-identity machinery appends its own passwd/group entries at launch
/// anyway (ADR-0001/0002).
fn check_ends_as_root(step: &str, images: BuiltOn<'_>) -> Result<(), Violation> {
    // An OCI config with no `User` runs as root by definition, which is
    // exactly what C3 requires; an image whose inspect document merely omitted
    // `.Config.User` cannot reach here, because `from_docker_inspect` rejects a
    // missing `.Config` outright.
    let Some(user) = images.built.user.as_deref() else {
        return Ok(());
    };
    let name = user.split(':').next().unwrap_or("");
    if name.is_empty() || name == "root" || name == "0" {
        return Ok(());
    }
    Err(Violation {
        clause: Clause::EndsAsRoot,
        step: step.to_string(),
        detail: format!(
            "the built image's config sets User={user:?}, so a --root launch would run every \
             command as that user instead of root"
        ),
        fix: "end the Dockerfile with `USER root`".to_string(),
    })
}

/// Pulls the `PATH=` value out of an OCI config `Env` vector. The *last*
/// `PATH=` entry wins, matching how a shell applies successive assignments —
/// an image config can legally list `PATH` more than once across
/// base+derived `ENV` layers. Shared by C2 and by `run.rs`'s guest-PATH read
/// so the two can never disagree about which entry is in effect.
pub(crate) fn path_from_config_env(env: &[String]) -> Option<String> {
    env.iter()
        .filter_map(|e| e.strip_prefix("PATH="))
        .next_back()
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

/// Non-empty, `:`-separated entries of a `PATH` value. Empty segments (which
/// POSIX reads as "the current directory") are dropped: they are not a
/// directory a predecessor can lose.
fn path_entries(path: &str) -> Vec<&str> {
    path.split(':').filter(|s| !s.is_empty()).collect()
}

/// C1's fast half (plus C4's text half): the step's Dockerfile text must let
/// agent-vm choose the base and the platform. Checked before the confirmation
/// prompt, so a hardcoded `FROM` or a pinned `--platform` costs microseconds
/// instead of a confirmed multi-minute build, and gives an error the
/// image-level check cannot phrase ("line 2 says `FROM debian:bookworm`").
///
/// Three rules, all on the *last* `FROM` (the stage a plain
/// `docker buildx build` actually exports — a multi-stage layer with an
/// intermediate `FROM golang:1.22 AS builder` is legitimate and must pass):
///
/// 1. a global `ARG BASE_IMAGE` is declared before the first `FROM`;
/// 2. its image argument references `$BASE_IMAGE` / `${BASE_IMAGE}`;
/// 3. it does not pin `--platform=` to anything but `$TARGETPLATFORM` (C4b):
///    agent-vm already passes `--platform <host>`, and a `FROM
///    --platform=linux/amd64` re-bases the exported rootfs on foreign content
///    while BuildKit still stamps the export with the host platform, so no
///    image-level check can see it.
///
/// Rule 1 requires *global* scope (before the first `FROM`) because that is
/// Docker's own rule: an `ARG` declared inside a stage is out of scope for a
/// later stage's `FROM` line, so it cannot actually supply `BASE_IMAGE` there.
/// Rule 3 deliberately does **not** look at earlier stages: `FROM
/// --platform=$BUILDPLATFORM … AS builder` is the standard cross-compile idiom
/// and its output may legitimately be host-targeted.
///
/// Deliberately not a Dockerfile parser: it joins `\`-continuations, drops
/// comments and blank lines, and matches instruction keywords
/// case-insensitively (Docker's own rule) while treating the *variable* name
/// case-sensitively (Docker's rule too — `${base_image}` is a different
/// variable and would expand to nothing). `FROM` flags (`--platform=…`) are
/// skipped before reading the image argument.
///
/// A multi-stage layer whose *final* stage is `FROM scratch` (or `FROM
/// builder`) is **correctly rejected** even if an earlier stage used
/// `${BASE_IMAGE}`: what `--output type=docker|oci` exports is the last stage,
/// and an image that does not contain the base's layers is precisely the C1
/// violation this clause exists for — the image-level check would reject it a
/// build later. Do not "fix" this into a false negative.
pub fn lint_step_dockerfile(step: &ChainStep, text: &str) -> Result<(), Violation> {
    let instructions = logical_instructions(text);

    let mut arg_base_image_global = false;
    let mut first_from_seen = false;
    let mut last_from_image: Option<String> = None;
    let mut last_from_platform: Option<String> = None;
    for words in &instructions {
        let Some(keyword) = words.first() else {
            continue;
        };
        if keyword.eq_ignore_ascii_case("ARG") {
            if !first_from_seen {
                // Docker's `ARG <name>[=<v>] [<name>[=<v>]…]` declares every
                // name on the line, so any of the words after the keyword may
                // be `BASE_IMAGE` (MINOR-6).
                let declares_base_image = words
                    .iter()
                    .skip(1)
                    .any(|w| w.split('=').next() == Some("BASE_IMAGE"));
                if declares_base_image {
                    arg_base_image_global = true;
                }
            }
            continue;
        }
        if keyword.eq_ignore_ascii_case("FROM") {
            first_from_seen = true;
            last_from_platform = words
                .iter()
                .skip(1)
                .find_map(|w| w.strip_prefix("--platform=").map(ToString::to_string));
            last_from_image = words
                .iter()
                .skip(1)
                .find(|word| !word.starts_with("--"))
                .cloned();
        }
    }

    let Some(image) = last_from_image else {
        return Err(lint_violation(
            step,
            Clause::BuildsOnPredecessor,
            "its Dockerfile has no FROM instruction".to_string(),
            C1_FIX,
        ));
    };
    // Rules 1 and 2 run before rule 3 so a hardcoded `FROM` reports C1 first:
    // C1 remains the most fundamental failure.
    if !arg_base_image_global {
        return Err(lint_violation(
            step,
            Clause::BuildsOnPredecessor,
            "no global \"ARG BASE_IMAGE\" is declared before the first FROM".to_string(),
            C1_FIX,
        ));
    }
    if !references_base_image(&image) {
        return Err(lint_violation(
            step,
            Clause::BuildsOnPredecessor,
            format!("its final FROM names {image:?}"),
            C1_FIX,
        ));
    }
    if let Some(platform) = last_from_platform
        && !matches!(platform.as_str(), "$TARGETPLATFORM" | "${TARGETPLATFORM}")
    {
        return Err(lint_violation(
            step,
            Clause::TargetsHostPlatform,
            format!(
                "its final FROM pins --platform={platform}; agent-vm builds every step for \
                 the host platform, and BuildKit would still stamp the exported image with \
                 the host platform while its layers came from {platform}"
            ),
            "delete the --platform flag from the final FROM (or write \
             --platform=$TARGETPLATFORM); agent-vm passes --platform for the host itself",
        ));
    }
    Ok(())
}

/// Whether a `FROM` image argument actually resolves `${BASE_IMAGE}`. Written
/// against the literal variable name (case-sensitive) so `${base_image}` —
/// which Docker would expand to nothing — is rejected.
fn references_base_image(image: &str) -> bool {
    image.contains("${BASE_IMAGE}") || image.contains("$BASE_IMAGE")
}

/// The canonical two lines a C1 lint failure tells the author to write. One
/// definition so all three C1 lint failures share exactly the same fix text.
const C1_FIX: &str = "declare a global ARG before the first FROM and build FROM it:\n  \
                      ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-template:latest\n  \
                      FROM ${BASE_IMAGE}";

fn lint_violation(step: &ChainStep, clause: Clause, detail: String, fix: &str) -> Violation {
    Violation {
        clause,
        step: step_label(step),
        detail,
        fix: fix.to_string(),
    }
}

/// Splits a Dockerfile into logical instructions: `\`-continuations joined,
/// comment and blank lines dropped, each instruction's whitespace-separated
/// words.
fn logical_instructions(text: &str) -> Vec<Vec<String>> {
    let mut instructions = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        let trimmed = raw.trim();
        // A `#` line is a comment (including the `# syntax=…` parser
        // directive) — but only at the *start* of an instruction, never in
        // the middle of a `\`-continuation.
        if current.is_empty() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        let (line, continues) = match raw.trim_end().strip_suffix('\\') {
            Some(without_continuation) => (without_continuation, true),
            None => (raw, false),
        };
        current.push_str(line);
        if continues {
            current.push(' ');
        } else {
            let words: Vec<String> = current
                .split_whitespace()
                .map(ToString::to_string)
                .collect();
            if !words.is_empty() {
                instructions.push(words);
            }
            current.clear();
        }
    }
    let tail: Vec<String> = current
        .split_whitespace()
        .map(ToString::to_string)
        .collect();
    if !tail.is_empty() {
        instructions.push(tail);
    }
    instructions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{ChainPosition, LayerIdentity};
    use std::path::{Path, PathBuf};

    // Fixtures shared with `layer`'s own e2e harness, promoted into
    // `layer::test_support` by issue #102.
    use crate::layer::test_support::{
        DockerTagGuard, E2eBase, docker_tag_exists, e2e_base_fixture, e2e_nonce, first_of_one,
        write_layer_file,
    };
    // The engine the contract's live proof drives. These are `layer`'s own items;
    // a child module may name its ancestor's private ones (`host_oci_platform`),
    // which is why none of them needed a visibility change for this move.
    use crate::layer::{
        build_derived_docker, build_derived_oci, derived_is_cached, discard_derived_image,
        docker_image_facts, ensure_docker_buildx, final_image_facts, host_oci_platform,
        load_derived_image, resolve,
    };

    /// The platform `check` supplies as "this host" for the check tests.
    /// Deliberately not `host_oci_platform()`: the check is pure, and pinning
    /// a literal keeps both host families testable on either.
    const HOST: &str = "linux/arm64";

    fn chain_step(index: usize, total: usize) -> ChainStep {
        ChainStep {
            id: LayerIdentity {
                dir: PathBuf::from(format!("/proj/.agent-vm/layers/{index}")),
                dockerfile: PathBuf::from(format!("/proj/.agent-vm/layers/{index}/Dockerfile")),
                tag: format!("agent-vm-layer:proj-tag{index}"),
                hash: format!("hash{index}"),
                file_count: 1,
                hashed_bytes: 1,
                position: ChainPosition { index, total },
            },
            label: format!(".agent-vm/layers/{index}"),
        }
    }

    fn facts(diff_ids: &[&str]) -> ImageFacts {
        ImageFacts {
            diff_ids: diff_ids.iter().map(|s| (*s).to_string()).collect(),
            env: Vec::new(),
            user: None,
            platform: HOST.to_string(),
        }
    }

    fn with_env(mut facts: ImageFacts, env: &[&str]) -> ImageFacts {
        facts.env = env.iter().map(|s| (*s).to_string()).collect();
        facts
    }

    /// The check under test, on step 2/3, against `HOST`.
    fn check(pred: &ImageFacts, built: &ImageFacts, role: StepRole) -> Result<(), Violation> {
        check_built_image(
            &chain_step(1, 3),
            role,
            BuiltOn {
                predecessor: pred,
                built,
            },
            HOST,
        )
    }

    fn lint(text: &str) -> Result<(), Violation> {
        lint_step_dockerfile(&chain_step(1, 3), text)
    }

    // --- ImageFacts::from_docker_inspect() (tests 1–3) ---

    /// A real `docker image inspect debian:13-slim --format '{{json .}}'`
    /// document (one layer, arm64, no `User`), trimmed of a few fields this
    /// module never reads while keeping enough of them (`RepoTags`,
    /// `Descriptor`) to prove unknown fields are ignored. A docker release
    /// that changes the shape fails here rather than on a user's build.
    const REAL_DOCKER_INSPECT: &str = r#"{"Id":"sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132","RepoTags":["debian:13-slim"],"RepoDigests":["debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132"],"Comment":"debuerreotype 0.17","Created":"2026-08-24T00:00:00Z","Config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["bash"]},"Architecture":"arm64","Variant":"v8","Os":"linux","Size":30170062,"RootFS":{"Type":"layers","Layers":["sha256:41d6505109809884e681a97f978542a2d4d3506af0124f18b3f3a471edfcc9b7"]},"Metadata":{"LastTagTime":"2026-09-11T22:27:12.266800212Z"},"Descriptor":{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132","size":8973}}"#;

    #[test]
    fn from_docker_inspect_reads_a_real_document() {
        let got = ImageFacts::from_docker_inspect(REAL_DOCKER_INSPECT).unwrap();
        assert_eq!(
            got,
            ImageFacts {
                diff_ids: vec![
                    "sha256:41d6505109809884e681a97f978542a2d4d3506af0124f18b3f3a471edfcc9b7"
                        .to_string()
                ],
                env: vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()
                ],
                user: None,
                platform: "linux/arm64".to_string(),
            }
        );
    }

    #[test]
    fn from_docker_inspect_normalizes_null_env_and_empty_user() {
        let doc = r#"{"Config":{"Env":null,"User":""},"Architecture":"arm64","Os":"linux","RootFS":{"Layers":["sha256:a"]}}"#;
        let got = ImageFacts::from_docker_inspect(doc).unwrap();
        assert_eq!(got.env, Vec::<String>::new());
        assert_eq!(got.user, None);
    }

    #[test]
    fn from_docker_inspect_rejects_missing_fields_and_empty_output() {
        let no_layers = r#"{"Config":{},"Architecture":"arm64","Os":"linux","RootFS":{}}"#;
        let err = ImageFacts::from_docker_inspect(no_layers).unwrap_err();
        assert!(format!("{err:#}").contains(".RootFS.Layers"), "{err:#}");

        let err = ImageFacts::from_docker_inspect("").unwrap_err();
        assert!(format!("{err:#}").contains("empty output"), "{err:#}");

        // The trailing newline `docker` prints must not matter.
        let doc = format!(
            "{}\n",
            r#"{"Config":{},"Architecture":"arm64","Os":"linux","RootFS":{"Layers":["sha256:a"]}}"#
        );
        assert!(ImageFacts::from_docker_inspect(&doc).is_ok());
    }

    #[test]
    fn from_docker_inspect_rejects_a_document_without_a_config_object() {
        // A *missing* `.Config` is the F12 fail-open hole: reading it as "no
        // Env, no User" would silently disable C2 and satisfy C3. An empty
        // `Config` object stays legal (see the sibling tests).
        let doc = r#"{"Architecture":"arm64","Os":"linux","RootFS":{"Layers":["sha256:a"]}}"#;
        let err = ImageFacts::from_docker_inspect(doc).unwrap_err();
        assert!(format!("{err:#}").contains(".Config"), "{err:#}");
    }

    // --- ImageFacts::from_cached_metadata() (test 4) ---

    fn cached_metadata(raw_config_json: &str) -> microsandbox_image::CachedImageMetadata {
        use microsandbox_image::{CachedImageMetadata, CachedLayerMetadata, ImageConfig};
        CachedImageMetadata {
            manifest_digest: "sha256:manifest".to_string(),
            config_digest: "sha256:config".to_string(),
            raw_manifest_json: "{}".to_string(),
            raw_config_json: raw_config_json.to_string(),
            config: ImageConfig::default(),
            layers: vec![
                CachedLayerMetadata {
                    digest: "sha256:compressed-a".to_string(),
                    media_type: Some("application/vnd.oci.image.layer.v1.tar+zstd".to_string()),
                    size_bytes: Some(1),
                    diff_id: "sha256:layer-a".to_string(),
                },
                CachedLayerMetadata {
                    digest: "sha256:compressed-b".to_string(),
                    media_type: None,
                    size_bytes: None,
                    diff_id: "sha256:layer-b".to_string(),
                },
            ],
        }
    }

    #[test]
    fn from_cached_metadata_maps_diff_ids_in_order_and_reads_the_platform() {
        let md = cached_metadata(r#"{"architecture":"arm64","os":"linux"}"#);
        let got = ImageFacts::from_cached_metadata(&md).unwrap();
        assert_eq!(
            got.diff_ids,
            vec!["sha256:layer-a".to_string(), "sha256:layer-b".to_string()]
        );
        assert_eq!(got.platform, "linux/arm64");
        assert_eq!(got.user, None);
        assert_eq!(got.env, Vec::<String>::new());
    }

    #[test]
    fn from_cached_metadata_errors_without_an_architecture() {
        let md = cached_metadata(r#"{"os":"linux"}"#);
        let err = ImageFacts::from_cached_metadata(&md).unwrap_err();
        assert!(format!("{err:#}").contains("os/architecture"), "{err:#}");
    }

    // --- cross-producer mapping (test 5) ---

    #[test]
    fn the_two_producers_map_the_same_image_to_the_same_facts() {
        // Same image: same diff ids (uncompressed), same env, same user, same
        // arch/os. Pins the *mapping* — the reality of the cross-store
        // assumption is e2e test 43.
        let mut md = cached_metadata(r#"{"architecture":"arm64","os":"linux"}"#);
        md.config.env = vec!["PATH=/a:/b".to_string()];
        let doc = r#"{"Config":{"Env":["PATH=/a:/b"],"User":""},"Architecture":"arm64","Os":"linux","RootFS":{"Layers":["sha256:layer-a","sha256:layer-b"]}}"#;

        assert_eq!(
            ImageFacts::from_cached_metadata(&md).unwrap(),
            ImageFacts::from_docker_inspect(doc).unwrap(),
        );
    }

    // --- C1 (tests 6–10) ---

    #[test]
    fn c1_accepts_a_prefix_plus_anything() {
        let pred = facts(&["a", "b", "c"]);
        // Equal (a metadata-only step) and strict extensions both pass.
        check(&pred, &facts(&["a", "b", "c"]), StepRole::Final).unwrap();
        check(&pred, &facts(&["a", "b", "c", "d"]), StepRole::Final).unwrap();
        check(&pred, &facts(&["a", "b", "c", "d", "e"]), StepRole::Final).unwrap();
    }

    #[test]
    fn c1_rejects_a_first_element_mismatch_naming_index_zero() {
        let err = check(
            &facts(&["a", "b", "c"]),
            &facts(&["x", "a", "b"]),
            StepRole::Final,
        )
        .unwrap_err();
        assert_eq!(err.clause, Clause::BuildsOnPredecessor);
        assert!(err.detail.contains("position 0"), "{}", err.detail);
    }

    #[test]
    fn c1_rejects_a_mid_list_mismatch_naming_the_index() {
        let err = check(
            &facts(&["a", "b", "c"]),
            &facts(&["a", "b", "x", "d"]),
            StepRole::Final,
        )
        .unwrap_err();
        assert_eq!(err.clause, Clause::BuildsOnPredecessor);
        assert!(err.detail.contains("position 2"), "{}", err.detail);
    }

    #[test]
    fn c1_rejects_a_built_image_shorter_than_its_predecessor() {
        let err = check(
            &facts(&["a", "b", "c"]),
            &facts(&["a", "b"]),
            StepRole::Final,
        )
        .unwrap_err();
        assert!(err.detail.contains("only 2"), "{}", err.detail);
        assert!(err.detail.contains("has 3"), "{}", err.detail);
    }

    #[test]
    fn c1_rejects_a_reordered_predecessor() {
        let err = check(
            &facts(&["a", "b", "c"]),
            &facts(&["b", "a", "c"]),
            StepRole::Final,
        )
        .unwrap_err();
        assert_eq!(err.clause, Clause::BuildsOnPredecessor);
        assert!(err.detail.contains("position 0"), "{}", err.detail);
    }

    // --- C2 (tests 11–16) ---

    const BASE_PATH: &str = "/opt/agent/.local/bin:/usr/local/bin:/usr/bin:/usr/sbin:/bin";

    fn path_facts(diff_ids: &[&str], path: &str) -> ImageFacts {
        with_env(facts(diff_ids), &[&format!("PATH={path}")])
    }

    #[test]
    fn c2_accepts_any_superset_regardless_of_order() {
        let pred = path_facts(&["a"], BASE_PATH);
        for built in [
            BASE_PATH.to_string(),
            format!("/opt/x/bin:{BASE_PATH}"),
            format!("{BASE_PATH}:/opt/x/bin"),
            format!("/usr/bin:{BASE_PATH}"),
        ] {
            check(&pred, &path_facts(&["a", "b"], &built), StepRole::Final).unwrap();
        }
    }

    #[test]
    fn c2_rejects_a_dropped_directory_and_lists_every_missing_one() {
        let pred = path_facts(&["a"], "/a:/b:/c");
        let err = check(&pred, &path_facts(&["a", "b"], "/a"), StepRole::Final).unwrap_err();
        assert_eq!(err.clause, Clause::PathIsAdditive);
        assert!(err.detail.contains("/b"), "{}", err.detail);
        assert!(err.detail.contains("/c"), "{}", err.detail);
    }

    #[test]
    fn c2_is_vacuous_when_the_predecessor_declares_no_path() {
        let pred = facts(&["a"]);
        let built = with_env(facts(&["a", "b"]), &["PATH=/only/mine"]);
        check(&pred, &built, StepRole::Final).unwrap();
    }

    #[test]
    fn c2_rejects_a_built_image_that_dropped_path_entirely() {
        let pred = path_facts(&["a"], BASE_PATH);
        let err = check(&pred, &facts(&["a", "b"]), StepRole::Final).unwrap_err();
        assert_eq!(err.clause, Clause::PathIsAdditive);
    }

    #[test]
    fn c2_uses_the_last_path_entry_on_both_sides() {
        // The last assignment wins, so the predecessor's effective PATH is
        // `/last` and a built image that keeps only `/last` is fine.
        let pred = with_env(facts(&["a"]), &["PATH=/keep:/also", "PATH=/last"]);
        let built = with_env(facts(&["a", "b"]), &["PATH=/last:/x"]);
        check(&pred, &built, StepRole::Final).unwrap();

        // Reversed: now `/keep:/also` is in effect and the built image drops
        // both.
        let pred = with_env(facts(&["a"]), &["PATH=/last", "PATH=/keep:/also"]);
        let built = with_env(facts(&["a", "b"]), &["PATH=/last:/x"]);
        let err = check(&pred, &built, StepRole::Final).unwrap_err();
        assert!(err.detail.contains("/keep"), "{}", err.detail);
        assert!(err.detail.contains("/also"), "{}", err.detail);
    }

    #[test]
    fn c2_ignores_empty_path_segments_on_both_sides() {
        let pred = path_facts(&["a"], "/a::/b");
        check(&pred, &path_facts(&["a", "b"], "/a:/b"), StepRole::Final).unwrap();
    }

    // --- C3 (tests 17–19) ---

    fn user_facts(user: Option<&str>) -> ImageFacts {
        let mut facts = facts(&["a", "b"]);
        facts.user = user.map(ToString::to_string);
        facts
    }

    #[test]
    fn c3_accepts_unset_root_and_the_numeric_root() {
        for user in [
            None,
            Some(""),
            Some("root"),
            Some("0"),
            Some("0:0"),
            Some("root:root"),
        ] {
            check(&facts(&["a"]), &user_facts(user), StepRole::Final)
                .unwrap_or_else(|e| panic!("user {user:?} must pass C3: {e}"));
        }
    }

    #[test]
    fn c3_rejects_a_non_root_user_on_the_final_step() {
        for user in ["chrome", "9999", "chrome:chrome"] {
            let err = check(&facts(&["a"]), &user_facts(Some(user)), StepRole::Final)
                .err()
                .unwrap_or_else(|| panic!("user {user:?} must fail C3, got Ok"));
            assert_eq!(err.clause, Clause::EndsAsRoot);
        }
    }

    #[test]
    fn c3_does_not_apply_to_an_intermediate_step() {
        // Decision D5: a mid-chain `USER chrome` reset by a later `USER root`
        // is legitimate — the shipped chrome example's shape.
        check(
            &facts(&["a"]),
            &user_facts(Some("chrome")),
            StepRole::Intermediate,
        )
        .unwrap();
    }

    // --- C4c (the internal export assertion) ---

    #[test]
    fn c4c_export_assertion_rejects_a_stamp_that_is_not_the_host() {
        // This proves the comparison, not that the operand can vary: the real
        // C4 enforcement tests are `c4a_*` and
        // `lint_rejects_a_pinned_platform_on_the_final_from`.
        let pred = facts(&["a"]);
        check(&pred, &facts(&["a", "b"]), StepRole::Final).unwrap();

        let mut wrong_arch = facts(&["a", "b"]);
        wrong_arch.platform = "linux/amd64".to_string();
        let err = check(&pred, &wrong_arch, StepRole::Final).unwrap_err();
        assert_eq!(err.clause, Clause::TargetsHostPlatform);
        assert!(err.detail.contains("linux/amd64"), "{}", err.detail);
        assert!(err.detail.contains(HOST), "{}", err.detail);

        let mut wrong_os = facts(&["a", "b"]);
        wrong_os.platform = "windows/arm64".to_string();
        let err = check(&pred, &wrong_os, StepRole::Final).unwrap_err();
        assert_eq!(err.clause, Clause::TargetsHostPlatform);
        assert!(err.detail.contains("windows/arm64"), "{}", err.detail);
    }

    // --- C4a (the base link's platform) ---

    #[test]
    fn c4a_rejects_a_foreign_base_link_naming_both_platforms() {
        let mut base = facts(&["a", "b", "c"]);
        base.platform = "linux/amd64".to_string();

        let err = check_base_image(&chain_step(0, 1), &base, HOST).unwrap_err();
        assert_eq!(err.clause, Clause::TargetsHostPlatform);
        assert!(err.detail.contains("linux/amd64"), "{}", err.detail);
        assert!(err.detail.contains(HOST), "{}", err.detail);
        assert!(err.detail.contains("base"), "{}", err.detail);
    }

    #[test]
    fn c4a_accepts_a_host_platform_base_link() {
        check_base_image(&chain_step(0, 1), &facts(&["a", "b", "c"]), HOST).unwrap();
    }

    // --- precedence (test 21) ---

    #[test]
    fn an_image_violating_several_clauses_reports_c1_first() {
        let pred = path_facts(&["a", "b", "c"], BASE_PATH);
        let mut built = with_env(facts(&["x"]), &["PATH=/only/mine"]);
        built.platform = "linux/amd64".to_string();
        built.user = Some("chrome".to_string());
        let err = check(&pred, &built, StepRole::Final).unwrap_err();
        assert_eq!(err.clause, Clause::BuildsOnPredecessor);
    }

    // --- lint_step_dockerfile() (tests 22–29) ---

    const CANONICAL: &str =
        "ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-template:latest\nFROM ${BASE_IMAGE}\n";

    #[test]
    fn lint_accepts_the_canonical_forms() {
        for text in [
            CANONICAL.to_string(),
            "ARG BASE_IMAGE=base\nFROM $BASE_IMAGE\n".to_string(),
            "ARG BASE_IMAGE=base\nFROM --platform=$TARGETPLATFORM ${BASE_IMAGE}\n".to_string(),
            "ARG BASE_IMAGE=base\nFROM --platform=${TARGETPLATFORM} ${BASE_IMAGE}\n".to_string(),
            "ARG BASE_IMAGE=base\nFROM ${BASE_IMAGE} AS final\n".to_string(),
            "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n".to_string(),
        ] {
            lint(&text).unwrap_or_else(|e| panic!("must pass: {text:?}\n{e}"));
        }
    }

    #[test]
    fn lint_accepts_a_multi_name_global_arg() {
        // Docker's `ARG <name>[=<v>] [<name>[=<v>]…]` declares every name on
        // the line (MINOR-6), so a preceding name must not hide `BASE_IMAGE`.
        lint("ARG TARGETARCH BASE_IMAGE=base\nFROM ${BASE_IMAGE}\n").unwrap();
    }

    #[test]
    fn lint_rejects_a_pinned_platform_on_the_final_from() {
        // C4b: a pinned platform on the exported stage re-bases the rootfs on
        // foreign content while BuildKit still stamps the export with the host
        // platform, so no image-level check can see it.
        for text in [
            "ARG BASE_IMAGE=base\nFROM --platform=linux/amd64 ${BASE_IMAGE}\n",
            "ARG BASE_IMAGE=base\nFROM --platform=$BUILDPLATFORM ${BASE_IMAGE}\n",
        ] {
            let err = lint(text).unwrap_err();
            assert_eq!(err.clause, Clause::TargetsHostPlatform, "{text:?}");
        }
        let err =
            lint("ARG BASE_IMAGE=base\nFROM --platform=linux/amd64 ${BASE_IMAGE}\n").unwrap_err();
        assert!(err.detail.contains("linux/amd64"), "{}", err.detail);
    }

    #[test]
    fn lint_accepts_a_platform_flag_only_on_an_earlier_stage() {
        // `FROM --platform=$BUILDPLATFORM … AS builder` is the standard
        // cross-compile idiom; only the exported (last) stage is checked.
        lint(
            "ARG BASE_IMAGE=base\nFROM --platform=$BUILDPLATFORM golang:1.22 AS builder\n\
             RUN true\nFROM ${BASE_IMAGE}\n",
        )
        .unwrap();
    }

    #[test]
    fn a_hardcoded_from_with_a_pinned_platform_reports_c1_first() {
        // Rule ordering: C1 is the most fundamental failure, so it wins even
        // when the same FROM also pins a platform.
        let err =
            lint("ARG BASE_IMAGE=base\nFROM --platform=linux/amd64 debian:bookworm\n").unwrap_err();
        assert_eq!(err.clause, Clause::BuildsOnPredecessor);
        assert!(err.detail.contains("debian:bookworm"), "{}", err.detail);
    }

    #[test]
    fn lint_looks_only_at_the_last_stage_and_rejects_a_non_base_last_stage() {
        // A multi-stage layer whose exported (last) stage builds FROM the base
        // is legitimate.
        lint("ARG BASE_IMAGE=base\nFROM golang:1.22 AS builder\nRUN true\nFROM ${BASE_IMAGE}\n")
            .unwrap();

        // Reversed — the last stage is the builder, not the base.
        let err = lint(
            "ARG BASE_IMAGE=base\nFROM ${BASE_IMAGE} AS base-stage\nFROM golang:1.22 AS builder\n",
        )
        .unwrap_err();
        assert!(err.detail.contains("golang:1.22"), "{}", err.detail);

        // `FROM scratch` last is intended to be rejected: what gets exported
        // is the last stage, and it does not contain the base.
        let err = lint("ARG BASE_IMAGE=base\nFROM ${BASE_IMAGE} AS base-stage\nFROM scratch\n")
            .unwrap_err();
        assert!(err.detail.contains("scratch"), "{}", err.detail);
    }

    #[test]
    fn lint_rejects_a_hardcoded_final_from_quoting_the_literal() {
        let err = lint(
            "ARG BASE_IMAGE=ghcr.io/wirenboard/agent-vm-template:latest\n\
             FROM debian:bookworm\n",
        )
        .unwrap_err();
        assert_eq!(err.clause, Clause::BuildsOnPredecessor);
        assert!(err.detail.contains("\"debian:bookworm\""), "{}", err.detail);
    }

    #[test]
    fn lint_rejects_a_missing_or_late_global_arg() {
        let err = lint("FROM ${BASE_IMAGE}\n").unwrap_err();
        assert!(
            err.detail.contains("before the first FROM"),
            "{}",
            err.detail
        );

        let err = lint("FROM ${BASE_IMAGE}\nARG BASE_IMAGE=base\n").unwrap_err();
        assert!(
            err.detail.contains("before the first FROM"),
            "{}",
            err.detail
        );

        // An ARG inside an earlier stage is not global: Docker puts it out of
        // scope for a later FROM.
        let err = lint("FROM golang:1.22 AS builder\nARG BASE_IMAGE=base\nFROM ${BASE_IMAGE}\n")
            .unwrap_err();
        assert!(
            err.detail.contains("before the first FROM"),
            "{}",
            err.detail
        );
    }

    #[test]
    fn lint_is_case_sensitive_about_the_variable_name() {
        let err = lint("ARG BASE_IMAGE=base\nFROM ${base_image}\n").unwrap_err();
        assert!(err.detail.contains("${base_image}"), "{}", err.detail);
    }

    #[test]
    fn lint_handles_comments_blank_lines_directives_and_continuations() {
        lint(
            "# syntax=docker/dockerfile:1\n\n   # a comment\n\
             ARG BASE_IMAGE=base\n\
             FROM \\\n                 ${BASE_IMAGE}\n",
        )
        .unwrap();
    }

    #[test]
    fn lint_rejects_an_empty_dockerfile() {
        let err = lint("\n# only a comment\n").unwrap_err();
        assert!(err.detail.contains("no FROM instruction"), "{}", err.detail);
    }

    #[test]
    fn shipped_example_layers_pass_the_dockerfile_lint() {
        let root = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/layers"
        ));
        let mut count = 0;
        for entry in std::fs::read_dir(root).expect("read examples/layers") {
            let dockerfile = entry.unwrap().path().join("Dockerfile");
            if !dockerfile.is_file() {
                continue;
            }
            count += 1;
            let text = std::fs::read_to_string(&dockerfile).unwrap();
            if let Err(violation) = lint(&text) {
                panic!(
                    "shipped example {} violates the C1 lint: {violation}",
                    dockerfile.display()
                );
            }
        }
        // The repo ships exactly four today (`chrome-devtools`, `go-dev`,
        // `rust-dev`, `wirenboard-cpp`). If a future change leaves only one,
        // lower this bound deliberately rather than deleting the assertion.
        assert!(
            count >= 4,
            "expected at least four shipped example layers, found {count}"
        );
    }

    // --- Violation::Display (test 30) ---

    #[test]
    fn violation_display_names_the_clause_step_fix_and_adr() {
        let err = check(
            &path_facts(&["a"], "/a:/b"),
            &path_facts(&["a", "b"], "/a"),
            StepRole::Final,
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("C2"), "{text}");
        assert!(text.contains("keeps PATH additive"), "{text}");
        assert!(text.contains("step 2/3 (.agent-vm/layers/1)"), "{text}");
        assert!(text.contains("Fix:"), "{text}");
        assert!(text.contains(ADR), "{text}");
        assert!(text.contains("The layer image contract"), "{text}");
    }

    // --- property tests (m5): the two highest-value invariants of the
    //     module's total pure functions. The lint's invariants are enumerable
    //     and already table-driven, so it is not proptested here.

    proptest::proptest! {
        #[test]
        fn c1_accepts_any_prefix_plus_tail_and_rejects_a_mutated_prefix_index(
            prefix in proptest::collection::vec("[a-z0-9]{1,6}", 1..6),
            tail in proptest::collection::vec("[a-z0-9]{1,6}", 0..6),
            index_pick in proptest::prelude::any::<proptest::sample::Index>(),
        ) {
            // Distinct sentinels (`pred-`/`tail-`/`mutated-`) keep a mutated
            // element from coincidentally equalling a real one.
            let pred = ImageFacts {
                diff_ids: prefix
                    .iter()
                    .enumerate()
                    .map(|(i, s)| format!("pred-{i}-{s}"))
                    .collect(),
                env: Vec::new(),
                user: None,
                platform: HOST.to_string(),
            };
            let mut built = pred.clone();
            built.diff_ids.extend(
                tail.iter()
                    .enumerate()
                    .map(|(i, s)| format!("tail-{i}-{s}")),
            );
            check(&pred, &built, StepRole::Final).unwrap();

            let i = index_pick.index(prefix.len());
            built.diff_ids[i] = format!("mutated-{i}");
            let err = check(&pred, &built, StepRole::Final).unwrap_err();
            proptest::prop_assert_eq!(err.clause, Clause::BuildsOnPredecessor);
            proptest::prop_assert!(
                err.detail.contains(&format!("position {i}")),
                "detail must name index {}: {}",
                i,
                err.detail
            );
        }

        #[test]
        fn c2_accepts_any_superset_ordering_and_rejects_removing_an_entry(
            entries in proptest::collection::vec("[a-z0-9]{1,6}", 1..6),
            extra in proptest::collection::vec("[a-z0-9]{1,6}", 0..4),
            index_pick in proptest::prelude::any::<proptest::sample::Index>(),
        ) {
            let mut pred_entries: Vec<String> = entries.iter().map(|s| format!("/e-{s}")).collect();
            pred_entries.sort();
            pred_entries.dedup();
            proptest::prop_assume!(!pred_entries.is_empty());

            let pred = path_facts(&["a"], &pred_entries.join(":"));
            let mut built_entries = pred_entries.clone();
            built_entries.extend(extra.iter().map(|s| format!("/x-{s}")));
            // Any ordering of a superset must pass.
            let n = built_entries.len();
            built_entries.rotate_left(index_pick.index(n));
            let built = path_facts(&["a", "b"], &built_entries.join(":"));
            check(&pred, &built, StepRole::Final).unwrap();

            let removed = pred_entries[index_pick.index(pred_entries.len())].clone();
            built_entries.retain(|e| e != &removed);
            let broken = path_facts(&["a", "b"], &built_entries.join(":"));
            let err = check(&pred, &broken, StepRole::Final).unwrap_err();
            proptest::prop_assert_eq!(err.clause, Clause::PathIsAdditive);
            proptest::prop_assert!(
                err.detail.contains(&removed),
                "detail must name the removed directory {}: {}",
                removed,
                err.detail
            );
        }
    }

    /// Every enforced clause's id and title must appear in the ADR's contract
    /// table: the error messages, the tests and the normative text are
    /// required to name the same thing (CODING_STANDARDS.md, "one canonical
    /// place"). Backticks are stripped because the ADR formats identifiers
    /// like `PATH` as code; the check is otherwise literal.
    #[test]
    fn every_clause_id_and_title_appears_in_the_adr_table() {
        let adr = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/adr/0003-project-tooling-layers.md"
        ))
        .expect("read ADR-0003")
        .replace('`', "");

        for clause in [
            Clause::BuildsOnPredecessor,
            Clause::PathIsAdditive,
            Clause::EndsAsRoot,
            Clause::TargetsHostPlatform,
        ] {
            let id = clause.id();
            assert!(
                adr.contains(&format!("**{id}**")),
                "ADR-0003's contract table must name {id}"
            );
            let title = clause.title();
            let mut chars = title.chars();
            let capitalized = match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            };
            assert!(
                adr.contains(&capitalized),
                "ADR-0003's contract table must name clause {id} ({capitalized})"
            );
        }
    }

    /// The sample error transcript in `USAGE.md` must be the *verbatim*
    /// output of [`Violation`]'s `Display` for the violation it illustrates.
    /// A transcript in a fenced `text` block is read as real output, so a
    /// stray full stop or a reworded `fix` silently misleads the reader —
    /// the drift the issue-#97 follow-up review found (NEW-3). Pinning it
    /// here means the doc and the rendering can only move together.
    #[test]
    fn the_usage_sample_transcript_is_the_actual_display_output() {
        let usage = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../USAGE.md"))
            .expect("read USAGE.md");
        let block = usage
            .split("```text\n")
            .skip(1)
            .filter_map(|chunk| chunk.split("\n```").next())
            .find(|b| b.starts_with("Error: tooling layer"))
            .expect("USAGE.md must contain the sample contract-violation transcript");

        let violation = check_ends_as_root(
            "step 1/1 (.agent-vm/layers/10-a)",
            BuiltOn {
                predecessor: &facts(&["a"]),
                built: &user_facts(Some("chrome")),
            },
        )
        .unwrap_err();
        assert_eq!(
            block,
            format!("Error: {violation}"),
            "the USAGE.md sample transcript drifted from Violation's Display"
        );
    }

    // --- path_from_config_env() (moved here from run.rs) ---

    #[test]
    fn path_from_config_env_reads_the_path_entry() {
        let env = vec![
            "LANG=C.UTF-8".to_string(),
            "PATH=/opt/agent/.local/bin:/usr/bin".to_string(),
            "TZ=UTC".to_string(),
        ];
        assert_eq!(
            path_from_config_env(&env),
            Some("/opt/agent/.local/bin:/usr/bin".to_string())
        );
    }

    #[test]
    fn path_from_config_env_absent_is_none() {
        let env = vec!["LANG=C.UTF-8".to_string()];
        assert_eq!(path_from_config_env(&env), None);
    }

    #[test]
    fn path_from_config_env_empty_value_is_none() {
        let env = vec!["PATH=".to_string()];
        assert_eq!(path_from_config_env(&env), None);
    }

    #[test]
    fn path_from_config_env_last_entry_wins() {
        let env = vec!["PATH=/first".to_string(), "PATH=/second".to_string()];
        assert_eq!(path_from_config_env(&env), Some("/second".to_string()));
    }

    #[test]
    fn path_from_config_env_ignores_non_path_keys_containing_path_substring() {
        let env = vec!["XPATH=/should-not-match".to_string()];
        assert_eq!(path_from_config_env(&env), None);
    }

    // --- e2e: the layer image contract against real docker + the msb cache ---
    // Ignore attribute values must be literals, so the repeated reasons stay
    // at their call sites to deliberately retain direct test registration.
    //
    // Moved here from `layer.rs` by issue #102; the fixtures these tests share
    // with `layer`'s own e2e harness live in `layer::test_support`.
    //
    // These eight tests are the live proof of the clauses in
    // `docs/adr/0003-project-tooling-layers.md`: seven build a real derived
    // image over the fixture's base link and check the contract against the
    // facts the two producers actually report — the tripwire for the design's
    // riskiest assumptions (BuildKit preserving the base's diff ids; docker's
    // store and the msb cache agreeing on them). The eighth builds its own
    // foreign base, proving C4a is not a tautology.

    /// Build `dockerfile` (a one-step layer over the fixture's base link) with
    /// `--output type=oci`, ingest it into a fresh temp cache, and return the
    /// step, that cache dir, the ingested image's facts and the base link's
    /// facts. The caller keeps the returned `TempDir` alive.
    async fn e2e_ingest_one_step(
        fixture: &E2eBase,
        dockerfile: &str,
        extra_files: &[(&str, &str)],
    ) -> (ChainStep, tempfile::TempDir, ImageFacts, ImageFacts) {
        let base = fixture.link.clone();
        let layer_dir = tempfile::tempdir().unwrap();
        write_layer_file(layer_dir.path(), "Dockerfile", dockerfile, 0o644);
        for (rel, content) in extra_files {
            write_layer_file(layer_dir.path(), rel, content, 0o755);
        }
        let id = resolve(
            layer_dir.path(),
            Path::new("/tmp/e2e-contract-project"),
            &fixture.digest,
            first_of_one(),
        )
        .unwrap();
        let step = ChainStep {
            id,
            label: ".agent-vm/layers/10-a".to_string(),
        };

        let cache_dir = tempfile::tempdir().unwrap();
        // Under the cache dir, not the system tmp (AGENTS.md) — a full OCI
        // tar can be hundreds of MB.
        let tar = tempfile::Builder::new()
            .suffix(".tar")
            .tempfile_in(cache_dir.path())
            .unwrap();
        build_derived_oci(&step.id, &base, tar.path())
            .await
            .expect("docker buildx build");
        let metadata = load_derived_image(cache_dir.path(), tar.path(), &step.id.tag)
            .await
            .expect("load_archive");
        let built = ImageFacts::from_cached_metadata(&metadata).unwrap();
        let base_facts = docker_image_facts(&base)
            .await
            .unwrap()
            .expect("the fixture's base link must be inspectable");
        (step, cache_dir, built, base_facts)
    }

    /// The distinct stderr messages below are the observable run-versus-skip
    /// contract, so each precondition keeps its own wording. Split in two
    /// because the foreign-base test needs the buildx check without the
    /// ordinary host-base fixture.
    async fn e2e_buildx_or_skip() -> bool {
        if ensure_docker_buildx().await.is_err() {
            eprintln!("skipping: `docker buildx` not available on PATH");
            return false;
        }
        true
    }

    /// Return the owned fixture, not just its link: its guard must survive
    /// until the caller exits, including early returns and unwinding.
    async fn e2e_fixture_or_skip() -> Option<E2eBase> {
        if !e2e_buildx_or_skip().await {
            return None;
        }
        let Some(fixture) = e2e_base_fixture() else {
            eprintln!("skipping: no base image available locally or via network pull");
            return None;
        };
        Some(fixture)
    }

    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_a_built_layers_diff_ids_extend_its_base() {
        let Some(fixture) = e2e_fixture_or_skip().await else {
            return;
        };
        let base = fixture.link.clone();
        let (step, _cache, built, base_facts) = e2e_ingest_one_step(
            &fixture,
            &format!(
                "ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\n\
                 RUN ln -s /bin/true /usr/local/bin/marker-tool\n\
                 ENV PATH=/usr/local/bin:$PATH\n"
            ),
            &[],
        )
        .await;

        assert!(
            base_facts.diff_ids.len() < built.diff_ids.len(),
            "the layer must add at least one layer: base {:?}, built {:?}",
            base_facts.diff_ids,
            built.diff_ids
        );
        assert_eq!(
            built.diff_ids[..base_facts.diff_ids.len()],
            base_facts.diff_ids[..],
            "the built image's diff ids must extend the base's as a prefix — the \
             assumption C1's image half rests on"
        );
        check_built_image(
            &step,
            StepRole::Final,
            BuiltOn {
                predecessor: &base_facts,
                built: &built,
            },
            &host_oci_platform(),
        )
        .expect("C1 must pass for a layer built FROM the base link");
    }

    /// BuildKit is free to rebase layers for `COPY --link`; if this ever
    /// stops preserving the base's diff ids, that is a design change (see the
    /// plan's F1), never something to paper over with a carve-out.
    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_copy_link_still_extends_its_base() {
        let Some(fixture) = e2e_fixture_or_skip().await else {
            return;
        };
        let base = fixture.link.clone();
        let (step, _cache, built, base_facts) = e2e_ingest_one_step(
            &fixture,
            &format!(
                "ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\n\
                 COPY --link --chmod=0755 hello.sh /usr/local/bin/hello.sh\n"
            ),
            &[("hello.sh", "#!/bin/sh\necho hi\n")],
        )
        .await;

        assert_eq!(
            built.diff_ids[..base_facts.diff_ids.len()],
            base_facts.diff_ids[..],
            "COPY --link must still leave the base's diff ids as a prefix: base {:?}, built {:?}",
            base_facts.diff_ids,
            built.diff_ids
        );
        check_built_image(
            &step,
            StepRole::Final,
            BuiltOn {
                predecessor: &base_facts,
                built: &built,
            },
            &host_oci_platform(),
        )
        .expect("C1 must pass for a COPY --link layer built FROM the base link");
    }

    /// The cross-store comparability C1's final-step check depends on: the
    /// docker exporter and the OCI exporter must report the same diff ids for
    /// the same Dockerfile (they legitimately differ in the *compressed* blob
    /// digests, which is why only diff ids are compared).
    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_facts_agree_between_dockers_store_and_the_msb_cache() {
        let Some(fixture) = e2e_fixture_or_skip().await else {
            return;
        };
        let base = fixture.link.clone();

        let layer_dir = tempfile::tempdir().unwrap();
        write_layer_file(
            layer_dir.path(),
            "Dockerfile",
            &format!(
                "ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\n\
                 RUN ln -s /bin/true /usr/local/bin/marker-tool\n"
            ),
            0o644,
        );
        let id = resolve(
            layer_dir.path(),
            Path::new("/tmp/e2e-contract-same-image"),
            &fixture.digest,
            first_of_one(),
        )
        .unwrap();
        if docker_tag_exists(&id.tag) {
            eprintln!("skipping: {} already exists locally", id.tag);
            return;
        }

        // docker-exporter build first, so its tag can be cleaned up.
        let docker_facts = build_derived_docker(&id, &base)
            .await
            .expect("docker-exporter build");
        let mut guard = DockerTagGuard::default();
        guard.own(&id.tag);

        let cache_dir = tempfile::tempdir().unwrap();
        let tar = tempfile::Builder::new()
            .suffix(".tar")
            .tempfile_in(cache_dir.path())
            .unwrap();
        build_derived_oci(&id, &base, tar.path())
            .await
            .expect("oci-exporter build");
        let metadata = load_derived_image(cache_dir.path(), tar.path(), &id.tag)
            .await
            .expect("load_archive");
        let cache_facts = ImageFacts::from_cached_metadata(&metadata).unwrap();

        assert_eq!(
            docker_facts.diff_ids, cache_facts.diff_ids,
            "docker's store and the msb cache must report the same diff ids"
        );
        assert_eq!(docker_facts, cache_facts);
    }

    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_a_path_replacing_layer_is_rejected() {
        let Some(fixture) = e2e_fixture_or_skip().await else {
            return;
        };
        let base = fixture.link.clone();
        let (step, _cache, built, base_facts) = e2e_ingest_one_step(
            &fixture,
            &format!("ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\nENV PATH=/only/mine\n"),
            &[],
        )
        .await;

        let err = check_built_image(
            &step,
            StepRole::Final,
            BuiltOn {
                predecessor: &base_facts,
                built: &built,
            },
            &host_oci_platform(),
        )
        .expect_err("replacing PATH must violate C2 against real facts");
        assert_eq!(err.clause, Clause::PathIsAdditive);
    }

    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_a_non_root_final_layer_is_rejected() {
        let Some(fixture) = e2e_fixture_or_skip().await else {
            return;
        };
        let base = fixture.link.clone();
        let (step, _cache, built, base_facts) = e2e_ingest_one_step(
            &fixture,
            &format!("ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\nUSER 9999\n"),
            &[],
        )
        .await;

        let err = check_built_image(
            &step,
            StepRole::Final,
            BuiltOn {
                predecessor: &base_facts,
                built: &built,
            },
            &host_oci_platform(),
        )
        .expect_err("a non-root final must violate C3 against real facts");
        assert_eq!(err.clause, Clause::EndsAsRoot);
        // The identical image passes as an intermediate (decision D5).
        check_built_image(
            &step,
            StepRole::Intermediate,
            BuiltOn {
                predecessor: &base_facts,
                built: &built,
            },
            &host_oci_platform(),
        )
        .expect("a mid-chain USER is legitimate");
    }

    /// D7's rollback, and a live guard on the vendored
    /// `delete_image_metadata_async`: after the discard the tag reads as
    /// uncached, so the next launch rebuilds and re-checks instead of booting
    /// the violating artifact.
    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_discard_derived_image_makes_a_loaded_tag_uncached() {
        let Some(fixture) = e2e_fixture_or_skip().await else {
            return;
        };
        let base = fixture.link.clone();
        let (step, cache_dir, _built, _base_facts) = e2e_ingest_one_step(
            &fixture,
            &format!("ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\nENV MARKER=present\n"),
            &[],
        )
        .await;

        assert!(
            derived_is_cached(cache_dir.path(), &step.id.tag)
                .await
                .unwrap(),
            "the ingest must leave the tag cached"
        );
        discard_derived_image(cache_dir.path(), &step.id.tag)
            .await
            .expect("discard_derived_image");
        assert!(
            !derived_is_cached(cache_dir.path(), &step.id.tag)
                .await
                .unwrap(),
            "after the discard the tag must read as uncached, so the next launch \
             rebuilds and re-checks the contract"
        );
    }

    /// MAJOR-3's fix: an image agent-vm ingested but could **not evaluate**
    /// must be discarded, not left "cached" for the next launch to boot with
    /// zero clauses checked. The metadata here claims a platform-less config,
    /// which `from_cached_metadata` rejects.
    ///
    /// The intermediate half of the same fix is not separately tested:
    /// forcing a malformed `docker image inspect` needs a fake docker binary.
    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_an_unevaluatable_final_is_not_left_ingested() {
        let Some(fixture) = e2e_fixture_or_skip().await else {
            return;
        };
        let base = fixture.link.clone();
        let (step, cache_dir, _built, _base_facts) = e2e_ingest_one_step(
            &fixture,
            &format!("ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}}\nENV MARKER=present\n"),
            &[],
        )
        .await;
        assert!(
            derived_is_cached(cache_dir.path(), &step.id.tag)
                .await
                .unwrap(),
            "the ingest must leave the tag cached"
        );

        use microsandbox_image::{CachedImageMetadata, CachedLayerMetadata, ImageConfig};
        let unevaluatable = CachedImageMetadata {
            manifest_digest: "sha256:manifest".to_string(),
            config_digest: "sha256:config".to_string(),
            raw_manifest_json: "{}".to_string(),
            raw_config_json: "{}".to_string(),
            config: ImageConfig::default(),
            layers: vec![CachedLayerMetadata {
                digest: "sha256:compressed".to_string(),
                media_type: None,
                size_bytes: None,
                diff_id: "sha256:layer".to_string(),
            }],
        };
        let err = final_image_facts(cache_dir.path(), &step.id.tag, &unevaluatable).await;
        assert!(err.is_err(), "a platform-less config must not evaluate");
        assert!(
            !derived_is_cached(cache_dir.path(), &step.id.tag)
                .await
                .unwrap(),
            "an unevaluatable final must be discarded, or the next launch boots it \
             with no clause checked"
        );
    }

    /// C4a's falsifiability: a base link that really is a foreign-platform
    /// image must be rejected. This is the test the reviewer said could not be
    /// written without changing the check — the proof C4 is not a tautology.
    #[tokio::test]
    #[ignore = "needs docker buildx + a resolvable base image; run with `cargo test ... -- --ignored`"]
    async fn e2e_a_foreign_base_link_is_rejected_by_c4() {
        if !e2e_buildx_or_skip().await {
            return;
        }
        let foreign = if host_oci_platform() == "linux/amd64" {
            "linux/arm64"
        } else {
            "linux/amd64"
        };

        let link = format!("agent-vm-base:e2e-foreign-{}", e2e_nonce());
        if docker_tag_exists(&link) {
            eprintln!("skipping: {link} already exists locally");
            return;
        }

        // Build a genuinely foreign-platform image. A `FROM`-only Dockerfile
        // has no `RUN` to emulate, so buildx can still export the target
        // platform's rootfs. A plain `docker pull --platform <foreign>`
        // would *not* do: with the classic image store it leaves an existing
        // host-platform tag in place (`Image is up to date`) and the link
        // would inspect as the host platform, silently voiding the test.
        let ctx = tempfile::tempdir().unwrap();
        write_layer_file(
            ctx.path(),
            "Dockerfile",
            "FROM debian:13-slim\nLABEL agent-vm-e2e-foreign-platform=1\n",
            0o644,
        );
        // Offline is not a failure of the check: skip, and never report the
        // skip as a pass (the reviewer's explicit warning).
        let built = std::process::Command::new("docker")
            .args(["buildx", "build", "--platform", foreign, "-t", &link])
            .args(["--output", "type=docker", ctx.path().to_str().unwrap()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !built {
            eprintln!(
                "skipping: could not build a {foreign} image (no network, or no \
                 cross-platform support on this builder)"
            );
            return;
        }
        let mut guard = DockerTagGuard::default();
        guard.own(&link);

        let base = docker_image_facts(&link)
            .await
            .unwrap()
            .expect("the foreign base link must be inspectable");
        assert_eq!(
            base.platform, foreign,
            "buildx must have produced a {foreign} image under the link"
        );

        let step = chain_step(0, 1);
        let err = check_base_image(&step, &base, &host_oci_platform())
            .expect_err("a foreign base link must violate C4a");
        assert_eq!(err.clause, Clause::TargetsHostPlatform);
    }
}
