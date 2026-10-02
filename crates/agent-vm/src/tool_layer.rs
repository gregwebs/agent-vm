//! Compose the tool layers a resolved catalog declares onto a published image.
//!
//! Issue #84 splits the guest image into a tool-free base plus one standalone
//! layer per shipped agent CLI. This module is the launcher-side half: it embeds
//! the layer sources (`images/tools/`), decides which published image the
//! resulting chain builds `FROM` ([`chain_root`]), and materialises the builtin
//! layers into throwaway build contexts ([`materialize`]).
//!
//! The embed exists because agent-vm ships as prebuilt npm binaries: an
//! npm-installed launcher has no repo checkout to read `images/tools/` from at
//! runtime. `include_dir!` snapshots the whole directory at compile time;
//! `tests::embedded_sources_match_the_on_disk_tree` asserts the snapshot equals
//! what CI builds from, and `build.rs` registers the directory as a rebuild
//! input so an added file is picked up rather than silently stale.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use include_dir::{Dir, DirEntry, include_dir};
use tempfile::TempDir;

use crate::config::{DeclaredLayer, ToolLayer};
use crate::defaults;
use crate::layer;

/// The six shipped tool layer sources, embedded at compile time. The path
/// resolves relative to `$CARGO_MANIFEST_DIR` (`crates/agent-vm`), so
/// `../../images/tools` is the repo's tool-layer directory.
static TOOL_LAYERS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../images/tools");

/// Which published image the chain builds `FROM`, and whether tool layers must
/// be composed onto it. Returned by [`chain_root`], which is pure.
#[derive(Debug)]
pub(crate) enum ChainRoot {
    /// `--image`: boot this verbatim, compose no tool layers. Project layers
    /// still chain on top (ADR-0003 is unchanged).
    Verbatim(String),
    /// The published composed default already carries every declared layer.
    Template(String),
    /// The tool-free base; every declared tool layer chains onto it.
    Base(String),
}

impl ChainRoot {
    /// The reference `--update-check` probes and `pull` fetches — always a
    /// published tag, never a locally composed one (D6). `agent-vm-layer:<hash>`
    /// has no registry, so probing it would always miss.
    pub(crate) fn reference(&self) -> &str {
        match self {
            ChainRoot::Verbatim(reference)
            | ChainRoot::Template(reference)
            | ChainRoot::Base(reference) => reference,
        }
    }

    /// Whether this launch must build the declared tool layers locally.
    pub(crate) fn composes_tool_layers(&self) -> bool {
        matches!(self, ChainRoot::Base(_))
    }
}

/// The one place the chain-root decision table is encoded. Pure, so the whole
/// table is unit-tested without touching Docker or the environment.
///
/// `image_flag` and `base_flag` arrive already reconciled by `cli`'s image-flag
/// precedence rule (`ImageFlags::reconcile`), so the `(set, set)` row means a
/// real conflict: both flags typed, or both environment variables set.
///
/// `declared` is the catalog's ordered, deduplicated layer sequence
/// ([`crate::config::LaunchCatalog::declared_layers`] projected to its layers);
/// `shipped` is [`crate::config::shipped_tool_layers`].
///
/// | `--image` | `--base-image` | declared == shipped | root |
/// |---|---|---|---|
/// | set | unset | — | that image, verbatim |
/// | set | set | — | error |
/// | unset | unset | yes | the composed template (zero builds) |
/// | unset | unset | no | the tool-free base |
/// | unset | set | — | the given base (always composes) |
pub(crate) fn chain_root(
    image_flag: Option<String>,
    base_flag: Option<String>,
    declared: &[ToolLayer],
    shipped: &[ToolLayer],
) -> Result<ChainRoot> {
    match (image_flag, base_flag) {
        (Some(_), Some(_)) => bail!(
            "--image and --base-image are mutually exclusive: --image boots an image verbatim \
             (no tool composition), --base-image chooses what tool layers are composed onto. \
             Drop one. (An explicit flag wins over the other's environment variable; setting \
             both AGENT_VM_IMAGE_TAG and AGENT_VM_BASE_IMAGE conflicts too.)"
        ),
        // `--image` boots verbatim; the caller composes nothing.
        (Some(image), None) => Ok(ChainRoot::Verbatim(image)),
        // `--base-image` always forces composition, even for the shipped default
        // tool set — it is how a source-checkout user tests a locally
        // built/imported base (D5).
        (None, Some(base)) => Ok(ChainRoot::Base(base)),
        (None, None) => {
            if declared == shipped {
                // Fast path: the published composed default already carries every
                // declared layer, so boot it directly with zero docker calls.
                Ok(ChainRoot::Template(defaults::DEFAULT_IMAGE_REF.to_string()))
            } else {
                Ok(ChainRoot::Base(
                    defaults::DEFAULT_BASE_IMAGE_REF.to_string(),
                ))
            }
        }
    }
}

/// RAII holder for the temp build contexts a builtin layer is materialised
/// into. Dropping it deletes the directories, so the caller must keep it alive
/// for the whole of chain resolution *and* execution — dropping it early would
/// delete the build context out from under `docker buildx` (D2).
pub(crate) struct MaterializedLayers(
    // Held only for its `Drop`; never read.
    #[allow(dead_code)] Vec<TempDir>,
);

/// Materialise `declared` into chain steps, in declaration order. A builtin
/// layer is written into a throwaway temp directory (the agent-vm binary has no
/// checkout to build from); a `path` layer is anchored and validated in place.
///
/// The returned [`MaterializedLayers`] guard owns the temp directories and must
/// outlive the build. Pure apart from the filesystem writes, so it is
/// unit-testable without Docker.
pub(crate) fn materialize(
    declared: &[DeclaredLayer],
) -> Result<(Vec<layer::ChainDir>, MaterializedLayers)> {
    let mut dirs = Vec::with_capacity(declared.len());
    let mut temps = Vec::new();

    for layer in declared {
        match layer.layer() {
            ToolLayer::Builtin(builtin) => {
                let name = builtin.as_str();
                let subtree = TOOL_LAYERS.get_dir(name).ok_or_else(|| {
                    anyhow!(
                        "the agent-vm binary has no embedded source for builtin layer {name:?}; \
                         this is a bug (see src/tool_layer.rs)"
                    )
                })?;
                let temp = TempDir::new().context("creating a tool-layer build context")?;
                write_tree(subtree, temp.path())?;
                dirs.push(layer::ChainDir {
                    dir: temp.path().to_path_buf(),
                    label: format!("tool \"{}\" (builtin layer {name})", layer.tool()),
                });
                temps.push(temp);
            }
            ToolLayer::Path(declared_path) => {
                let declared_in = match layer.anchor() {
                    Some(dir) => format!(" (declared in {})", dir.display()),
                    None => String::new(),
                };
                let anchored = declared_path.anchored(layer.anchor()).with_context(|| {
                    format!(
                        "resolving the `layer = {{ path = … }}` declared by tool \"{}\"{declared_in}",
                        layer.tool()
                    )
                })?;
                let canonical = anchored.canonicalize().with_context(|| {
                    format!(
                        "tool \"{}\": layer path {} does not exist{declared_in}",
                        layer.tool(),
                        anchored.display()
                    )
                })?;
                if !canonical.is_dir() {
                    bail!(
                        "tool \"{}\": layer path {} is not a directory",
                        layer.tool(),
                        anchored.display()
                    );
                }
                if !canonical.join("Dockerfile").is_file() {
                    bail!(
                        "tool \"{}\": layer path {} has no Dockerfile (a layer directory must \
                         hold a Dockerfile that starts with `ARG BASE_IMAGE` / `FROM \
                         ${{BASE_IMAGE}}`)",
                        layer.tool(),
                        anchored.display()
                    );
                }
                dirs.push(layer::ChainDir {
                    dir: canonical,
                    label: format!(
                        "tool \"{}\" (layer {})",
                        layer.tool(),
                        declared_path.as_path().display()
                    ),
                });
            }
        }
    }

    Ok((dirs, MaterializedLayers(temps)))
}

/// Write an embedded directory tree into `dest`.
///
/// Every file is written mode `0o644` (no execute bit), explicitly, with **no**
/// per-filename special cases. `composition::context` folds a file's mode to
/// a single execute bit (`composition::context::git_mode`), so a byte-identical git checkout of
/// these sources—also `100644`—must materialise identically or a local compose
/// would build a different image than a `--layer`/example build of the same
/// bytes. The execute bit a tool layer needs (`seed-claude-plugins.sh`) is
/// granted by `COPY --chmod=0755` in the layer's Dockerfile, not here.
fn write_tree(dir: &Dir<'_>, dest: &Path) -> Result<()> {
    for entry in dir.entries() {
        // `DirEntry::path()` is relative to the `include_dir!` root at every
        // depth, so strip this directory's own prefix to place the entry
        // correctly under `dest`.
        let rel = entry
            .path()
            .strip_prefix(dir.path())
            .unwrap_or(entry.path());
        let out = dest.join(rel);
        match entry {
            DirEntry::File(file) => {
                if let Some(parent) = out.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("creating build-context dir {}", parent.display())
                    })?;
                }
                fs::write(&out, file.contents())
                    .with_context(|| format!("writing build-context file {}", out.display()))?;
                fs::set_permissions(&out, fs::Permissions::from_mode(0o644))
                    .with_context(|| format!("chmod 0644 {}", out.display()))?;
            }
            DirEntry::Dir(sub) => {
                fs::create_dir_all(&out)
                    .with_context(|| format!("creating build-context dir {}", out.display()))?;
                write_tree(sub, &out)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BuiltinLayer;
    use std::path::PathBuf;

    fn builtin(layer: BuiltinLayer) -> ToolLayer {
        ToolLayer::Builtin(layer)
    }

    fn shipped() -> Vec<ToolLayer> {
        crate::config::shipped_tool_layers().expect("the shipped layers resolve")
    }

    // -- §3.3's decision table, row by row --------------------------------

    #[test]
    fn chain_root_table() {
        let shipped = shipped();

        // Row 1 / 2: `--image` boots verbatim; both flags is an error.
        let root =
            chain_root(Some("img:1".into()), None, &shipped, &shipped).expect("verbatim root");
        assert!(matches!(&root, ChainRoot::Verbatim(r) if r == "img:1"));
        assert!(!root.composes_tool_layers());

        // `--image` with a non-default set is still verbatim and composes
        // nothing.
        let claude_only_nondefault = vec![builtin(BuiltinLayer::Claude)];
        let root = chain_root(
            Some("img:1".into()),
            None,
            &claude_only_nondefault,
            &shipped,
        )
        .expect("verbatim root");
        assert!(matches!(&root, ChainRoot::Verbatim(_)));
        assert!(!root.composes_tool_layers());

        let err = chain_root(
            Some("img:1".into()),
            Some("base:1".into()),
            &shipped,
            &shipped,
        )
        .expect_err("both flags is an error");
        let text = format!("{err:#}");
        assert!(text.contains("--image"), "{text}");
        assert!(text.contains("--base-image"), "{text}");

        // Row 3: default set + nothing given ⇒ the published template, no build.
        let root = chain_root(None, None, &shipped, &shipped).expect("template root");
        assert!(matches!(&root, ChainRoot::Template(r) if r == defaults::DEFAULT_IMAGE_REF));
        assert!(!root.composes_tool_layers());

        // Row 4: non-default set ⇒ the tool-free base, compose all declared.
        let claude_only = vec![builtin(BuiltinLayer::Claude)];
        let root = chain_root(None, None, &claude_only, &shipped).expect("base root");
        assert!(matches!(&root, ChainRoot::Base(r) if r == defaults::DEFAULT_BASE_IMAGE_REF));
        assert!(root.composes_tool_layers());

        // Rows 5–6: `--base-image` always composes, even with the default set.
        let root =
            chain_root(None, Some("base:dev".into()), &shipped, &shipped).expect("base root");
        assert!(matches!(&root, ChainRoot::Base(r) if r == "base:dev"));
        assert!(root.composes_tool_layers());

        let root =
            chain_root(None, Some("base:dev".into()), &claude_only, &shipped).expect("base root");
        assert!(matches!(&root, ChainRoot::Base(r) if r == "base:dev"));
    }

    /// A permutation of the shipped layers is *not* the shipped default: being
    /// over-strict can only cost a build, never boot the wrong image (D1).
    #[test]
    fn a_permuted_layer_sequence_is_not_the_shipped_default() {
        let mut permuted = shipped();
        permuted.swap(0, 1);
        assert_ne!(permuted, shipped());
        let root = chain_root(None, None, &permuted, &shipped()).expect("base root");
        assert!(
            matches!(root, ChainRoot::Base(_)),
            "a permutation must compose"
        );
    }

    /// D1: the root keys on the declared *layer sequence*, not the tool names.
    /// A catalog whose tool names differ but whose layer sequence is identical
    /// still boots the template.
    #[test]
    fn renamed_tools_with_the_same_layer_sequence_still_boot_the_template() {
        let renamed = declared_from_config(
            "[[tools]]\nname = \"dsh-x\"\ncommand = \"dsh\"\nlayer = { builtin = \"dsh\" }\n\
             [[tools]]\nname = \"pi-x\"\ncommand = \"pi\"\nlayer = { builtin = \"pi\" }\n\
             [[tools]]\nname = \"codex-x\"\ncommand = \"codex\"\nlayer = { builtin = \"codex\" }\n\
             [[tools]]\nname = \"opencode-x\"\ncommand = \"opencode\"\nlayer = { builtin = \"opencode\" }\n\
             [[tools]]\nname = \"claude-x\"\ncommand = \"claude\"\nlayer = { builtin = \"claude\" }\n\
             [[tools]]\nname = \"copilot-x\"\ncommand = \"copilot\"\nlayer = { builtin = \"copilot\" }\n",
        );
        let declared: Vec<ToolLayer> = renamed.iter().map(|l| l.layer().clone()).collect();
        assert_eq!(declared, shipped());
        let root = chain_root(None, None, &declared, &shipped()).expect("root");
        assert!(matches!(root, ChainRoot::Template(_)));
    }

    // -- the declaration order is transcribed into CI and images/build.sh --

    fn repo_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    /// The declaration order has one source of truth, `default-tools.toml`, but
    /// CI's seven build steps and `images/build.sh`'s layer variables transcribe
    /// it by hand (a workflow and a shell script cannot import a Rust const).
    /// Nothing else ties them together, and the drift is silent: if CI composes
    /// the published template in a different order than the launcher believes,
    /// the default-set fast path boots an image that is not what the config
    /// describes — the class of bug D1 exists to prevent. Mirrors
    /// `layer::tests::base_repo_constant_matches_the_import_script_literal`
    /// (issue-#84 review, Finding 4).
    #[test]
    fn tool_order_matches_the_ci_and_build_script_literals() {
        let shipped: Vec<String> = crate::config::shipped_tool_layers()
            .expect("the shipped layers resolve")
            .iter()
            .map(|layer| match layer {
                ToolLayer::Builtin(builtin) => builtin.as_str().to_string(),
                ToolLayer::Path(_) => panic!("a shipped layer must be a builtin"),
            })
            .collect();

        let workflow = std::fs::read_to_string(repo_path(".github/workflows/build-image.yml"))
            .expect("read .github/workflows/build-image.yml");
        let ci_order: Vec<String> = workflow
            .lines()
            .filter_map(|line| line.trim().strip_prefix("context: images/tools/"))
            .map(|tool| tool.trim().to_string())
            .collect();
        assert_eq!(
            ci_order, shipped,
            "build-image.yml must chain the tool layers in the order default-tools.toml declares"
        );

        let script =
            std::fs::read_to_string(repo_path("images/build.sh")).expect("read images/build.sh");
        let mut script_order: Vec<String> = Vec::new();
        for line in script.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("INTERMEDIATE_LAYERS=(") {
                script_order.extend(
                    rest.trim_end_matches(')')
                        .split_whitespace()
                        .map(str::to_string),
                );
            } else if let Some(rest) = line.strip_prefix("FINAL_LAYER=") {
                script_order.push(rest.trim().to_string());
            }
        }
        assert_eq!(
            script_order, shipped,
            "images/build.sh must chain the tool layers in the order default-tools.toml declares"
        );

        // Order is not enough. A step left building FROM `steps.base` (e.g. the
        // `codex` step's `BASE_IMAGE` still pointing at the base digest instead
        // of `steps.pi`) keeps every `context:` line in order and still passes
        // the workflow's own prefix + `m > n` gate -- yet the published
        // template then contains no `pi`. Assert the chain *edges* too: each
        // tool builds FROM its predecessor step's digest, and the first builds
        // FROM the base.
        let mut current: Option<&str> = None;
        let mut edges: Vec<(String, String)> = Vec::new();
        for line in workflow.lines() {
            let line = line.trim();
            if let Some(tool) = line.strip_prefix("context: images/tools/") {
                current = Some(tool.trim());
                continue;
            }
            if let Some(rest) = line.strip_prefix("BASE_IMAGE=${{ env.BASE }}@${{ steps.")
                && let Some(step) = rest.strip_suffix(".outputs.digest }}")
            {
                let tool = current.expect("every BASE_IMAGE edge follows a context line");
                edges.push((tool.to_string(), step.to_string()));
            }
        }
        let expected_edges: Vec<(String, String)> = shipped
            .iter()
            .enumerate()
            .map(|(index, tool)| {
                let predecessor = if index == 0 {
                    "base".to_string()
                } else {
                    shipped[index - 1].clone()
                };
                (tool.clone(), predecessor)
            })
            .collect();
        assert_eq!(
            edges, expected_edges,
            "build-image.yml must chain each tool layer FROM its predecessor's step digest, \
             starting from `steps.base` -- otherwise the published template omits a layer"
        );
    }

    // -- §6.3(3): the embedded snapshot matches the on-disk sources -------

    /// Walk the embedded tree and the on-disk tree and assert the same
    /// relative-path set and the same bytes, **both directions** (a
    /// one-directional check misses a deleted file). Compares bytes and paths
    /// only, not modes: `include_dir` does not carry the executable bit, and
    /// §2.4 explains why nothing here needs it.
    #[test]
    fn embedded_sources_match_the_on_disk_tree() {
        let on_disk_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../images/tools");
        let mut embedded = Vec::new();
        collect_embedded(&TOOL_LAYERS, &mut embedded);
        embedded.sort();
        let mut on_disk = Vec::new();
        collect_on_disk(&on_disk_root, &on_disk_root, &mut on_disk)
            .expect("walking the on-disk tool sources");
        on_disk.sort();
        assert_eq!(
            embedded, on_disk,
            "the embedded images/tools/ snapshot drifted from the on-disk sources CI builds from"
        );
    }

    fn collect_embedded(dir: &Dir<'_>, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in dir.entries() {
            match entry {
                DirEntry::File(file) => {
                    out.push((file.path().to_path_buf(), file.contents().to_vec()))
                }
                DirEntry::Dir(sub) => collect_embedded(sub, out),
            }
        }
    }

    fn collect_on_disk(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) -> Result<()> {
        for item in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let item = item?;
            let path = item.path();
            let rel = path
                .strip_prefix(root)
                .expect("every visited path is under the root")
                .to_path_buf();
            let file_type = item.file_type()?;
            if file_type.is_dir() {
                collect_on_disk(root, &path, out)?;
            } else if file_type.is_file() {
                out.push((rel, fs::read(&path)?));
            }
        }
        Ok(())
    }

    // -- §6.3(4): every shipped Dockerfile satisfies the C1 lint ---------

    #[test]
    fn shipped_layers_satisfy_the_c1_lint() {
        for builtin in BuiltinLayer::ALL {
            let name = builtin.as_str();
            let text = TOOL_LAYERS
                .get_file(format!("{name}/Dockerfile"))
                .unwrap_or_else(|| panic!("{name}/Dockerfile is embedded"))
                .contents_utf8()
                .expect("the Dockerfile is UTF-8");
            let step = dummy_step(name);
            layer::contract::lint_step_dockerfile(&step, text).unwrap_or_else(|violation| {
                panic!("{name}/Dockerfile fails the C1 lint: {violation}")
            });
        }
    }

    // -- §6.3(5): each layer's ENV PATH is additive (a C2 text proxy) -----

    #[test]
    fn shipped_layers_extend_path_additively() {
        for builtin in BuiltinLayer::ALL {
            let name = builtin.as_str();
            let text = TOOL_LAYERS
                .get_file(format!("{name}/Dockerfile"))
                .unwrap()
                .contents_utf8()
                .unwrap();
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix("ENV PATH=") {
                    assert!(
                        rest.contains("${PATH}"),
                        "{name}/Dockerfile sets a non-additive ENV PATH: {line}"
                    );
                }
            }
        }
    }

    // -- the pinned Pi layer: one home for the pin, and npm's one hole ----

    fn embedded_json(relative: &str) -> serde_json::Value {
        let text = TOOL_LAYERS
            .get_file(relative)
            .unwrap_or_else(|| panic!("{relative} is embedded"))
            .contents_utf8()
            .expect("the embedded file is UTF-8");
        serde_json::from_str(text)
            .unwrap_or_else(|error| panic!("{relative} is valid JSON: {error}"))
    }

    fn pi_pin() -> String {
        embedded_json("pi/package.json")["dependencies"]["@earendil-works/pi-coding-agent"]
            .as_str()
            .expect("the manifest pins pi")
            .to_string()
    }

    /// The pin has exactly two homes -- `images/tools/pi/package.json` and its
    /// lockfile -- and `npm ci` is only as good as their agreement. Assert it
    /// here rather than discovering it in the image build.
    #[test]
    fn the_pinned_pi_version_agrees_across_the_manifest_and_the_lockfile() {
        let pinned = pi_pin();
        let lock = embedded_json("pi/package-lock.json");
        let root = lock["packages"][""]["dependencies"]["@earendil-works/pi-coding-agent"]
            .as_str()
            .expect("the lock's root records the pi dependency");
        assert_eq!(
            root, pinned,
            "the lock's root dependency must equal the manifest's pin"
        );
        let locked = lock["packages"]["node_modules/@earendil-works/pi-coding-agent"]["version"]
            .as_str()
            .expect("pi is locked");
        assert_eq!(
            locked, pinned,
            "npm ci would install {locked}, but the manifest pins {pinned}"
        );
    }

    /// Every entry in the committed lock carries `integrity`. A freshly
    /// generated lock does NOT: npm inherits Pi's published
    /// `npm-shrinkwrap.json`, which omits the hashes for its five
    /// `@earendil-works` siblings. They are filled by hand from the registry
    /// (`images/tools/README.md`), so this test is what catches a regenerated
    /// lock that silently dropped them again -- `install-pi.sh` would then have
    /// nothing to verify against.
    #[test]
    fn every_locked_package_carries_integrity() {
        let lock = embedded_json("pi/package-lock.json");
        let packages = lock["packages"]
            .as_object()
            .expect("`packages` is an object");
        let missing: Vec<&str> = packages
            .iter()
            .filter(|(key, value)| !key.is_empty() && value.get("integrity").is_none())
            .map(|(key, _)| key.as_str())
            .collect();
        assert!(
            missing.is_empty(),
            "these committed lock entries carry no `integrity` hash: {missing:?}\n\
             A freshly generated lock omits it for pi's five @earendil-works siblings\n\
             (npm inherits pi's published npm-shrinkwrap.json). Refill the five with:\n\
             for p in chord pi-agent-core pi-ai pi-telemetry pi-tui; do \
             npm view \"@earendil-works/$p@$(jq -r '.dependencies[\"@earendil-works/pi-coding-agent\"]' images/tools/pi/package.json)\" dist.integrity; done\n\
             and paste each value into its lock entry -- see images/tools/README.md."
        );
    }

    /// `install-pi.sh` verifies exactly the packages npm will not: the
    /// `@earendil-works` siblings nested directly under pi-coding-agent's own
    /// `node_modules`. Pin that set by name and version here, so a pin bump
    /// that changes the nested layout fails in `cargo test` rather than turning
    /// the layer's jq selector into a silent no-op. The selector is deliberately
    /// direct-children-only: pi-ai carries its own nested deps (agent-base,
    /// https-proxy-agent) one level deeper, and those DO carry npm-checked
    /// integrity, so a looser substring match would over-match them.
    #[test]
    fn the_build_verified_sibling_set_is_exactly_the_five_nested_earendil_packages() {
        const SIBLINGS: [&str; 5] = ["chord", "pi-agent-core", "pi-ai", "pi-telemetry", "pi-tui"];
        let pinned = pi_pin();
        let lock = embedded_json("pi/package-lock.json");
        const PREFIX: &str =
            "node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/";
        let mut matched: Vec<(String, String)> = Vec::new();
        for (key, value) in lock["packages"].as_object().unwrap() {
            let Some(name) = key.strip_prefix(PREFIX) else {
                continue;
            };
            if name.contains('/') {
                continue;
            }
            let version = value["version"].as_str().unwrap_or("<none>").to_string();
            matched.push((name.to_string(), version));
        }
        matched.sort();
        let mut expected: Vec<(String, String)> = SIBLINGS
            .iter()
            .map(|name| (name.to_string(), pinned.clone()))
            .collect();
        expected.sort();
        assert_eq!(
            matched, expected,
            "install-pi.sh's selector must match exactly the five shrinkwrap-only siblings at the pin"
        );
    }

    // -- the pinned bridge packages: one home for the pin, full integrity, and
    // -- no second Pi ---------------------------------------------

    fn bridge_pin() -> String {
        embedded_json("pi/bridge/package.json")["dependencies"]["pi-claude-bridge"]
            .as_str()
            .expect("the bridge manifest pins pi-claude-bridge")
            .to_string()
    }

    /// Unlike pi's lock, the bridge tree has no shrinkwrap anywhere in its
    /// chain, so every entry carries npm's own `integrity` with no hand-refilled
    /// hashes -- which is exactly why `install-pi-packages.sh` carries no
    /// bespoke verifier. This test is what keeps that true.
    #[test]
    fn every_bridge_locked_package_carries_integrity() {
        let lock = embedded_json("pi/bridge/package-lock.json");
        let packages = lock["packages"]
            .as_object()
            .expect("`packages` is an object");
        let missing: Vec<&str> = packages
            .iter()
            .filter(|(key, value)| !key.is_empty() && value.get("integrity").is_none())
            .map(|(key, _)| key.as_str())
            .collect();
        assert!(
            missing.is_empty(),
            "these committed bridge lock entries carry no `integrity` hash: {missing:?}\n\
             `install-pi-packages.sh` deliberately carries no bespoke verifier because every\n\
             tarball here is npm-authenticated. Regenerate with:\n\
             cd images/tools/pi/bridge && npm install --ignore-scripts --package-lock-only \\\n\
               --no-audit --no-fund --legacy-peer-deps  (see images/tools/README.md)"
        );
    }

    /// The bridge pin is exact, and the lock agrees with the manifest. There is
    /// no shrinkwrap in this tree, so `npm ci` resolves nothing and the lock is
    /// authoritative -- a range in the manifest would let a regenerated lock
    /// move the installed version without this repo moving the pin.
    #[test]
    fn the_bridge_pin_is_exact_and_the_lock_agrees() {
        let pinned = bridge_pin();
        let range_characters = ['^', '~', '>', '<', '=', '*', '|', ' ', 'x', 'X'];
        assert!(
            pinned.split('.').count() >= 3
                && !pinned.chars().any(|c| range_characters.contains(&c)),
            "the pi-claude-bridge pin must be an exact version, not a range: {pinned:?}"
        );
        let lock = embedded_json("pi/bridge/package-lock.json");
        let root = lock["packages"][""]["dependencies"]["pi-claude-bridge"]
            .as_str()
            .expect("the lock's root records the bridge dependency");
        assert_eq!(
            root, pinned,
            "the lock's root dependency must equal the manifest's pin"
        );
        let locked = lock["packages"]["node_modules/pi-claude-bridge"]["version"]
            .as_str()
            .expect("pi-claude-bridge is locked");
        assert_eq!(
            locked, pinned,
            "npm ci would install {locked}, but the manifest pins {pinned}"
        );
    }

    /// `--legacy-peer-deps` was used on BOTH the lock and the layer's `npm ci`.
    /// Without it npm solves the bridge's `@earendil-works/pi-*` and `typebox`
    /// peer ranges and drags in a SECOND, version-skewed
    /// `@earendil-works/pi-coding-agent` beside the image's own Pi. Pi's
    /// extension loader aliases every one of those specifiers to its own copies
    /// (`dist/core/extensions/loader.js`), so none may be installed. Assert the
    /// whole loader-aliased set, not just `@earendil-works`.
    #[test]
    fn the_bridge_lock_installs_no_loader_aliased_pi_package() {
        // The specifiers ADR-0023 names as loader-aliased: the three shipped Pi
        // packages plus their typebox base. A regenerated lock must contain no
        // package whose path matches any of them.
        const ALIASED: [&str; 5] = [
            "@earendil-works",
            "typebox",
            "pi-agent-core",
            "pi-tui",
            "pi-ai",
        ];
        let lock = embedded_json("pi/bridge/package-lock.json");
        let offending: Vec<&str> = lock["packages"]
            .as_object()
            .expect("`packages` is an object")
            .keys()
            .map(String::as_str)
            .filter(|key| ALIASED.iter().any(|aliased| key.contains(aliased)))
            .collect();
        assert!(
            offending.is_empty(),
            "the bridge lock installs a package Pi's loader aliases: {offending:?}\n\
             It was generated without `--legacy-peer-deps`; regenerate it with that\n\
             flag (see images/tools/README.md)."
        );
    }

    /// `--omit=optional` and `--legacy-peer-deps` are mandatory on the layer's
    /// `npm ci`. The lock carries the Claude Agent SDK's eight
    /// `optionalDependencies` (one whole native Claude Code binary per
    /// platform), so dropping `--omit=optional` silently adds ~197 MiB to the
    /// image while every other guard -- and the runtime matrix -- stays green.
    /// Pin the flags to the script that runs the install.
    #[test]
    fn the_bridge_install_passes_npm_ci_the_mandatory_flags() {
        let script = TOOL_LAYERS
            .get_file("pi/install-pi-packages.sh")
            .expect("pi/install-pi-packages.sh is embedded")
            .contents_utf8()
            .expect("the install script is UTF-8");
        let ci_line = script
            .lines()
            .find(|line| line.contains("npm ci --ignore-scripts"))
            .expect("install-pi-packages.sh runs `npm ci --ignore-scripts`");
        for flag in ["--omit=optional", "--legacy-peer-deps"] {
            assert!(
                ci_line.contains(flag),
                "pi/install-pi-packages.sh's npm ci line dropped {flag}: {ci_line}"
            );
        }
    }

    // -- the pinned dsh layer: one home for the pin, and full integrity ----

    fn dsh_pin() -> String {
        embedded_json("dsh/package.json")["dependencies"]["@deepseek-ai/dsh"]
            .as_str()
            .expect("the dsh manifest pins @deepseek-ai/dsh")
            .to_string()
    }

    /// The dsh pin has exactly two homes -- `images/tools/dsh/package.json` and
    /// its lockfile -- and `npm ci` is only as good as their agreement, so
    /// assert it in `cargo test` rather than discovering a mismatch in the
    /// image build. `verify-dsh.sh` asserts the *running* binary equals the
    /// manifest pin; this asserts the manifest equals the lock.
    #[test]
    fn the_pinned_dsh_version_agrees_across_the_manifest_and_the_lockfile() {
        let pinned = dsh_pin();
        let lock = embedded_json("dsh/package-lock.json");
        let root = lock["packages"][""]["dependencies"]["@deepseek-ai/dsh"]
            .as_str()
            .expect("the lock's root records the dsh dependency");
        assert_eq!(
            root, pinned,
            "the lock's root dependency must equal the manifest's pin"
        );
        let locked = lock["packages"]["node_modules/@deepseek-ai/dsh"]["version"]
            .as_str()
            .expect("dsh is locked");
        assert_eq!(
            locked, pinned,
            "npm ci would install {locked}, but the manifest pins {pinned}"
        );
        // `dsh plugin` needs pnpm, and the Dockerfile links it out of this same
        // lock, so a dropped pnpm dependency must fail here rather than as a
        // still-green build that ships a plugin command that cannot run.
        let pnpm = embedded_json("dsh/package.json")["dependencies"]["pnpm"]
            .as_str()
            .expect("the dsh manifest pins pnpm")
            .to_string();
        assert!(
            lock["packages"]["node_modules/pnpm"]["version"].as_str() == Some(pnpm.as_str()),
            "the lock must install the pinned pnpm ({pnpm})"
        );
    }

    /// Every entry in the committed dsh lock carries `integrity`, so `npm ci`
    /// authenticates the whole tree it installs. A regenerated lock that drops
    /// a hash must fail here, not silently widen what the build trusts.
    #[test]
    fn every_dsh_locked_package_carries_integrity() {
        let lock = embedded_json("dsh/package-lock.json");
        let packages = lock["packages"]
            .as_object()
            .expect("`packages` is an object");
        // An empty/truncated lock would vacuously satisfy the loop below.
        assert!(
            packages.contains_key("node_modules/@deepseek-ai/dsh"),
            "the dsh lock must actually carry the dsh package"
        );
        let missing: Vec<&str> = packages
            .iter()
            .filter(|(key, value)| !key.is_empty() && value.get("integrity").is_none())
            .map(|(key, _)| key.as_str())
            .collect();
        assert!(
            missing.is_empty(),
            "these committed dsh lock entries carry no `integrity` hash: {missing:?}\n\
             Regenerate with `cd images/tools/dsh && npm install --package-lock-only`."
        );
    }

    /// `write_tree` materialises every embedded file 0644, while
    /// `composition::context::git_mode` folds an on-disk source file's mode to one execute
    /// bit. A source file that is executable on disk (i.e. committed `100755`)
    /// therefore hashes differently from the same bytes materialised into a
    /// build context -- a silent double build. The execute bit a layer needs
    /// (`pi.sh`, `seed-claude-plugins.sh`) comes from `COPY --chmod=0755` in
    /// its Dockerfile, never from the source tree.
    #[test]
    fn embedded_layer_sources_are_committed_without_the_execute_bit() {
        let root = repo_path("images/tools");
        let mut offenders: Vec<PathBuf> = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for item in fs::read_dir(&dir).expect("read images/tools") {
                let item = item.expect("read dir entry");
                let metadata = item.metadata().expect("stat a tool-layer source");
                if metadata.is_dir() {
                    stack.push(item.path());
                } else if metadata.permissions().mode() & 0o111 != 0 {
                    offenders.push(
                        item.path()
                            .strip_prefix(&root)
                            .expect("under the root")
                            .to_path_buf(),
                    );
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these images/tools/ sources are executable on disk (committed 100755?): {offenders:?}\n\
             `write_tree` materialises them 0644, so an executable source hashes differently \
             from a locally composed layer. Grant the execute bit with COPY --chmod=0755 instead."
        );
    }

    /// pi is the first shipped layer with a subdirectory (`extensions/`), so
    /// exercise `write_tree` against the real layer rather than the synthetic
    /// fixture `write_tree_preserves_nested_subdirectory_paths` uses (adding pi
    /// does not touch that fixture).
    #[test]
    fn materialize_places_the_pi_extension_at_its_nested_path() {
        let layers = declared_from_config(
            "[[tools]]\nname = \"pi\"\ncommand = \"pi\"\nlayer = { builtin = \"pi\" }\n",
        );
        assert_eq!(layers.len(), 1);
        let (dirs, guard) = materialize(&layers).expect("materialize");
        let context = &dirs[0].dir;
        for rel in [
            "Dockerfile",
            "package.json",
            "package-lock.json",
            "install-pi.sh",
            "verify-pi.sh",
            "pi.sh",
            "extensions/guest-credential-warning.js",
        ] {
            let path = context.join(rel);
            assert!(
                path.is_file(),
                "{rel} must materialise at its path relative to the embed root"
            );
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "{rel} must materialise 0644");
        }
        drop(guard);
    }

    fn dummy_step(name: &str) -> layer::ChainStep {
        layer::ChainStep {
            id: layer::LayerIdentity {
                dir: PathBuf::from(name),
                dockerfile: PathBuf::from(name).join("Dockerfile"),
                tag: format!("agent-vm-layer:{name}-dummy"),
                hash: "0".repeat(8),
                file_count: 0,
                hashed_bytes: 0,
                position: layer::ChainPosition { index: 0, total: 1 },
            },
            label: name.to_string(),
        }
    }

    // -- §6.3(6): materialisation -----------------------------------------

    fn declared_from_config(body: &str) -> Vec<DeclaredLayer> {
        use crate::config::ConfigPaths;
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("config.toml");
        fs::write(&project, body).unwrap();
        crate::config::load(&ConfigPaths {
            user: Some(dir.path().join("no-user.toml")),
            project,
        })
        .expect("fixture config parses")
        .into_launch_catalog()
        .expect("fixture catalog resolves")
        .declared_layers()
    }

    #[test]
    fn materialize_builtin_writes_a_dockerfile_mode_0644() {
        let layers = declared_from_config(
            "[[tools]]\nname = \"claude\"\ncommand = \"claude\"\nlayer = { builtin = \"claude\" }\ncredentials = [\"anthropic\"]\n",
        );
        assert_eq!(layers.len(), 1);
        let (dirs, guard) = materialize(&layers).expect("materialize");
        assert_eq!(dirs.len(), 1);
        let dockerfile = dirs[0].dir.join("Dockerfile");
        assert!(dockerfile.is_file(), "the Dockerfile is materialised");
        let mode = fs::metadata(&dockerfile).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "every materialised file is 0644");
        // The guard keeps the context alive.
        drop(guard);
        assert!(
            !dockerfile.is_file(),
            "dropping the guard removes the context"
        );
    }

    /// Regression (issue #84 review, Finding 1): `write_tree` must place a
    /// nested entry at its path **relative to the embed root**, not at the
    /// context root. `include_dir::Dir::path()` is root-relative at every depth
    /// (`include_dir-0.7.4/src/dir.rs:18-22`), so recursing with the parent's
    /// `dest` instead of the child's hoists `sub/nested.txt` to the context
    /// root. The shipped layers are flat today, so the flat `materialize_*`
    /// tests above would still pass with that bug in place; this fixture tree
    /// is deliberately nested so the test fails without the fix. The
    /// consequence is not cosmetic: `composition::context` hashes
    /// *relative* paths, so a hoisted entry hashes differently from a git
    /// checkout of the same bytes and the same layer builds twice.
    #[test]
    fn write_tree_preserves_nested_subdirectory_paths() {
        static NESTED: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/tool-layer-tree");
        let dest = TempDir::new().unwrap();
        write_tree(&NESTED, dest.path()).expect("write_tree");
        for rel in ["Dockerfile", "sub/nested.txt", "sub/deeper/leaf.txt"] {
            assert!(
                dest.path().join(rel).is_file(),
                "{rel} must materialise at its path relative to the embed root"
            );
        }
        assert!(
            !dest.path().join("nested.txt").exists() && !dest.path().join("leaf.txt").exists(),
            "a nested file must not be hoisted to the context root"
        );
    }

    #[test]
    fn materialized_paths_outlive_the_materialize_call() {
        let layers = declared_from_config(
            "[[tools]]\nname = \"copilot\"\ncommand = \"copilot\"\nlayer = { builtin = \"copilot\" }\ncredentials = [\"copilot\"]\n",
        );
        let (dirs, _guard) = materialize(&layers).expect("materialize");
        assert!(dirs[0].dir.join("Dockerfile").is_file());
    }

    /// Two tools naming the same builtin dedupe to one chain step (via
    /// `declared_layers`), and the label names the tool, not the temp path.
    #[test]
    fn duplicate_builtins_dedupe_and_label_names_the_tool() {
        let layers = declared_from_config(
            "[[tools]]\nname = \"a\"\ncommand = \"claude\"\nlayer = { builtin = \"claude\" }\n\
             [[tools]]\nname = \"b\"\ncommand = \"claude\"\nlayer = { builtin = \"claude\" }\n",
        );
        assert_eq!(layers.len(), 1, "duplicate builtin layers dedupe");
        let (dirs, _guard) = materialize(&layers).expect("materialize");
        // The label identifies the *declaring tool* and the layer it selects.
        // A bare `contains("a")` would also hold for a label that named only
        // the builtin (`claude` contains `a`), so assert the position and the
        // builtin name separately.
        assert!(dirs[0].label.starts_with("tool \"a\""), "{}", dirs[0].label);
        assert!(
            dirs[0].label.contains("builtin layer claude"),
            "{}",
            dirs[0].label
        );
        // The temp path is meaningless to a user reading the confirmation
        // prompt. Assert the actual property (the path is absent) rather than
        // a `/tmp`/`T/` substring, which never appears in a format string.
        let temp = dirs[0].dir.to_string_lossy();
        assert!(
            !dirs[0].label.contains(temp.as_ref()),
            "the label must not name the materialised path: {}",
            dirs[0].label
        );
    }

    /// A `path` layer anchors on the declaring config file's directory (D7) and
    /// errors, naming that file, when the directory is missing or has no
    /// Dockerfile.
    #[test]
    fn path_layer_anchors_on_the_declaring_file_and_errors_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("sub");
        fs::create_dir_all(&project).unwrap();
        let layer_dir = project.join("mylayer");
        fs::create_dir_all(&layer_dir).unwrap();
        fs::write(
            layer_dir.join("Dockerfile"),
            "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n",
        )
        .unwrap();
        let config = project.join("config.toml");
        let body = "[[tools]]\nname = \"mytool\"\ncommand = \"mytool\"\n\
                    layer = { path = \"mylayer\" }\n";
        fs::write(&config, body).unwrap();
        let catalog = crate::config::load(&crate::config::ConfigPaths {
            user: Some(dir.path().join("no-user.toml")),
            project: config.clone(),
        })
        .expect("config parses")
        .into_launch_catalog()
        .expect("catalog resolves");
        let layers = catalog.declared_layers();
        assert_eq!(layers.len(), 1);
        let (dirs, _guard) = materialize(&layers).expect("materialize");
        assert_eq!(
            dirs[0].dir.canonicalize().unwrap(),
            layer_dir.canonicalize().unwrap(),
            "the relative path anchors on the config file's directory"
        );

        // Missing directory: error names the declaring config file's tool.
        let body = "[[tools]]\nname = \"mytool\"\ncommand = \"mytool\"\n\
                    layer = { path = \"nope\" }\n";
        fs::write(&config, body).unwrap();
        let layers = crate::config::load(&crate::config::ConfigPaths {
            user: Some(dir.path().join("no-user.toml")),
            project: config,
        })
        .expect("config parses")
        .into_launch_catalog()
        .expect("catalog resolves")
        .declared_layers();
        let err = match materialize(&layers) {
            Ok(_) => panic!("a missing path layer must be an error"),
            Err(error) => error,
        };
        assert!(format!("{err:#}").contains("mytool"), "{err:#}");
    }

    // -- exact shipped tool slots: ARGs, labels, contracts, vendored patches --

    /// The eight version slots: the label suffix, the recipe directory that
    /// owns the label, and the single-line `ARG` that selects the slot. The
    /// single-slot recipes carry an exact nonempty default; dsh/pnpm and
    /// pi/bridge are the two lock-backed recipes whose ARG defaults are EMPTY
    /// (an empty slot reuses the committed lock byte-for-byte).
    const VERSION_SLOTS: [(&str, &str, &str); 8] = [
        ("codex", "codex", "AGENT_VERSION_CODEX"),
        ("opencode", "opencode", "AGENT_VERSION_OPENCODE"),
        ("claude", "claude", "AGENT_VERSION_CLAUDE"),
        ("copilot", "copilot", "AGENT_VERSION_COPILOT"),
        ("dsh", "dsh", "AGENT_VERSION_DSH"),
        ("pnpm", "dsh", "AGENT_VERSION_PNPM"),
        ("pi", "pi", "AGENT_VERSION_PI"),
        ("pi-claude-bridge", "pi", "AGENT_VERSION_PI_CLAUDE_BRIDGE"),
    ];

    fn embedded_text(relative: &str) -> String {
        TOOL_LAYERS
            .get_file(relative)
            .unwrap_or_else(|| panic!("{relative} is embedded"))
            .contents_utf8()
            .expect("the embedded file is UTF-8")
            .to_string()
    }

    fn embedded_files() -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        collect_embedded(&TOOL_LAYERS, &mut out);
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// The one `ARG NAME=<value>` line's value (panics unless exactly one).
    fn dockerfile_arg(text: &str, name: &str) -> String {
        let prefix = format!("ARG {name}=");
        let matches: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with(&prefix))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one `ARG {name}=` line, found {}: {matches:?}",
            matches.len()
        );
        matches[0][prefix.len()..].to_string()
    }

    /// The active `LABEL` key=value pairs of a Dockerfile, parsed the way a
    /// build would see them. Comment lines (first non-blank character `#`) are
    /// dropped before instruction joining, and a trailing `\\` joins the next
    /// line, so a commented-out or continued label is resolved exactly as the
    /// built image resolves it (review E2).
    fn active_label_values(text: &str) -> Vec<(String, String)> {
        // Drop comment lines first: a `#`-prefixed LABEL is not an instruction
        // and must never satisfy a guard even inside a continuation block.
        let stripped: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect();
        let mut logical: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut continuing = false;
        for line in stripped {
            let line = line.trim();
            if continuing {
                current.push(' ');
            } else {
                current.clear();
            }
            current.push_str(line);
            if current.ends_with('\\') {
                current.pop();
                continuing = true;
            } else {
                logical.push(std::mem::take(&mut current));
                continuing = false;
            }
        }
        if !current.is_empty() {
            logical.push(current);
        }
        let mut pairs = Vec::new();
        for instruction in logical {
            let (verb, rest) = match instruction.split_once(char::is_whitespace) {
                Some(parts) => parts,
                None => continue,
            };
            if !verb.eq_ignore_ascii_case("LABEL") {
                continue;
            }
            pairs.extend(label_pairs(rest));
        }
        pairs
    }

    /// Split a `LABEL` body into `key=value` pairs; a quoted value keeps its
    /// bytes, an unquoted value runs to the next whitespace.
    fn label_pairs(body: &str) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        let mut chars = body.chars().peekable();
        while chars.peek().is_some() {
            while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                chars.next();
            }
            let mut key = String::new();
            while let Some(&c) = chars.peek() {
                if c == '=' || c.is_whitespace() {
                    break;
                }
                key.push(c);
                chars.next();
            }
            if key.is_empty() {
                break;
            }
            if chars.peek() != Some(&'=') {
                continue;
            }
            chars.next();
            let mut value = String::new();
            if chars.peek() == Some(&'"') {
                chars.next();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        break;
                    }
                    if c == '\\' {
                        if let Some(escaped) = chars.next() {
                            value.push(escaped);
                        }
                    } else {
                        value.push(c);
                    }
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        break;
                    }
                    value.push(c);
                    chars.next();
                }
            }
            pairs.push((key, value));
        }
        pairs
    }

    /// The value of the single ACTIVE `LABEL KEY="..."`, or `None` when absent.
    /// A duplicate active label is a failure (there is no defensible selection).
    fn find_label_value(text: &str, key: &str) -> Option<String> {
        let values: Vec<String> = active_label_values(text)
            .into_iter()
            .filter(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
            .collect();
        match values.len() {
            0 => None,
            1 => Some(values.into_iter().next().expect("one value")),
            n => panic!("the {key} label must appear exactly once, found {n}"),
        }
    }

    /// The quoted value of an active `LABEL KEY="..."` (must appear once).
    fn label_value(text: &str, key: &str) -> String {
        find_label_value(text, key).unwrap_or_else(|| panic!("the {key} label is present"))
    }

    /// The active `org.agent-vm.version.*` keys of a Dockerfile.
    fn active_version_labels(text: &str) -> Vec<String> {
        active_label_values(text)
            .into_iter()
            .map(|(key, _)| key)
            .filter(|key| key.starts_with("org.agent-vm.version."))
            .collect()
    }

    /// Canonical semver 2.0.0 parsing of the exact slot the owning hook accepts
    /// (review E2): each core identifier is numeric with no leading zero; a
    /// pre-release identifier is numeric (no leading zero) or alphanumeric; a
    /// build identifier is digits (leading zeros allowed) or alphanumeric.
    fn is_exact_semver(body: &str) -> bool {
        fn numeric(s: &str) -> bool {
            !s.is_empty()
                && s.chars().all(|c| c.is_ascii_digit())
                && (s == "0" || !s.starts_with('0'))
        }
        fn digits(s: &str) -> bool {
            !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
        }
        fn alphanumeric(s: &str) -> bool {
            !s.is_empty()
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && s.chars().any(|c| !c.is_ascii_digit())
        }
        let (core_and_pre, build) = match body.split_once('+') {
            Some((head, build)) => (head, Some(build)),
            None => (body, None),
        };
        let (core, pre) = match core_and_pre.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (core_and_pre, None),
        };
        let core_ids: Vec<&str> = core.split('.').collect();
        if core_ids.len() != 3 || !core_ids.iter().all(|id| numeric(id)) {
            return false;
        }
        if pre.is_some_and(|p| {
            p.is_empty() || !p.split('.').all(|id| numeric(id) || alphanumeric(id))
        }) {
            return false;
        }
        if build
            .is_some_and(|b| b.is_empty() || !b.split('.').all(|id| digits(id) || alphanumeric(id)))
        {
            return false;
        }
        true
    }

    /// A structural proxy for the exact-input grammar the owning hooks enforce:
    /// nonempty, an exact canonical semver body, and no range/URL/floating
    /// marker.
    fn assert_exact_slot(value: &str, prefix: &str) {
        assert!(!value.is_empty(), "a selected slot must not be empty");
        let body = value
            .strip_prefix(prefix)
            .unwrap_or_else(|| panic!("the slot must start with {prefix:?}: {value:?}"));
        assert!(
            is_exact_semver(body),
            "the slot must be an exact semver version: {value:?}"
        );
        for forbidden in ['^', '~', '>', '<', '=', '*', '|', ' ', 'x', 'X', '@', '/'] {
            assert!(
                !value.contains(forbidden),
                "the slot must be exact, not a range/tag/URL: {value:?}"
            );
        }
    }

    /// Each single-slot recipe commits an exact nonempty default and its label
    /// names that same slot (the ARG is the label's only source).
    #[test]
    fn single_slot_recipes_pin_an_exact_default_and_reference_it_in_the_label() {
        for (label, recipe, arg) in &VERSION_SLOTS[..4] {
            let text = embedded_text(&format!("{recipe}/Dockerfile"));
            let value = dockerfile_arg(&text, arg);
            match *label {
                "codex" => assert_exact_slot(&value, "rust-v"),
                "opencode" => assert_exact_slot(&value, "v"),
                _ => assert_exact_slot(&value, ""),
            }
            assert_eq!(
                label_value(&text, &format!("org.agent-vm.version.{label}")),
                format!("${{{arg}}}"),
                "{recipe}: the version label must reference {arg}"
            );
        }
    }

    /// The two lock-backed recipes keep both ARGs EMPTY, and the label fallbacks
    /// mirror the committed manifests exactly -- the Dockerfile must never
    /// duplicate a pin as a nonempty ARG default, and a stale fallback must fail
    /// here rather than silently labelling the wrong selection.
    #[test]
    fn multi_slot_args_are_empty_and_label_fallbacks_mirror_the_manifests() {
        let dsh = embedded_text("dsh/Dockerfile");
        assert_eq!(dockerfile_arg(&dsh, "AGENT_VERSION_DSH"), "");
        assert_eq!(dockerfile_arg(&dsh, "AGENT_VERSION_PNPM"), "");
        let pnpm_pin = embedded_json("dsh/package.json")["dependencies"]["pnpm"]
            .as_str()
            .expect("the dsh manifest pins pnpm")
            .to_string();
        assert_eq!(
            label_value(&dsh, "org.agent-vm.version.dsh"),
            format!("${{AGENT_VERSION_DSH:-{}}}", dsh_pin()),
            "the dsh label fallback must mirror images/tools/dsh/package.json"
        );
        assert_eq!(
            label_value(&dsh, "org.agent-vm.version.pnpm"),
            format!("${{AGENT_VERSION_PNPM:-{pnpm_pin}}}"),
            "the pnpm label fallback must mirror images/tools/dsh/package.json"
        );

        let pi = embedded_text("pi/Dockerfile");
        assert_eq!(dockerfile_arg(&pi, "AGENT_VERSION_PI"), "");
        assert_eq!(dockerfile_arg(&pi, "AGENT_VERSION_PI_CLAUDE_BRIDGE"), "");
        assert_eq!(
            label_value(&pi, "org.agent-vm.version.pi"),
            format!("${{AGENT_VERSION_PI:-{}}}", pi_pin()),
            "the pi label fallback must mirror images/tools/pi/package.json"
        );
        assert_eq!(
            label_value(&pi, "org.agent-vm.version.pi-claude-bridge"),
            format!("${{AGENT_VERSION_PI_CLAUDE_BRIDGE:-{}}}", bridge_pin()),
            "the bridge label fallback must mirror images/tools/pi/bridge/package.json"
        );
    }

    /// All eight version labels are present exactly once across the six
    /// recipes: a missing or duplicated label silently breaks the selection
    /// tag/replay contract #228 consumes.
    #[test]
    fn every_shipped_version_label_is_present_exactly_once() {
        let mut seen: Vec<String> = Vec::new();
        for builtin in BuiltinLayer::ALL {
            let name = builtin.as_str();
            let text = embedded_text(&format!("{name}/Dockerfile"));
            seen.extend(active_version_labels(&text));
        }
        let mut expected: Vec<String> = VERSION_SLOTS
            .iter()
            .map(|(label, _, _)| format!("org.agent-vm.version.{label}"))
            .collect();
        seen.sort();
        expected.sort();
        assert_eq!(
            seen, expected,
            "the shipped version labels drifted from the eight-slot contract"
        );
    }

    /// The label guards must read ACTIVE `LABEL` instructions, not arbitrary
    /// substrings: commenting the label out of the real Dockerfile must fail the
    /// guard, and the uncommented control must pass (review E2).
    #[test]
    fn commented_out_version_labels_fail_the_guards() {
        // Control: the active fixture labels parse.
        assert_eq!(
            active_label_values("FROM scratch\nLABEL a=1 b=\"2\"\n"),
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string())
            ],
            "active LABEL pairs must parse"
        );
        assert_eq!(
            label_value(
                "FROM scratch\nLABEL org.agent-vm.version.copilot=\"${AGENT_VERSION_COPILOT}\"\n",
                "org.agent-vm.version.copilot"
            ),
            "${AGENT_VERSION_COPILOT}",
            "the active copilot label value must parse"
        );

        // Negative: a commented-out label is invisible to every guard.
        let commented =
            "FROM scratch\n# LABEL org.agent-vm.version.copilot=\"${AGENT_VERSION_COPILOT}\"\n";
        assert!(
            active_label_values(commented).is_empty(),
            "a commented LABEL must not be read: {commented:?}"
        );
        assert_eq!(
            find_label_value(commented, "org.agent-vm.version.copilot"),
            None,
            "a commented LABEL must fail the guard"
        );

        // The exact reviewer mutation, applied to the embedded Dockerfile: all
        // shipped-label guards must notice the missing active label.
        let copilot = embedded_text("copilot/Dockerfile");
        assert_eq!(
            label_value(&copilot, "org.agent-vm.version.copilot"),
            "${AGENT_VERSION_COPILOT}"
        );
        let mutated = copilot.replace(
            "LABEL org.agent-vm.version.copilot=",
            "# LABEL org.agent-vm.version.copilot=",
        );
        assert_ne!(mutated, copilot, "the mutation must change the text");
        assert_eq!(
            find_label_value(&mutated, "org.agent-vm.version.copilot"),
            None,
            "commenting out the copilot label must fail the guard"
        );
        assert!(
            !active_version_labels(&mutated).contains(&"org.agent-vm.version.copilot".to_string()),
            "the shipped-label set must notice the commented label"
        );
    }

    /// A LABEL continued across lines is joined before parsing, and the exact
    /// slot grammar rejects a non-numeric default that the old dot-count proxy
    /// accepted (review E2).
    #[test]
    fn continuations_join_and_the_exact_slot_grammar_rejects_bad_defaults() {
        let continued = "FROM scratch\nLABEL org.agent-vm.version.pi=\"x\" \\\n      org.agent-vm.version.pi-claude-bridge=\"y\"\n";
        assert_eq!(
            active_label_values(continued),
            vec![
                ("org.agent-vm.version.pi".to_string(), "x".to_string()),
                (
                    "org.agent-vm.version.pi-claude-bridge".to_string(),
                    "y".to_string()
                )
            ],
            "a continued LABEL must be joined"
        );

        for good in ["1.2.3", "0.159.3-alpha.1.2", "1.2.3-rc.1+build.01"] {
            assert!(is_exact_semver(good), "{good:?} is exact semver");
        }
        for bad in ["a.b.c", "01.2.3", "1.2.3-01", "1.2.3-a.", "1.2", "latest"] {
            assert!(!is_exact_semver(bad), "{bad:?} is NOT exact semver");
        }
    }

    /// Every per-recipe `contract/` copy is byte-identical to the canonical
    /// `images/recipe-contract/` source; `script/build/sync-recipe-contracts.sh
    /// --check` asserts the same, here so a `cargo test` catches a drifted copy.
    #[test]
    fn per_recipe_contract_copies_are_byte_identical_to_the_canonical_contract() {
        const CANONICAL: [&str; 6] = [
            "download.sh",
            "run-install.sh",
            "run-npm.sh",
            "run-report.sh",
            "check-tool-access.py",
            "install-status.py",
        ];
        for builtin in BuiltinLayer::ALL {
            let name = builtin.as_str();
            for file in CANONICAL {
                let canonical = fs::read(repo_path(&format!("images/recipe-contract/{file}")))
                    .unwrap_or_else(|error| panic!("read images/recipe-contract/{file}: {error}"));
                let copy = TOOL_LAYERS
                    .get_file(format!("{name}/contract/{file}"))
                    .unwrap_or_else(|| panic!("{name}/contract/{file} is embedded"))
                    .contents();
                assert_eq!(
                    canonical, copy,
                    "{name}/contract/{file} drifted from images/recipe-contract/{file}; \
                     run script/build/sync-recipe-contracts.sh --write"
                );
            }
        }
    }

    /// The base ships a blanket `agent-vm-install` download/run helper for
    /// compatibility; no shipped recipe may call it, because the exact-input,
    /// classified-transport and per-slot status contract lives in the recipe's
    /// own mounted `contract/` seam.
    #[test]
    fn no_shipped_recipe_calls_the_base_agent_vm_install_helper() {
        let mut offenders = Vec::new();
        for (path, contents) in embedded_files() {
            if !is_recipe_source(&path) {
                continue;
            }
            if String::from_utf8_lossy(&contents).contains("agent-vm-install") {
                offenders.push(path);
            }
        }
        assert!(
            offenders.is_empty(),
            "these shipped recipes still call the base agent-vm-install helper: {offenders:?}"
        );
    }

    /// A shipped recipe must not resolve an upstream "latest": no floating
    /// default, no `releases/latest`/`dist-tags.latest`/`@latest` lookup. The
    /// upstream `.upstream.sh` snapshots are display-only provenance (never run)
    /// and are excluded; only the runnable recipe sources are scanned, and only
    /// their non-comment lines.
    #[test]
    fn no_shipped_recipe_resolves_upstream_latest() {
        const FORBIDDEN: [&str; 6] = [
            "releases/latest",
            "/latest/download",
            "dist-tags.latest",
            "@latest",
            ":-latest",
            "claude-code-releases/latest",
        ];
        let mut offenders = Vec::new();
        for (path, contents) in embedded_files() {
            if !is_recipe_source(&path) || is_provenance_snapshot(&path) {
                continue;
            }
            let text = String::from_utf8_lossy(&contents);
            for (index, line) in text.lines().enumerate() {
                if line.trim_start().starts_with('#') {
                    continue;
                }
                for needle in FORBIDDEN {
                    if line.contains(needle) {
                        offenders.push(format!("{}:{}: {needle}", path.display(), index + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these shipped recipes still resolve upstream latest: {offenders:?}"
        );
    }

    /// A recipe Dockerfile/hook/contract/JSON source (not docs, not the
    /// `install.upstream.sh` provenance snapshots).
    fn is_recipe_source(path: &Path) -> bool {
        if is_provenance_snapshot(path) {
            return false;
        }
        matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("Dockerfile")
        ) || matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("sh" | "js" | "py")
        )
    }

    fn is_provenance_snapshot(path: &Path) -> bool {
        path.to_string_lossy().ends_with("install.upstream.sh")
    }

    /// The vendored runnable installers are the upstream snapshot plus a patch
    /// that enforces exact selection; the patch MUST reproduce the runnable copy
    /// from the snapshot byte-for-byte, or the reviewed diff and the shipped
    /// script have diverged. `script/test/*-installer.sh` cross-checks this with
    /// real `git apply`; this is the same guard in `cargo test`.
    #[test]
    fn vendored_installer_patches_reproduce_the_runnable_scripts() {
        for recipe in ["codex", "opencode", "claude"] {
            let upstream = embedded_text(&format!("{recipe}/vendor/install.upstream.sh"));
            let patch = embedded_text(&format!("{recipe}/vendor/install.patch"));
            let runnable = embedded_text(&format!("{recipe}/vendor/install.sh"));
            let applied = apply_unified_patch(&upstream, &patch);
            assert_eq!(
                applied, runnable,
                "{recipe}: vendor/install.patch no longer reproduces vendor/install.sh from \
                 vendor/install.upstream.sh"
            );
        }
    }

    /// Apply a `diff -u` patch to `original`; test-only (committed, reviewed
    /// fixture bytes -- not untrusted input). See
    /// `vendored_installer_patches_reproduce_the_runnable_scripts`.
    fn apply_unified_patch(original: &str, patch: &str) -> String {
        let orig: Vec<&str> = original.lines().collect();
        let patch_lines: Vec<&str> = patch.lines().collect();
        let mut out: Vec<&str> = Vec::new();
        let mut cursor = 0usize;
        let mut i = 0usize;
        while i < patch_lines.len() {
            let line = patch_lines[i];
            i += 1;
            let Some(header) = line.strip_prefix("@@ ") else {
                continue;
            };
            let ranges = header.split(" @@").next().expect("hunk header ranges");
            let mut fields = ranges.split(' ');
            let old = fields
                .next()
                .expect("old range")
                .strip_prefix('-')
                .expect("old range starts with -");
            let new = fields
                .next()
                .expect("new range")
                .strip_prefix('+')
                .expect("new range starts with +");
            let (a_start, a_count) = parse_hunk_range(old);
            let (_, c_count) = parse_hunk_range(new);
            let target = a_start.saturating_sub(1);
            while cursor < target {
                out.push(orig[cursor]);
                cursor += 1;
            }
            let (mut old_used, mut new_used) = (0usize, 0usize);
            while old_used < a_count || new_used < c_count {
                let hunk_line = patch_lines
                    .get(i)
                    .copied()
                    .unwrap_or_else(|| panic!("{header}: the hunk body ran out"));
                i += 1;
                let (tag, content) = hunk_line.split_at(1);
                match tag {
                    " " => {
                        assert_eq!(
                            content,
                            orig[cursor],
                            "context mismatch at old line {}",
                            cursor + 1
                        );
                        out.push(orig[cursor]);
                        cursor += 1;
                        old_used += 1;
                        new_used += 1;
                    }
                    "-" => {
                        assert_eq!(
                            content,
                            orig[cursor],
                            "deletion mismatch at old line {}",
                            cursor + 1
                        );
                        cursor += 1;
                        old_used += 1;
                    }
                    "+" => {
                        out.push(content);
                        new_used += 1;
                    }
                    other => panic!("unexpected hunk line tag {other:?}: {hunk_line:?}"),
                }
            }
        }
        while cursor < orig.len() {
            out.push(orig[cursor]);
            cursor += 1;
        }
        let mut result = out.join("\n");
        if original.ends_with('\n') {
            result.push('\n');
        }
        result
    }

    fn parse_hunk_range(range: &str) -> (usize, usize) {
        match range.split_once(',') {
            Some((start, count)) => (
                start.parse().expect("hunk start"),
                count.parse().expect("hunk count"),
            ),
            // An omitted count defaults to 1 (e.g. `@@ -5 +5 @@`).
            None => (range.parse().expect("hunk start"), 1),
        }
    }

    /// The exact-install hooks and vendored runnable installers are shipped and
    /// materialise 0644 (the execute bit is granted with `COPY --chmod=0755`,
    /// never from the source tree -- see
    /// `embedded_layer_sources_are_committed_without_the_execute_bit`).
    #[test]
    fn the_exact_install_hooks_are_shipped_and_materialise_at_0644() {
        let expected = [
            "codex/install-codex.sh",
            "codex/verify-codex.sh",
            "codex/vendor/install.sh",
            "opencode/install-opencode.sh",
            "opencode/verify-opencode.sh",
            "opencode/vendor/install.sh",
            "claude/install-claude.sh",
            "claude/verify-claude.sh",
            "claude/vendor/install.sh",
            "copilot/install-copilot.sh",
            "copilot/verify-copilot.sh",
            "dsh/install-dsh.sh",
            "dsh/verify-dsh.sh",
            "dsh/prepare-lock.sh",
            "dsh/check-lock-update.js",
            "pi/install-pi.sh",
            "pi/install-pi-packages.sh",
            "pi/verify-pi.sh",
            "pi/prepare-lock.sh",
            "pi/bridge/prepare-lock.sh",
        ];
        for rel in expected {
            assert!(
                TOOL_LAYERS.get_file(rel).is_some(),
                "{rel} must be embedded in the shipped tool layers"
            );
        }

        let catalog =
            crate::config::default_launch_catalog().expect("the default catalog resolves");
        let (dirs, _guard) =
            materialize(&catalog.declared_layers()).expect("materialize the shipped set");
        let mut seen = 0usize;
        for dir in &dirs {
            let mut stack = vec![dir.dir.clone()];
            while let Some(current) = stack.pop() {
                for entry in fs::read_dir(&current).expect("read a materialised context") {
                    let entry = entry.expect("read a dir entry");
                    if entry.file_type().expect("file type").is_dir() {
                        stack.push(entry.path());
                        continue;
                    }
                    let mode = entry.metadata().expect("stat").permissions().mode() & 0o777;
                    assert_eq!(
                        mode,
                        0o644,
                        "{} must materialise 0644",
                        entry.path().display()
                    );
                    seen += 1;
                }
            }
        }
        assert!(seen > 0, "the shipped layers materialise files");
    }
}
