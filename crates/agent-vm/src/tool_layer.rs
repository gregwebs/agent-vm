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

/// The four shipped tool layer sources, embedded at compile time. The path
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
             Drop one. (AGENT_VM_IMAGE_TAG / AGENT_VM_BASE_IMAGE count as passing the flag.)"
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
                let anchored = declared_path.anchored(layer.anchor()).with_context(|| {
                    format!(
                        "resolving the `layer = {{ path = … }}` declared by tool \"{}\"",
                        layer.tool()
                    )
                })?;
                let canonical = anchored.canonicalize().with_context(|| {
                    format!(
                        "tool \"{}\": layer path {} does not exist",
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
/// per-filename special cases. `layer::canonical_stream` folds a file's mode to
/// a single execute bit (`layer::git_mode`), so a byte-identical git checkout of
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
                write_tree(sub, dest)?;
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
        assert!(dirs[0].label.contains("a"), "{}", dirs[0].label);
        assert!(!dirs[0].label.contains("/tmp"), "{}", dirs[0].label);
        assert!(!dirs[0].label.contains("T/"), "{}", dirs[0].label);
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
}
