//! Turns a derived Layer DAG into a pre-build [`CompositionPlan`]: the unique
//! participating artifacts in stitch order, each with its identity computed,
//! plus the composition identity (issue #228, roadmap CP1). Pure — no store,
//! digest, artifact or I/O.
//!
//! # Why a separate planner
//!
//! Identity propagation, first-holder deduplication and index remapping are
//! one piece of difficult ordering logic. Doing them here, once, keeps each
//! call site (CP2's shadow harness, CP7's compose seam, CP9's request adapter)
//! from re-deriving parent order or accidentally hashing against the wrong
//! parent. Callers supply names, parents, payloads and per-node inputs; the
//! planner supplies the rest.
//!
//! # The index contract
//!
//! After dedupe, [`PlannedLayer::index`] may have gaps: it is the layer's
//! **original** graph stitch index, not an offset into [`CompositionPlan::layers`].
//! [`PlannedLayer::parent`] likewise names a retained holder's original index.
//! Later checkpoints look a layer up by `index`; they must never index the
//! compact `layers()` vector with `parent.get()`. Internally `identify` keeps a
//! graph-index to holder-offset map so dedupe cannot move a child's parent.
//!
//! # Deduplication (I6)
//!
//! Two layers with the same computed identity participate once: the first in
//! derived stitch order is the holder, and later keys become aliases. The key
//! includes parent and all hashed inputs, so the same source under a different
//! parent or pin stays distinct. Aliases make the association to the holder
//! visible; dedupe never deletes catalog entries, and the complete resolved
//! request stays outside this compact artifact-only plan (CP8/CP9 retain it)
//! so no command, account or validation obligation is bypassed.

use std::collections::HashMap;

use anyhow::{Context, Result};

use super::dag::{LayerGraph, LayerKey, StitchIndex};
use super::identity::{
    ArtifactIdentity, ArtifactInputs, CompositionIdentity, ParentIdentity, RootIdentity,
};

/// One unique participating artifact in stitch order.
pub(crate) struct PlannedLayer<T> {
    /// The first holder's **original** graph stitch index, possibly gapped.
    pub(crate) index: StitchIndex,
    pub(crate) key: LayerKey,
    /// Later keys with an identical identity, in graph stitch order.
    pub(crate) aliases: Vec<LayerKey>,
    /// The first holder's parent index, or the parent's retained holder.
    /// `None` means the composition root.
    pub(crate) parent: Option<StitchIndex>,
    pub(crate) parent_identity: ParentIdentity,
    pub(crate) inputs: ArtifactInputs,
    pub(crate) identity: ArtifactIdentity,
    /// The first holder's payload; a later duplicate's payload is dropped.
    pub(crate) payload: T,
}

/// The root plus its unique participating artifacts, with the derived
/// composition identity. Computed before any build.
pub(crate) struct CompositionPlan<T> {
    root: RootIdentity,
    layers: Vec<PlannedLayer<T>>,
    identity: CompositionIdentity,
}

impl<T> CompositionPlan<T> {
    /// Computes every artifact identity in stitch order, then the composition
    /// identity. `inputs_for` is called exactly once per original graph node —
    /// including nodes that turn out to be aliases, because identity equality
    /// can only be decided after their inputs exist — and its error names the
    /// node it failed on.
    pub(crate) fn identify(
        root: RootIdentity,
        graph: LayerGraph<T>,
        mut inputs_for: impl FnMut(&LayerKey, &T) -> Result<ArtifactInputs>,
    ) -> Result<Self> {
        let mut layers: Vec<PlannedLayer<T>> = Vec::with_capacity(graph.len());
        // Indexed by original graph stitch index; each entry is the offset
        // into `layers` that holds (or first held) that node's artifact.
        let mut holder_by_graph: Vec<usize> = Vec::with_capacity(graph.len());
        let mut first_holder: HashMap<ArtifactIdentity, usize> = HashMap::new();

        for node in graph.into_stitch_order() {
            let (parent, parent_identity) = match node.parent {
                None => (None, ParentIdentity::Root(root)),
                Some(parent_index) => {
                    let holder_offset = *holder_by_graph
                        .get(parent_index.get())
                        .context("internal: a graph parent was not placed before its child")?;
                    let holder = layers
                        .get(holder_offset)
                        .context("internal: a graph parent has no retained artifact")?;
                    (Some(holder.index), ParentIdentity::Layer(holder.identity))
                }
            };

            let inputs = inputs_for(&node.key, &node.payload)
                .with_context(|| format!("computing the identity of layer {}", node.key))?;
            let identity = ArtifactIdentity::compute(parent_identity, &inputs);

            if let Some(&holder_offset) = first_holder.get(&identity) {
                let holder = layers
                    .get_mut(holder_offset)
                    .context("internal: a duplicate artifact has no retained holder")?;
                holder.aliases.push(node.key);
                // A descendant of this alias inherits the holder's identity
                // and retained index, not a fresh node.
                holder_by_graph.push(holder_offset);
                continue;
            }

            let holder_offset = layers.len();
            first_holder.insert(identity, holder_offset);
            holder_by_graph.push(holder_offset);
            layers.push(PlannedLayer {
                index: node.index,
                key: node.key,
                aliases: Vec::new(),
                parent,
                parent_identity,
                inputs,
                identity,
                payload: node.payload,
            });
        }

        let ordered: Vec<ArtifactIdentity> = layers.iter().map(|layer| layer.identity).collect();
        Ok(Self {
            root,
            layers,
            identity: CompositionIdentity::compute(root, &ordered),
        })
    }

    pub(crate) fn root(&self) -> RootIdentity {
        self.root
    }

    pub(crate) fn identity(&self) -> CompositionIdentity {
        self.identity
    }

    pub(crate) fn layers(&self) -> &[PlannedLayer<T>] {
        &self.layers
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use anyhow::bail;
    use proptest::prelude::*;

    use super::*;
    use crate::composition::dag::{CatalogNode, InjectedLabel, InjectedLayer, ParentRef};
    use crate::composition::identity::{
        AccountLayerIdentity, ContextDigest, ManifestDigest, RootInputs,
    };
    use crate::composition::test_support::{args, layer_name, root, two_context_digests};

    fn graph_with_injected(
        rows: &[(&'static str, Option<&'static str>, &'static str)],
        labels: &[(&'static str, &'static str)],
    ) -> LayerGraph<&'static str> {
        LayerGraph::derive(
            rows.iter()
                .map(|(name, parent, payload)| CatalogNode {
                    name: layer_name(name),
                    parent: match parent {
                        Some(parent) => ParentRef::Layer(layer_name(parent)),
                        None => ParentRef::Root,
                    },
                    payload: *payload,
                })
                .collect(),
            labels
                .iter()
                .map(|(label, payload)| InjectedLayer {
                    label: InjectedLabel::new(label),
                    payload: *payload,
                })
                .collect(),
        )
        .expect("fixture graph derives")
    }

    /// The standard locality fixture: codex, claude, claude-plugin -> claude,
    /// rust-dev. Payloads are the logical ids the inputs key on, so renaming a
    /// layer (L4) leaves its inputs unchanged.
    fn locality_fixture() -> LayerGraph<&'static str> {
        graph_with_injected(
            &[
                ("codex", None, "codex"),
                ("claude", None, "claude"),
                ("claude-plugin", Some("claude"), "plugin"),
                ("rust-dev", None, "rust"),
            ],
            &[],
        )
    }

    fn inputs(
        payload: &str,
        context: ContextDigest,
        versions: &HashMap<&str, &str>,
    ) -> ArtifactInputs {
        let version = versions.get(payload).copied().unwrap_or("1");
        ArtifactInputs {
            context,
            build_args: args(&[("LAYER_MARKER", payload), ("LAYER_VERSION", version)]),
        }
    }

    fn identify(
        graph: LayerGraph<&'static str>,
        context: ContextDigest,
        versions: &HashMap<&'static str, &'static str>,
        root: RootIdentity,
    ) -> (CompositionPlan<&'static str>, Vec<String>) {
        let mut calls = Vec::new();
        let plan = CompositionPlan::identify(root, graph, |key, payload| {
            calls.push(key.to_string());
            Ok(inputs(payload, context, versions))
        })
        .expect("fixture identifies");
        (plan, calls)
    }

    fn by_payload<'a>(
        plan: &'a CompositionPlan<&'static str>,
        payload: &str,
    ) -> &'a PlannedLayer<&'static str> {
        plan.layers()
            .iter()
            .find(|layer| layer.payload == payload)
            .expect("payload present")
    }

    fn strings(keys: &[LayerKey]) -> Vec<String> {
        keys.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn tool_bump_changes_only_that_layer_and_its_descendants() {
        let context = two_context_digests().0;
        let root = root(None);
        let base_versions = HashMap::<&str, &str>::new();
        let (before, _) = identify(locality_fixture(), context, &base_versions, root);

        let mut bumped_versions = HashMap::new();
        bumped_versions.insert("claude", "2");
        let (after, _) = identify(locality_fixture(), context, &bumped_versions, root);

        assert_eq!(
            by_payload(&before, "codex").identity,
            by_payload(&after, "codex").identity
        );
        assert_ne!(
            by_payload(&before, "claude").identity,
            by_payload(&after, "claude").identity
        );
        assert_ne!(
            by_payload(&before, "plugin").identity,
            by_payload(&after, "plugin").identity
        );
        assert_eq!(
            by_payload(&before, "rust").identity,
            by_payload(&after, "rust").identity
        );
        assert_ne!(before.identity(), after.identity());

        // The locality fixture cannot distinguish the *actual* parent from the
        // stitch predecessor: `claude-plugin` immediately follows its parent
        // `claude`. Here `late-plugin` is declared last and parented to
        // `codex`, so its predecessor in stitch order is `rust-dev`. A
        // regression that hashed against the preceding stitch entry instead
        // of the declared parent would leave `late-plugin` unchanged when its
        // real parent is bumped, which the assertion below forbids; `rust-dev`
        // is independent and must stay put under both.
        let non_predecessor_fixture = || {
            graph_with_injected(
                &[
                    ("codex", None, "codex"),
                    ("claude", None, "claude"),
                    ("claude-plugin", Some("claude"), "plugin"),
                    ("rust-dev", None, "rust"),
                    ("late-plugin", Some("codex"), "late"),
                ],
                &[],
            )
        };
        let (before, _) = identify(non_predecessor_fixture(), context, &base_versions, root);
        let mut codex_bumped = HashMap::new();
        codex_bumped.insert("codex", "2");
        let (after, _) = identify(non_predecessor_fixture(), context, &codex_bumped, root);
        assert_ne!(
            by_payload(&before, "late").identity,
            by_payload(&after, "late").identity,
            "bumping codex must change its child late-plugin, whose actual parent is not \
             its stitch predecessor"
        );
        assert_eq!(
            by_payload(&before, "rust").identity,
            by_payload(&after, "rust").identity,
            "rust-dev is independent of codex and must not move"
        );
    }

    #[test]
    fn root_changes_propagate_to_every_artifact() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let baseline_root = root(None);
        let (baseline, _) = identify(locality_fixture(), context, &versions, baseline_root);
        assert_eq!(baseline.root(), baseline_root);

        let other_base = ManifestDigest::parse(&format!("sha256:{}", "2".repeat(64))).unwrap();
        let changed_roots = [
            RootIdentity::compute(&RootInputs {
                base: &other_base,
                accounts: None,
            }),
            root(Some(AccountLayerIdentity::of_canonical_bytes(
                b"root:x:0:0\n",
            ))),
            root(Some(AccountLayerIdentity::of_canonical_bytes(&[]))),
        ];
        for changed_root in changed_roots {
            let (changed, _) = identify(locality_fixture(), context, &versions, changed_root);
            for layer in baseline.layers() {
                let other = changed
                    .layers()
                    .iter()
                    .find(|other| other.key == layer.key)
                    .expect("same key");
                assert_ne!(layer.identity, other.identity, "{}", layer.key);
            }
            assert_ne!(baseline.identity(), changed.identity());
        }

        // A nonempty union replaced by a different nonempty union, base and
        // context unchanged: every artifact and the final identity must move.
        let union_a = root(Some(AccountLayerIdentity::of_canonical_bytes(
            b"root:x:0:0\n",
        )));
        let union_b = root(Some(AccountLayerIdentity::of_canonical_bytes(
            b"root:x:0:1\n",
        )));
        let (before, _) = identify(locality_fixture(), context, &versions, union_a);
        let (after, _) = identify(locality_fixture(), context, &versions, union_b);
        for layer in before.layers() {
            let other = after
                .layers()
                .iter()
                .find(|other| other.key == layer.key)
                .expect("same key");
            assert_ne!(layer.identity, other.identity, "{}", layer.key);
        }
        assert_ne!(before.identity(), after.identity());
    }

    #[test]
    fn injected_and_declared_identical_sources_share_identity() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let root = root(None);

        let (declared, _) = identify(
            graph_with_injected(&[("codex", None, "codex"), ("chrome", None, "chrome")], &[]),
            context,
            &versions,
            root,
        );
        let (injected, _) = identify(
            graph_with_injected(&[("codex", None, "codex")], &[("./chrome", "chrome")]),
            context,
            &versions,
            root,
        );

        let declared_chrome = by_payload(&declared, "chrome");
        let injected_chrome = by_payload(&injected, "chrome");
        assert_eq!(declared_chrome.key.to_string(), "chrome");
        assert_eq!(injected_chrome.key.to_string(), "--layer ./chrome");
        assert_eq!(declared_chrome.identity, injected_chrome.identity);
        assert_eq!(declared.identity(), injected.identity());
    }

    #[test]
    fn layer_name_does_not_enter_identity() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let root = root(None);

        let (base, _) = identify(locality_fixture(), context, &versions, root);
        let (renamed, _) = identify(
            graph_with_injected(
                &[
                    ("codex", None, "codex"),
                    ("claude2", None, "claude"),
                    ("plugin2", Some("claude2"), "plugin"),
                    ("rust-dev", None, "rust"),
                ],
                &[],
            ),
            context,
            &versions,
            root,
        );

        for layer in base.layers() {
            let other = by_payload(&renamed, layer.payload);
            assert_eq!(layer.identity, other.identity, "{}", layer.payload);
        }
        assert_eq!(base.identity(), renamed.identity());
    }

    #[test]
    fn parent_identity_is_the_actual_parents() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let root = root(None);
        let (plan, _) = identify(locality_fixture(), context, &versions, root);

        let codex = by_payload(&plan, "codex");
        let claude = by_payload(&plan, "claude");
        let plugin = by_payload(&plan, "plugin");

        assert_eq!(codex.parent, None);
        assert_eq!(codex.parent_identity, ParentIdentity::Root(root));
        assert_eq!(plugin.parent, Some(claude.index));
        assert_eq!(
            plugin.parent_identity,
            ParentIdentity::Layer(claude.identity)
        );
        assert_eq!(plugin.inputs, inputs("plugin", context, &versions));
        assert!(plugin.index.get() > claude.index.get());
    }

    #[test]
    fn duplicate_sources_keep_the_first_identity_holder() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let root = root(None);

        let (plan, _) = identify(
            graph_with_injected(
                &[
                    ("claude", None, "claude"),
                    ("claude-yolo", None, "claude"),
                    ("plugin", Some("claude-yolo"), "plugin"),
                ],
                &[],
            ),
            context,
            &versions,
            root,
        );

        assert_eq!(
            plan.layers().len(),
            2,
            "one claude artifact plus one plugin"
        );
        let claude = by_payload(&plan, "claude");
        assert_eq!(claude.key.to_string(), "claude");
        assert_eq!(strings(&claude.aliases), vec!["claude-yolo"]);
        let plugin = by_payload(&plan, "plugin");
        assert_eq!(plugin.parent, Some(claude.index));
        assert_eq!(
            plugin.parent_identity,
            ParentIdentity::Layer(claude.identity)
        );

        let (singleton, _) = identify(
            graph_with_injected(
                &[
                    ("claude", None, "claude"),
                    ("plugin", Some("claude"), "plugin"),
                ],
                &[],
            ),
            context,
            &versions,
            root,
        );
        assert_eq!(plan.identity(), singleton.identity());
        assert_eq!(plan.layers().len(), singleton.layers().len());

        // Two different directory labels whose normalized bytes are equal: the
        // callback returns identical inputs, so they dedupe and the first
        // payload and key are retained.
        let same_inputs = |_: &LayerKey, _: &&'static str| -> Result<ArtifactInputs> {
            Ok(ArtifactInputs {
                context,
                build_args: args(&[("LAYER_MARKER", "shared")]),
            })
        };
        let equal_bytes = LayerGraph::derive(
            vec![
                CatalogNode {
                    name: layer_name("alpha"),
                    parent: ParentRef::Root,
                    payload: "alpha",
                },
                CatalogNode {
                    name: layer_name("beta"),
                    parent: ParentRef::Root,
                    payload: "beta",
                },
            ],
            Vec::new(),
        )
        .unwrap();
        let deduped = CompositionPlan::identify(root, equal_bytes, same_inputs).unwrap();
        assert_eq!(deduped.layers().len(), 1);
        assert_eq!(deduped.layers()[0].payload, "alpha");
        assert_eq!(strings(&deduped.layers()[0].aliases), vec!["beta"]);
    }

    #[test]
    fn declared_source_plus_cli_injection_is_deduplicated() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let root = root(None);

        let (plan, _) = identify(
            graph_with_injected(&[("x", None, "x")], &[("./x", "x")]),
            context,
            &versions,
            root,
        );
        assert_eq!(plan.layers().len(), 1);
        let x = by_payload(&plan, "x");
        assert_eq!(x.key.to_string(), "x");
        assert_eq!(strings(&x.aliases), vec!["--layer ./x"]);

        let (declared_only, _) = identify(
            graph_with_injected(&[("x", None, "x")], &[]),
            context,
            &versions,
            root,
        );
        assert_eq!(plan.identity(), declared_only.identity());

        // A second declared alias before another root and a child, with the CLI
        // alias last: the compact list keeps the first holder's original,
        // gapped index while the child maps to the right parent.
        let (gapped, _) = identify(
            graph_with_injected(
                &[
                    ("x", None, "x"),
                    ("x-alias", None, "x"),
                    ("y", None, "y"),
                    ("y-child", Some("y"), "y-child"),
                ],
                &[("./x", "x")],
            ),
            context,
            &versions,
            root,
        );
        assert_eq!(gapped.layers().len(), 3);
        let x = by_payload(&gapped, "x");
        let y = by_payload(&gapped, "y");
        let child = by_payload(&gapped, "y-child");
        assert_eq!(x.index.get(), 0);
        assert_eq!(y.index.get(), 2);
        assert_eq!(child.index.get(), 3);
        assert_eq!(strings(&x.aliases), vec!["x-alias", "--layer ./x"]);
        assert_eq!(child.parent, Some(y.index));
        assert_eq!(child.parent_identity, ParentIdentity::Layer(y.identity));
    }

    #[test]
    fn same_inputs_under_different_parents_are_not_duplicates() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let root = root(None);

        let (plan, _) = identify(
            graph_with_injected(
                &[
                    ("claude", None, "claude"),
                    ("x", None, "x"),
                    ("x-under-claude", Some("claude"), "x"),
                ],
                &[],
            ),
            context,
            &versions,
            root,
        );

        assert_eq!(plan.layers().len(), 3);
        assert!(plan.layers().iter().all(|layer| layer.aliases.is_empty()));
        let by_key = |key: &str| {
            plan.layers()
                .iter()
                .find(|layer| layer.key.to_string() == key)
                .unwrap()
        };
        let x = by_key("x");
        let x_child = by_key("x-under-claude");
        assert_eq!(x.inputs, x_child.inputs, "equal own inputs");
        assert_eq!(x.parent_identity, ParentIdentity::Root(root));
        assert_eq!(
            x_child.parent_identity,
            ParentIdentity::Layer(by_key("claude").identity)
        );
        assert_ne!(x.identity, x_child.identity);
    }

    #[test]
    fn the_first_derived_holder_wins_over_earlier_declaration() {
        let context = two_context_digests().0;
        let root = root(None);
        // Two identical parents and two identical children. `c1` is declared
        // first, but its parent `p-late` is placed after `p-early`, so `c2`
        // holds the artifact in derived stitch order; `c1` becomes its alias.
        let graph = graph_with_injected(
            &[
                ("c1", Some("p-late"), "child"),
                ("p-early", None, "parent"),
                ("c2", Some("p-early"), "child"),
                ("p-late", None, "parent"),
                ("d1", Some("c1"), "descendant"),
            ],
            &[],
        );
        let plan = CompositionPlan::identify(root, graph, |_key, payload: &&'static str| {
            Ok(ArtifactInputs {
                context,
                build_args: args(&[("LAYER_MARKER", *payload)]),
            })
        })
        .unwrap();

        let keys: Vec<String> = plan
            .layers()
            .iter()
            .map(|layer| layer.key.to_string())
            .collect();
        assert_eq!(keys, vec!["p-early", "c2", "d1"]);
        let by_key = |key: &str| {
            plan.layers()
                .iter()
                .find(|layer| layer.key.to_string() == key)
                .unwrap()
        };
        let p_early = by_key("p-early");
        assert_eq!(strings(&p_early.aliases), vec!["p-late"]);
        let c2 = by_key("c2");
        assert_eq!(
            strings(&c2.aliases),
            vec!["c1"],
            "the later-declared c2 holds c1's artifact in derived order"
        );
        assert_eq!(c2.parent, Some(p_early.index));
        assert_eq!(c2.parent_identity, ParentIdentity::Layer(p_early.identity));
        let d1 = by_key("d1");
        assert_eq!(
            d1.parent,
            Some(c2.index),
            "a descendant of the alias c1 uses the retained holder"
        );
        assert_eq!(d1.parent_identity, ParentIdentity::Layer(c2.identity));
    }

    #[test]
    fn equal_context_with_different_pins_under_the_same_root_stays_two_artifacts() {
        let context = two_context_digests().0;
        let root = root(None);
        let graph = graph_with_injected(&[("a", None, "a"), ("b", None, "b")], &[]);
        let plan = CompositionPlan::identify(root, graph, |_key, payload: &&'static str| {
            Ok(ArtifactInputs {
                context,
                build_args: args(&[("PIN", *payload)]),
            })
        })
        .unwrap();

        assert_eq!(
            plan.layers().len(),
            2,
            "equal parents and contexts but different pins stay distinct"
        );
        assert!(plan.layers().iter().all(|layer| layer.aliases.is_empty()));
        let a = by_payload(&plan, "a");
        let b = by_payload(&plan, "b");
        assert_eq!(a.parent_identity, ParentIdentity::Root(root));
        assert_eq!(b.parent_identity, ParentIdentity::Root(root));
        assert_eq!(a.inputs.context, b.inputs.context);
        assert_ne!(a.inputs.build_args, b.inputs.build_args);
        assert_ne!(a.identity, b.identity);
    }

    #[test]
    fn a_duplicate_alias_callback_failure_is_reported_not_skipped() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let root = root(None);
        let graph = graph_with_injected(
            &[("claude", None, "claude"), ("claude-dupe", None, "claude")],
            &[],
        );
        let mut calls = Vec::new();
        let error = match CompositionPlan::identify(root, graph, |key, payload: &&'static str| {
            calls.push(key.to_string());
            if key.to_string() == "claude-dupe" {
                bail!("alias boom");
            }
            Ok(inputs(payload, context, &versions))
        }) {
            Ok(_) => panic!("the callback must fail"),
            Err(error) => error,
        };

        assert_eq!(
            calls,
            vec!["claude", "claude-dupe"],
            "the soon-to-be alias is still visited exactly once"
        );
        assert!(
            error.to_string().contains("claude-dupe"),
            "the failure must name the alias node: {error}"
        );
    }

    fn recording_graph() -> LayerGraph<&'static str> {
        graph_with_injected(
            &[
                ("codex", None, "codex"),
                ("claude", None, "claude"),
                ("claude-dupe", None, "claude"),
                ("claude-plugin", Some("claude"), "plugin"),
                ("rust-dev", None, "rust"),
            ],
            &[],
        )
    }

    #[test]
    fn an_inputs_error_names_the_layer_and_stops_callbacks() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let root = root(None);

        let mut calls = Vec::new();
        let error = match CompositionPlan::identify(
            root,
            recording_graph(),
            |key, payload: &&'static str| -> Result<ArtifactInputs> {
                calls.push(key.to_string());
                if key.to_string() == "claude-plugin" {
                    bail!("boom");
                }
                Ok(inputs(payload, context, &versions))
            },
        ) {
            Ok(_) => panic!("the callback must fail"),
            Err(error) => error,
        };

        assert_eq!(
            calls,
            vec!["codex", "claude", "claude-dupe", "claude-plugin"],
            "the alias node is visited and the failure stops later calls"
        );
        assert!(
            error.to_string().contains("claude-plugin"),
            "the error must name the failing layer: {error}"
        );

        let (_, calls) = identify(recording_graph(), context, &versions, root);
        assert_eq!(
            calls,
            vec![
                "codex",
                "claude",
                "claude-dupe",
                "claude-plugin",
                "rust-dev",
            ]
        );
    }

    #[test]
    fn composition_identity_is_order_sensitive() {
        let context = two_context_digests().0;
        let versions = HashMap::<&str, &str>::new();
        let root = root(None);

        let (forward, _) = identify(
            graph_with_injected(&[("a", None, "a"), ("b", None, "b")], &[]),
            context,
            &versions,
            root,
        );
        let (backward, _) = identify(
            graph_with_injected(&[("b", None, "b"), ("a", None, "a")], &[]),
            context,
            &versions,
            root,
        );

        assert_eq!(
            forward
                .layers()
                .iter()
                .map(|layer| layer.key.to_string())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(
            backward
                .layers()
                .iter()
                .map(|layer| layer.key.to_string())
                .collect::<Vec<_>>(),
            vec!["b", "a"]
        );

        let forward_ids: Vec<ArtifactIdentity> = forward
            .layers()
            .iter()
            .map(|layer| layer.identity)
            .collect();
        let backward_ids: Vec<ArtifactIdentity> = backward
            .layers()
            .iter()
            .map(|layer| layer.identity)
            .collect();
        let forward_set: HashSet<ArtifactIdentity> = forward_ids.iter().copied().collect();
        let backward_set: HashSet<ArtifactIdentity> = backward_ids.iter().copied().collect();
        assert_eq!(forward_set, backward_set, "the same artifacts participate");
        assert_ne!(forward_ids, backward_ids);
        assert_ne!(forward.identity(), backward.identity());
    }

    // --- P6: locality and declaration-order independence ---

    #[derive(Debug, Clone, Copy)]
    enum Perturbation {
        Context,
        Arg,
    }

    #[derive(Debug, Clone)]
    struct PlanCase {
        /// Parent as a topological index, or root.
        topo_parents: Vec<Option<usize>>,
        /// Which cached context each topological node uses.
        topo_contexts: Vec<usize>,
        /// Declaration order as topological indices.
        declaration_order: Vec<usize>,
        perturb: Option<(usize, Perturbation)>,
    }

    fn plan_case() -> impl Strategy<Value = PlanCase> {
        (1usize..=10)
            .prop_flat_map(|count| {
                (
                    Just(count),
                    prop::collection::vec(prop::option::of(0usize..count), count),
                    prop::collection::vec(0usize..2, count),
                    prop::collection::vec(any::<u32>(), count),
                    prop::option::of((0usize..count, any::<bool>())),
                )
            })
            .prop_map(|(count, raw_parents, contexts, sort_keys, perturb)| {
                let topo_parents: Vec<Option<usize>> = (0..count)
                    .map(|index| {
                        if index == 0 {
                            None
                        } else {
                            raw_parents[index].map(|parent| parent.min(index - 1))
                        }
                    })
                    .collect();
                let mut declaration_order: Vec<usize> = (0..count).collect();
                declaration_order.sort_by_key(|&topo| (sort_keys[topo], topo));
                PlanCase {
                    topo_parents,
                    topo_contexts: contexts,
                    declaration_order,
                    perturb: perturb.map(|(node, context)| {
                        (
                            node,
                            if context {
                                Perturbation::Context
                            } else {
                                Perturbation::Arg
                            },
                        )
                    }),
                }
            })
    }

    struct Built {
        by_name: HashMap<String, ArtifactIdentity>,
        order: Vec<ArtifactIdentity>,
        final_identity: CompositionIdentity,
    }

    fn build(case: &PlanCase, order: &[usize], apply_perturbation: bool) -> Built {
        let digests = two_context_digests();
        let names: Vec<String> = (0..case.topo_parents.len())
            .map(|index| format!("n{index}"))
            .collect();
        let declared: Vec<CatalogNode<(usize, String)>> = order
            .iter()
            .map(|&topo| CatalogNode {
                name: layer_name(&names[topo]),
                parent: match case.topo_parents[topo] {
                    Some(parent) => ParentRef::Layer(layer_name(&names[parent])),
                    None => ParentRef::Root,
                },
                payload: (topo, names[topo].clone()),
            })
            .collect();
        let graph = LayerGraph::derive(declared, Vec::new()).unwrap();

        let contexts = &case.topo_contexts;
        let perturb = if apply_perturbation {
            case.perturb
        } else {
            None
        };
        let plan =
            CompositionPlan::identify(root(None), graph, |_key, payload: &(usize, String)| {
                let (topo, name) = payload;
                let mut context = if contexts[*topo] == 0 {
                    digests.0
                } else {
                    digests.1
                };
                let mut pairs: Vec<(&str, &str)> = vec![("LAYER_MARKER", name.as_str())];
                if let Some((target, kind)) = perturb
                    && *topo == target
                {
                    match kind {
                        Perturbation::Context => {
                            context = if contexts[*topo] == 0 {
                                digests.1
                            } else {
                                digests.0
                            };
                        }
                        Perturbation::Arg => pairs.push(("LAYER_PERTURB", "1")),
                    }
                }
                Ok(ArtifactInputs {
                    context,
                    build_args: args(&pairs),
                })
            })
            .unwrap();

        Built {
            by_name: plan
                .layers()
                .iter()
                .map(|layer| (layer.payload.1.clone(), layer.identity))
                .collect(),
            order: plan.layers().iter().map(|layer| layer.identity).collect(),
            final_identity: plan.identity(),
        }
    }

    /// Every node whose parent chain reaches `target` (including `target`).
    fn descendants(parents: &[Option<usize>], target: usize) -> Vec<bool> {
        (0..parents.len())
            .map(|node| {
                let mut current = node;
                for _ in 0..=parents.len() {
                    if current == target {
                        return true;
                    }
                    match parents[current] {
                        Some(parent) => current = parent,
                        None => return false,
                    }
                }
                false
            })
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn input_locality_and_declaration_permutations(case in plan_case()) {
            let topological_order: Vec<usize> = (0..case.topo_parents.len()).collect();

            let shuffled = build(&case, &case.declaration_order, false);
            let canonical = build(&case, &topological_order, false);

            // Declaration order does not enter an artifact's identity.
            prop_assert_eq!(&shuffled.by_name, &canonical.by_name);

            // The composition identity is recomputed from the ordered list, so
            // it changes exactly when a permutation changes that list.
            if shuffled.order == canonical.order {
                prop_assert_eq!(shuffled.final_identity, canonical.final_identity);
            } else {
                prop_assert_ne!(shuffled.final_identity, canonical.final_identity);
            }

            if let Some((target, _)) = case.perturb {
                let perturbed = build(&case, &case.declaration_order, true);
                let changed = descendants(&case.topo_parents, target);
                for (topo, &is_changed) in changed.iter().enumerate() {
                    let name = format!("n{topo}");
                    let before = shuffled.by_name[&name];
                    let after = perturbed.by_name[&name];
                    if is_changed {
                        prop_assert_ne!(before, after, "{} must change", name);
                    } else {
                        prop_assert_eq!(before, after, "{} must not change", name);
                    }
                }
                prop_assert_ne!(shuffled.final_identity, perturbed.final_identity);
            }
        }
    }
}
