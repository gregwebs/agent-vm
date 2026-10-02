//! The Layer DAG: names, parents, derived stitch order and graph errors
//! (issue #228, roadmap CP1). Pure — no I/O, no catalog, no tiers.
//!
//! A layer's parent is either the composition root or one declared layer.
//! Stitch order is *derived* by repeatedly placing the earliest-positioned
//! layer whose parent is already placed. Declared layers occupy positions
//! `0..D`; injected `--layer` directories occupy `D..D+I` in command-line
//! order. The spec explicitly orders injected ties by command-line position
//! but leaves a declared-vs-injected tie unstated; putting injected layers
//! last matches today's chain (project steps before `--layer` steps) and the
//! master CP1 row. That is an interpretation, not a quoted spec rule — the
//! O(n²) test oracle encodes the same interpretation and so cannot disprove a
//! misreading of it.
//!
//! Injected layers are roots and can never be named as a parent: a
//! [`ParentRef`] only names a declared [`LayerName`], so a user who wants to
//! parent onto an injected source must declare it in config. The
//! missing-parent error says exactly that.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    fmt,
};

use anyhow::{Context, Result};

/// The composition's layer names are config's validated tool names — one
/// grammar, one validator, no divergent `LayerName::parse`.
pub(crate) use crate::config::ToolName as LayerName;

/// A `--layer DIR` label exactly as typed. It is display metadata, never a
/// parent name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InjectedLabel(String);

impl InjectedLabel {
    pub(crate) fn new(as_typed: &str) -> Self {
        Self(as_typed.to_string())
    }
}

/// What a declared layer builds `FROM`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParentRef {
    Root,
    Layer(LayerName),
}

/// A participating layer's identity within the graph, before any payload is
/// attached. Injected layers carry no name a `parent` could reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LayerKey {
    Declared(LayerName),
    Injected(InjectedLabel),
}

impl fmt::Display for LayerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declared(name) => f.write_str(name.as_str()),
            Self::Injected(label) => write!(f, "--layer {}", label.0),
        }
    }
}

/// One declared catalog layer. Named `CatalogNode` rather than reusing config's
/// `DeclaredLayer`, which carries anchoring and source data this graph must
/// not know about.
pub(crate) struct CatalogNode<T> {
    pub(crate) name: LayerName,
    pub(crate) parent: ParentRef,
    pub(crate) payload: T,
}

/// One injected `--layer` source. No `parent` field: an injected layer is
/// always a root.
pub(crate) struct InjectedLayer<T> {
    pub(crate) label: InjectedLabel,
    pub(crate) payload: T,
}

/// A node's position in derived stitch order, `0..len`. Distinct from a
/// vector offset only in intent: callers treat it as opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct StitchIndex(usize);

impl StitchIndex {
    pub(crate) fn get(self) -> usize {
        self.0
    }
}

/// One placed layer. The owned iterator yields these in stitch order, with
/// `index` equal to the node's own stitch position and `parent` naming the
/// parent's already-placed stitch index.
pub(crate) struct OwnedPlacedLayer<T> {
    pub(crate) index: StitchIndex,
    pub(crate) key: LayerKey,
    pub(crate) parent: Option<StitchIndex>,
    pub(crate) payload: T,
}

struct Node<T> {
    key: LayerKey,
    parent: Option<StitchIndex>,
    payload: T,
}

/// The derived Layer DAG, stored in stitch order.
pub(crate) struct LayerGraph<T> {
    nodes: Vec<Node<T>>,
}

impl<T> LayerGraph<T> {
    /// Validates names and parents, then derives stitch order. Duplicate names
    /// are rejected first, then all missing parents together, then cycles —
    /// each error is the most specific one available.
    pub(crate) fn derive(
        declared: Vec<CatalogNode<T>>,
        injected: Vec<InjectedLayer<T>>,
    ) -> Result<Self> {
        let declared_count = declared.len();
        let injected_count = injected.len();
        let total = declared_count + injected_count;

        // Declared names only: injected labels never enter this lookup, even
        // when their text equals a declared name.
        let mut declared_at: HashMap<LayerName, usize> = HashMap::with_capacity(declared_count);
        for (position, node) in declared.iter().enumerate() {
            if declared_at.insert(node.name.clone(), position).is_some() {
                return Err(GraphError::DuplicateName {
                    name: node.name.clone(),
                }
                .into());
            }
        }

        // Resolve parents; collect every missing one in declaration order
        // before failing.
        let mut parents: Vec<Option<usize>> = Vec::with_capacity(total);
        let mut missing: Vec<MissingParent> = Vec::new();
        for node in &declared {
            let parent = match &node.parent {
                ParentRef::Root => None,
                ParentRef::Layer(parent) => declared_at.get(parent).copied(),
            };
            if let (ParentRef::Layer(parent), None) = (&node.parent, parent) {
                missing.push(MissingParent {
                    layer: node.name.clone(),
                    parent: parent.clone(),
                });
            }
            parents.push(parent);
        }
        if !missing.is_empty() {
            return Err(GraphError::MissingParents {
                missing,
                declared: declared.iter().map(|node| node.name.clone()).collect(),
            }
            .into());
        }
        parents.resize(total, None); // injected layers are roots

        // Min-ready Kahn order: each node has one parent, so "all ancestors
        // placed" reduces to "parent placed or root", and a child is
        // readied exactly once (when its parent is placed). A min-heap
        // yields the earliest-positioned ready node.
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); total];
        let mut ready: BinaryHeap<Reverse<usize>> = BinaryHeap::new();
        for (position, parent) in parents.iter().enumerate() {
            match parent {
                None => ready.push(Reverse(position)),
                Some(parent) => children[*parent].push(position),
            }
        }
        let mut order: Vec<usize> = Vec::with_capacity(total);
        while let Some(Reverse(position)) = ready.pop() {
            order.push(position);
            for &child in &children[position] {
                ready.push(Reverse(child));
            }
        }

        // Anything unplaced is on, or downstream of, a cycle.
        if order.len() < total {
            let declared_names: Vec<LayerName> =
                declared.iter().map(|node| node.name.clone()).collect();
            let cycles = extract_cycles(&parents, &order, &declared_names)?;
            return Err(GraphError::Cycles { cycles }.into());
        }

        // Move payloads into stitch order. The checked lookups below guard an
        // internal invariant, not a user graph error, so a failure carries
        // `anyhow` context instead of a `GraphError` variant.
        let mut staged: Vec<Option<(LayerKey, T)>> = Vec::with_capacity(total);
        for node in declared {
            staged.push(Some((LayerKey::Declared(node.name), node.payload)));
        }
        for layer in injected {
            staged.push(Some((LayerKey::Injected(layer.label), layer.payload)));
        }

        let mut position_to_index: Vec<Option<StitchIndex>> = vec![None; total];
        let mut nodes: Vec<Node<T>> = Vec::with_capacity(total);
        for &position in &order {
            let (key, payload) = staged
                .get_mut(position)
                .and_then(Option::take)
                .context("internal: a graph position was placed twice")?;
            let parent = match parents[position] {
                None => None,
                Some(parent_position) => Some(
                    *position_to_index
                        .get(parent_position)
                        .and_then(Option::as_ref)
                        .context("internal: a graph parent was placed after its child")?,
                ),
            };
            position_to_index[position] = Some(StitchIndex(nodes.len()));
            nodes.push(Node {
                key,
                parent,
                payload,
            });
        }

        Ok(Self { nodes })
    }

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    /// The placed layers in stitch order. The `index` on each equals its
    /// position here; `parent` names an earlier entry.
    pub(crate) fn into_stitch_order(self) -> impl ExactSizeIterator<Item = OwnedPlacedLayer<T>> {
        self.nodes
            .into_iter()
            .enumerate()
            .map(|(offset, node)| OwnedPlacedLayer {
                index: StitchIndex(offset),
                key: node.key,
                parent: node.parent,
                payload: node.payload,
            })
    }
}

/// One declared layer whose `parent` names no declared layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MissingParent {
    pub(crate) layer: LayerName,
    pub(crate) parent: LayerName,
}

/// A user-actionable graph error. `derive` returns these as the typed source
/// of an `anyhow` error so callers can downcast and act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GraphError {
    DuplicateName {
        name: LayerName,
    },
    MissingParents {
        missing: Vec<MissingParent>,
        declared: Vec<LayerName>,
    },
    Cycles {
        cycles: Vec<Vec<LayerName>>,
    },
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateName { name } => write!(
                f,
                "duplicate layer name {:?} in this composition; layer names must be unique",
                name.as_str()
            ),
            Self::MissingParents { missing, declared } => {
                for row in missing {
                    writeln!(
                        f,
                        "layer {:?} declares parent {:?}, which is not a layer in this composition.",
                        row.layer.as_str(),
                        row.parent.as_str()
                    )?;
                }
                writeln!(
                    f,
                    "  Declared layers: {}",
                    declared
                        .iter()
                        .map(|name| name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
                write!(
                    f,
                    "  (a --layer directory has no name and cannot be a parent; declare it in config to use it as one)"
                )
            }
            Self::Cycles { cycles } => {
                let rows: Vec<String> = cycles
                    .iter()
                    .map(|cycle| {
                        let names: Vec<&str> = cycle.iter().map(|name| name.as_str()).collect();
                        format!("{} -> {}", names.join(" -> "), names[0])
                    })
                    .collect();
                match rows.as_slice() {
                    [single] => write!(
                        f,
                        "layers form a parent cycle: {single}\n  change or remove one of these `parent` declarations"
                    ),
                    many => {
                        writeln!(f, "layers form parent cycles:")?;
                        for row in many {
                            writeln!(f, "  {row}")?;
                        }
                        write!(f, "  change or remove one of these `parent` declarations")
                    }
                }
            }
        }
    }
}

impl std::error::Error for GraphError {}

/// The distinct cycles among the unplaced nodes, each rotated to its
/// earliest-declared member and ordered by that member. A stuck node's parent
/// is stuck too (a placed parent would have readied it), so following parent
/// pointers from stuck nodes walks only unplaced nodes and terminates in a
/// cycle; finishing a walk marks a node so a cycle reachable from two tails is
/// reported once and its downstream tails are never named.
fn extract_cycles(
    parents: &[Option<usize>],
    order: &[usize],
    declared_names: &[LayerName],
) -> Result<Vec<Vec<LayerName>>> {
    let total = parents.len();
    let mut placed = vec![false; total];
    for &position in order {
        placed[position] = true;
    }
    let mut finished = vec![false; total];
    let mut cycles: Vec<(usize, Vec<LayerName>)> = Vec::new();

    for start in 0..total {
        if placed[start] || finished[start] {
            continue;
        }
        let mut step_of: HashMap<usize, usize> = HashMap::new();
        let mut path: Vec<usize> = Vec::new();
        let mut current = Some(start);
        while let Some(position) = current {
            if placed[position] || finished[position] {
                break;
            }
            if let Some(&step) = step_of.get(&position) {
                let mut cycle: Vec<usize> = path[step..].to_vec();
                let earliest = *cycle.iter().min().expect("a cycle has members");
                let offset = cycle
                    .iter()
                    .position(|&member| member == earliest)
                    .expect("the earliest member is in the cycle");
                cycle.rotate_left(offset);
                let names = cycle
                    .iter()
                    .map(|&member| {
                        declared_names.get(member).cloned().with_context(|| {
                            format!("internal: cycle position {member} is not a declared layer")
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                cycles.push((earliest, names));
                break;
            }
            step_of.insert(position, path.len());
            path.push(position);
            current = parents[position];
        }
        for &position in &path {
            finished[position] = true;
        }
    }

    cycles.sort_by_key(|(earliest, _)| *earliest);
    Ok(cycles.into_iter().map(|(_, names)| names).collect())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::composition::test_support::layer_name;

    fn declared(rows: &[(&str, Option<&str>)]) -> Vec<CatalogNode<()>> {
        rows.iter()
            .map(|(name, parent)| CatalogNode {
                name: layer_name(name),
                parent: match parent {
                    Some(parent) => ParentRef::Layer(layer_name(parent)),
                    None => ParentRef::Root,
                },
                payload: (),
            })
            .collect()
    }

    fn injected(labels: &[&str]) -> Vec<InjectedLayer<()>> {
        labels
            .iter()
            .map(|label| InjectedLayer {
                label: InjectedLabel::new(label),
                payload: (),
            })
            .collect()
    }

    fn graph(rows: &[(&str, Option<&str>)], labels: &[&str]) -> LayerGraph<()> {
        LayerGraph::derive(declared(rows), injected(labels)).expect("graph derives")
    }

    /// `(key, parent stitch index)` in stitch order.
    fn placed(graph: LayerGraph<()>) -> Vec<(String, Option<usize>)> {
        graph
            .into_stitch_order()
            .map(|node| (node.key.to_string(), node.parent.map(StitchIndex::get)))
            .collect()
    }

    fn keys(graph: LayerGraph<()>) -> Vec<String> {
        placed(graph).into_iter().map(|(key, _)| key).collect()
    }

    fn graph_error(rows: &[(&str, Option<&str>)], labels: &[&str]) -> GraphError {
        LayerGraph::derive(declared(rows), injected(labels))
            .err()
            .expect("graph must fail")
            .downcast::<GraphError>()
            .expect("typed graph error")
    }

    // --- G1–G7: derived order ---

    #[test]
    fn worked_example_order() {
        let graph = graph(
            &[
                ("claude-plugin", Some("claude")),
                ("codex", None),
                ("claude", None),
                ("claude-skin", Some("claude-plugin")),
            ],
            &["./chrome", "./extra"],
        );
        assert_eq!(
            keys(graph),
            vec![
                "codex",
                "claude",
                "claude-plugin",
                "claude-skin",
                "--layer ./chrome",
                "--layer ./extra",
            ]
        );
    }

    #[test]
    fn child_declared_before_parent_is_placed_after_it() {
        assert_eq!(
            keys(graph(&[("b", Some("a")), ("a", None)], &[])),
            vec!["a", "b"]
        );
    }

    #[test]
    fn declaration_order_breaks_ready_ties() {
        // Roots keep declaration order, not name order.
        assert_eq!(
            keys(graph(&[("z", None), ("a", None), ("m", None)], &[])),
            vec!["z", "a", "m"]
        );
        // Siblings keep declaration order under a shared parent.
        assert_eq!(
            keys(graph(
                &[("p", None), ("c2", Some("p")), ("c1", Some("p"))],
                &[]
            )),
            vec!["p", "c2", "c1"]
        );
    }

    #[test]
    fn earliest_ready_beats_depth_first() {
        assert_eq!(
            keys(graph(&[("a", None), ("c", None), ("b", Some("a"))], &[])),
            vec!["a", "c", "b"]
        );
    }

    #[test]
    fn already_ordered_declarations_keep_declaration_order() {
        assert_eq!(
            keys(graph(
                &[("a", None), ("b", Some("a")), ("c", Some("b")), ("d", None)],
                &[]
            )),
            vec!["a", "b", "c", "d"]
        );
    }

    #[test]
    fn injected_layers_follow_declared_in_cli_order() {
        let graph = graph(&[("zeta", None), ("alpha", None)], &["mmm", "aaa", "zzz"]);
        assert_eq!(
            keys(graph),
            vec!["zeta", "alpha", "--layer mmm", "--layer aaa", "--layer zzz"]
        );
    }

    #[test]
    fn empty_and_injected_only_graphs() {
        let empty = graph(&[], &[]);
        assert_eq!(empty.len(), 0);
        assert!(placed(empty).is_empty());

        let only = graph(&[], &["one", "two", "three"]);
        assert_eq!(only.len(), 3);
        assert_eq!(
            placed(only),
            vec![
                ("--layer one".to_string(), None),
                ("--layer two".to_string(), None),
                ("--layer three".to_string(), None),
            ]
        );
    }

    // --- G8–G16: errors, in precedence order ---

    #[test]
    fn missing_parent_is_an_error_naming_layer_and_parent() {
        let error = graph_error(
            &[
                ("claude", None),
                ("claude-plugin", Some("claud")),
                ("codex", None),
            ],
            &[],
        );
        assert_eq!(
            error,
            GraphError::MissingParents {
                missing: vec![MissingParent {
                    layer: layer_name("claude-plugin"),
                    parent: layer_name("claud"),
                }],
                declared: vec![
                    layer_name("claude"),
                    layer_name("claude-plugin"),
                    layer_name("codex"),
                ],
            }
        );
        assert_eq!(
            error.to_string(),
            "layer \"claude-plugin\" declares parent \"claud\", which is not a layer in this composition.\n  Declared layers: claude, claude-plugin, codex\n  (a --layer directory has no name and cannot be a parent; declare it in config to use it as one)"
        );
    }

    #[test]
    fn all_missing_parents_are_reported_together() {
        let error = graph_error(
            &[
                ("x", Some("nope")),
                ("y", Some("z")),
                ("z", Some("also-nope")),
            ],
            &[],
        );
        match error {
            GraphError::MissingParents { missing, declared } => {
                assert_eq!(
                    missing,
                    vec![
                        MissingParent {
                            layer: layer_name("x"),
                            parent: layer_name("nope"),
                        },
                        MissingParent {
                            layer: layer_name("z"),
                            parent: layer_name("also-nope"),
                        },
                    ]
                );
                assert_eq!(
                    declared,
                    vec![layer_name("x"), layer_name("y"), layer_name("z")]
                );
            }
            other => panic!("expected MissingParents, got {other:?}"),
        }
    }

    #[test]
    fn a_parent_matching_only_an_injected_label_is_a_missing_parent() {
        // The parent text "inj" matches only the injected `--layer inj`
        // label. Injected layers are never parent targets, so this must be the
        // same missing-parent error as any other unresolvable name.
        let error = graph_error(&[("child", Some("inj"))], &["inj"]);
        assert_eq!(
            error,
            GraphError::MissingParents {
                missing: vec![MissingParent {
                    layer: layer_name("child"),
                    parent: layer_name("inj"),
                }],
                declared: vec![layer_name("child")],
            },
            "the injected label must not resolve as a parent"
        );
    }

    #[test]
    fn missing_parents_are_reported_before_cycles() {
        let error = graph_error(
            &[("a", Some("b")), ("b", Some("a")), ("c", Some("ghost"))],
            &[],
        );
        assert!(
            matches!(error, GraphError::MissingParents { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn self_parent_is_a_one_layer_cycle() {
        let error = graph_error(&[("a", Some("a"))], &[]);
        assert_eq!(
            error,
            GraphError::Cycles {
                cycles: vec![vec![layer_name("a")]],
            }
        );
        assert_eq!(
            error.to_string(),
            "layers form a parent cycle: a -> a\n  change or remove one of these `parent` declarations"
        );
    }

    #[test]
    fn cycle_error_names_the_cycle_in_parent_order() {
        // d -> a -> b -> c -> a: the walk starts at d, a tail of the cycle.
        let error = graph_error(
            &[
                ("d", Some("a")),
                ("a", Some("b")),
                ("b", Some("c")),
                ("c", Some("a")),
            ],
            &[],
        );
        assert_eq!(
            error,
            GraphError::Cycles {
                cycles: vec![vec![layer_name("a"), layer_name("b"), layer_name("c")]],
            }
        );
        assert_eq!(
            error.to_string(),
            "layers form a parent cycle: a -> b -> c -> a\n  change or remove one of these `parent` declarations",
            "the downstream tail `d` must not be named as a cycle member"
        );
    }

    #[test]
    fn two_disjoint_cycles_are_both_named() {
        let error = graph_error(
            &[
                ("a", Some("b")),
                ("b", Some("a")),
                ("c", Some("d")),
                ("d", Some("c")),
            ],
            &[],
        );
        assert_eq!(
            error,
            GraphError::Cycles {
                cycles: vec![
                    vec![layer_name("a"), layer_name("b")],
                    vec![layer_name("c"), layer_name("d")],
                ],
            }
        );
    }

    #[test]
    fn duplicate_declared_name_is_an_error() {
        let error = graph_error(&[("claude", None), ("claude", None)], &[]);
        assert_eq!(
            error,
            GraphError::DuplicateName {
                name: layer_name("claude"),
            }
        );
        assert_eq!(
            error.to_string(),
            "duplicate layer name \"claude\" in this composition; layer names must be unique"
        );
    }

    #[test]
    fn duplicate_names_are_reported_before_missing_parents() {
        let error = graph_error(&[("x", Some("ghost")), ("x", None)], &[]);
        assert!(
            matches!(error, GraphError::DuplicateName { .. }),
            "got {error:?}"
        );
    }

    // --- P4–P5: the derivation, against an independent definition ---

    /// The O(n²) definition of stitch order: repeatedly place the earliest
    /// interpreted position whose parent (if any) is already placed. It
    /// encodes the same mixed-origin interpretation production uses.
    fn naive_order(parents: &[Option<usize>]) -> Vec<usize> {
        let total = parents.len();
        let mut is_placed = vec![false; total];
        let mut order = Vec::with_capacity(total);
        while order.len() < total {
            let next = (0..total).find(|&position| {
                !is_placed[position] && parents[position].is_none_or(|parent| is_placed[parent])
            });
            match next {
                Some(position) => {
                    is_placed[position] = true;
                    order.push(position);
                }
                None => break,
            }
        }
        order
    }

    #[derive(Debug, Clone)]
    struct AcyclicCase {
        names: Vec<String>,
        /// Parent as a declaration-order index, or root.
        parents: Vec<Option<usize>>,
        injected: Vec<String>,
    }

    fn declared_nodes(names: &[String], parents: &[Option<usize>]) -> Vec<CatalogNode<()>> {
        names
            .iter()
            .enumerate()
            .map(|(index, name)| CatalogNode {
                name: layer_name(name),
                parent: match parents[index] {
                    Some(parent) => ParentRef::Layer(layer_name(&names[parent])),
                    None => ParentRef::Root,
                },
                payload: (),
            })
            .collect()
    }

    fn acyclic_case() -> impl Strategy<Value = AcyclicCase> {
        (1usize..=12)
            .prop_flat_map(|count| {
                (
                    Just(count),
                    prop::collection::vec(prop::option::of(0usize..count), count),
                    prop::collection::vec(any::<u32>(), count),
                    0usize..=3,
                )
            })
            .prop_map(|(count, raw_parents, sort_keys, injected_count)| {
                // Build the graph in topological order first (node i's parent
                // is earlier or absent), then shuffle declaration order so
                // declaration position is independent of the graph shape.
                let topo_names: Vec<String> = (0..count).map(|index| format!("n{index}")).collect();
                let topo_parents: Vec<Option<usize>> = (0..count)
                    .map(|index| {
                        if index == 0 {
                            None
                        } else {
                            raw_parents[index].map(|parent| parent.min(index - 1))
                        }
                    })
                    .collect();

                let mut order: Vec<usize> = (0..count).collect();
                order.sort_by_key(|&topo| (sort_keys[topo], topo));

                let mut topo_to_declared = vec![0usize; count];
                for (declared_position, &topo) in order.iter().enumerate() {
                    topo_to_declared[topo] = declared_position;
                }

                let mut names = Vec::with_capacity(count);
                let mut parents = Vec::with_capacity(count);
                for &topo in &order {
                    names.push(topo_names[topo].clone());
                    parents.push(topo_parents[topo].map(|parent| topo_to_declared[parent]));
                }

                AcyclicCase {
                    names,
                    parents,
                    injected: (0..injected_count)
                        .map(|index| format!("inj{index}"))
                        .collect(),
                }
            })
    }

    fn check_case(case: &AcyclicCase) {
        // Payloads are the node labels so the oracle also proves each
        // payload travels with its own key through the reorder — the seam
        // the planner consumes.
        let declared: Vec<CatalogNode<String>> = case
            .names
            .iter()
            .enumerate()
            .map(|(index, name)| CatalogNode {
                name: layer_name(name),
                parent: match case.parents[index] {
                    Some(parent) => ParentRef::Layer(layer_name(&case.names[parent])),
                    None => ParentRef::Root,
                },
                payload: name.clone(),
            })
            .collect();
        let injected: Vec<InjectedLayer<String>> = case
            .injected
            .iter()
            .map(|label| InjectedLayer {
                label: InjectedLabel::new(label),
                payload: label.clone(),
            })
            .collect();

        let graph = LayerGraph::derive(declared, injected).expect("acyclic case derives");
        let got: Vec<(usize, String, Option<usize>, String)> = graph
            .into_stitch_order()
            .map(|node| {
                (
                    node.index.get(),
                    node.key.to_string(),
                    node.parent.map(StitchIndex::get),
                    node.payload,
                )
            })
            .collect();

        let mut parents = case.parents.clone();
        parents.extend(std::iter::repeat_n(None, case.injected.len()));
        let order = naive_order(&parents);
        assert_eq!(order.len(), parents.len(), "oracle placed every node");

        let mut index_of_position = vec![0usize; parents.len()];
        for (index, &position) in order.iter().enumerate() {
            index_of_position[position] = index;
        }

        let label_of = |position: usize| -> String {
            if position < case.names.len() {
                case.names[position].clone()
            } else {
                format!("--layer {}", case.injected[position - case.names.len()])
            }
        };
        let payload_of = |position: usize| -> String {
            if position < case.names.len() {
                case.names[position].clone()
            } else {
                case.injected[position - case.names.len()].clone()
            }
        };
        let want: Vec<(usize, String, Option<usize>, String)> = order
            .iter()
            .enumerate()
            .map(|(index, &position)| {
                (
                    index,
                    label_of(position),
                    parents[position].map(|parent| index_of_position[parent]),
                    payload_of(position),
                )
            })
            .collect();
        assert_eq!(got, want);

        for (index, (_, _, parent, _)) in got.iter().enumerate() {
            if let Some(parent) = parent {
                assert!(*parent < index, "a parent must be placed before its child");
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn stitch_order_matches_the_naive_definition(case in acyclic_case()) {
            check_case(&case);
        }
    }

    #[test]
    fn a_root_and_an_injected_layer_carry_key_and_payload_together() {
        // The minimized case an early proptest *oracle* bug recorded: one root
        // plus one injection. The injected node's key is prefixed
        // ("--layer inj0") while its payload is the bare label; both must
        // travel with the node through the reorder. This is a regression
        // example for P4, not a production defect.
        check_case(&AcyclicCase {
            names: vec!["n0".to_string()],
            parents: vec![None],
            injected: vec!["inj0".to_string()],
        });
    }

    fn arbitrary_parents() -> impl Strategy<Value = Vec<Option<usize>>> {
        // Every rule: root, another node, or the node itself.
        (1usize..=12)
            .prop_flat_map(|count| prop::collection::vec(prop::option::of(0usize..count), count))
    }

    /// Nodes whose parent chain reaches the root, by fixpoint. A node with no
    /// root-reachable parent never resolves.
    fn resolved_mask(parents: &[Option<usize>]) -> Vec<bool> {
        let mut resolved = vec![false; parents.len()];
        loop {
            let mut changed = false;
            for (index, parent) in parents.iter().enumerate() {
                let now = match parent {
                    None => true,
                    Some(parent) => resolved[*parent],
                };
                if now && !resolved[index] {
                    resolved[index] = true;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        resolved
    }

    /// The true cycles among unresolved nodes, each rotated to its earliest
    /// member and ordered by that member.
    fn true_cycles(parents: &[Option<usize>]) -> Vec<Vec<usize>> {
        let mut resolved = vec![false; parents.len()];
        resolved.copy_from_slice(&resolved_mask(parents));
        let mut cycles: Vec<Vec<usize>> = Vec::new();
        for (start, &is_resolved) in resolved.iter().enumerate() {
            if is_resolved {
                continue;
            }
            let mut step_of: HashMap<usize, usize> = HashMap::new();
            let mut path: Vec<usize> = Vec::new();
            let mut current = start;
            loop {
                if let Some(&step) = step_of.get(&current) {
                    let mut cycle = path[step..].to_vec();
                    let earliest = *cycle.iter().min().expect("cycle has members");
                    let offset = cycle
                        .iter()
                        .position(|&member| member == earliest)
                        .expect("earliest member is in the cycle");
                    cycle.rotate_left(offset);
                    if !cycles.contains(&cycle) {
                        cycles.push(cycle);
                    }
                    break;
                }
                step_of.insert(current, path.len());
                path.push(current);
                match parents[current] {
                    Some(parent) => current = parent,
                    None => break, // an unresolved node always has a parent
                }
            }
        }
        cycles.sort();
        cycles
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn cyclic_graphs_always_error_with_real_cycles(parents in arbitrary_parents()) {
            let names: Vec<String> = (0..parents.len()).map(|index| format!("n{index}")).collect();
            let resolved = resolved_mask(&parents);

            let first = LayerGraph::derive(declared_nodes(&names, &parents), Vec::new());
            let second = LayerGraph::derive(declared_nodes(&names, &parents), Vec::new());

            match (first, second) {
                (Ok(first), Ok(second)) => {
                    prop_assert!(
                        resolved.iter().all(|&node| node),
                        "derive accepted a graph with an unreachable parent chain"
                    );
                    let order = naive_order(&parents);
                    let got: Vec<String> =
                        first.into_stitch_order().map(|node| node.key.to_string()).collect();
                    let want: Vec<String> =
                        order.iter().map(|&position| names[position].clone()).collect();
                    prop_assert_eq!(&got, &want);
                    let again: Vec<String> =
                        second.into_stitch_order().map(|node| node.key.to_string()).collect();
                    prop_assert_eq!(&got, &again);
                }
                (Err(first), Err(second)) => {
                    prop_assert!(
                        !resolved.iter().all(|&node| node),
                        "derive rejected an acyclic graph"
                    );
                    let first = first.downcast::<GraphError>().expect("typed graph error");
                    let second = second.downcast::<GraphError>().expect("typed graph error");
                    prop_assert_eq!(&first, &second);
                    let cycles = match first {
                        GraphError::Cycles { cycles } => cycles,
                        other => {
                            return Err(TestCaseError::fail(format!(
                                "expected Cycles, got {other:?}"
                            )));
                        }
                    };
                    let expected: Vec<Vec<String>> = true_cycles(&parents)
                        .into_iter()
                        .map(|cycle| {
                            cycle
                                .into_iter()
                                .map(|position| names[position].clone())
                                .collect()
                        })
                        .collect();
                    let got: Vec<Vec<String>> = cycles
                        .into_iter()
                        .map(|cycle| {
                            cycle
                                .into_iter()
                                .map(|name| name.as_str().to_string())
                                .collect()
                        })
                        .collect();
                    prop_assert_eq!(got, expected);
                }
                _ => prop_assert!(false, "derive is nondeterministic"),
            }
        }
    }
}
