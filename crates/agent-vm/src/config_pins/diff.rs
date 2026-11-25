//! The review diff for a pending pinned source (#736).
//!
//! A `trust = false` source is shown before its exact bytes are approved, and
//! this transcript *is* what "shown" means: the only place raw config text
//! reaches a terminal, and the only evidence the approval question is about.
//! Three properties follow, and they are this module's contract.
//!
//! # Injective over bytes
//!
//! [`escape_review_line`] maps any byte sequence to printable ASCII and to
//! nothing else, so two different candidates can never render the same
//! transcript. Its rule:
//!
//! * `\` (0x5c) renders as `\\`, so an escape sequence is never ambiguous with
//!   text that happens to look like one;
//! * printable ASCII `0x20..=0x7e` (except `\`) renders as itself;
//! * every other ASCII byte (C0 controls `0x00..=0x1f`, DEL `0x7f`) renders as
//!   `\xNN`, two lowercase hex digits;
//! * every valid non-ASCII UTF-8 scalar renders as `\u{HEX}`, uppercase with at
//!   least four digits, so a combining mark, a default-ignorable character, a
//!   right-to-left override or a homoglyph cannot pass for a different line;
//! * every byte that is not part of a valid UTF-8 sequence renders as `\xNN`,
//!   which is why a valid C1 scalar (`\u{0080}`) and the raw byte `0x80`
//!   (`\x80`) stay distinguishable.
//!
//! Because the rendered alphabet contains no LF, no CR and no raw `\`, no
//! content line can forge a `+`, `-`, `---`, `+++` or `@@` line: each one is
//! emitted with its own prefix by this module and cannot extend past its own
//! line.
//!
//! The transcript is therefore a *review*, not a `patch(1)` file: it is the
//! escaped rendering of the bytes, deliberately not a byte-for-byte patch.
//!
//! # Exact LF semantics
//!
//! Lines are split on LF only, keeping the terminator on its line, and the
//! escaped line is the diff key with that terminator retained. A file with no
//! final newline therefore carries a key no terminated line can equal (and a
//! `\ No newline at end of file` marker in the transcript), so a candidate that
//! only differs in its final newline can never be reviewed as an identical
//! file. CR is never a line break: `\r\n` renders as a visible `\x0d` before
//! the line's end, and nothing is normalised, trimmed or re-wrapped.
//!
//! # Refusal, never truncation
//!
//! [`render_review`] builds the whole transcript in memory and returns
//! [`TooLarge`] instead of returning a prefix of it. A review that hit a cap is
//! therefore never printed at all, which is what lets the prompt refuse an
//! oversized review without ever showing a diff the user might read as
//! complete.
//!
//! `similar` computes the LCS of the escaped line keys; the escaping, the hunk
//! rendering, the caps and the refusal are ours, so the output contract is
//! enforced by this module rather than inherited from the dependency.

use std::fmt::Write as _;
use std::time::Duration;

use similar::{Algorithm, ChangeTag, DiffOp, TextDiff};

use super::store::DiffState;
use super::{ContentHash, PendingSource, PinKey, Unavailable};
use crate::config_sources::{Declaration, SourceAlias, SourceScope};

/// Context lines on each side of a change, so an edit is read in its place.
pub(crate) const CONTEXT_LINES: usize = 3;
/// Longest rendered line: the escaped content, without its prefix.
pub(crate) const MAX_LINE_CHARS: usize = 4_096;
/// Rendered diff lines one source may add to a transcript.
pub(crate) const MAX_RENDERED_LINES_PER_SOURCE: usize = 4_000;
/// `@@` regions one source may have. Kept below what the line cap alone would
/// allow, so it is a reachable bound of its own: with three lines of context on
/// each side a new region costs at least nine rendered lines.
pub(crate) const MAX_CHANGED_REGIONS_PER_SOURCE: usize = 256;
/// Rendered diff lines the whole review may add.
pub(crate) const MAX_RENDERED_LINES_BATCH: usize = 8_000;
/// Rendered bytes the whole review may add, including banners and headers.
pub(crate) const MAX_RENDERED_BYTES_BATCH: usize = 2 * 1024 * 1024;

/// Myers is quadratic in the worst case. A diff that reaches this deadline
/// degrades to describing the whole candidate as changed: a louder review,
/// never a shorter one, so the deadline can only over-show.
const DIFF_DEADLINE: Duration = Duration::from_secs(2);

/// What a pending source is diffed against.
///
/// The baseline is the key's recorded `active` hash in the manifest read under
/// the diff's `LOCK_SH` (B7). It is deliberately *not* the pre-lock inspection's
/// [`super::PendingReason`] and never a snapshot's mtime: a peer may approve and
/// activate another version between inspection and this read, and the review
/// must describe what is recorded now, not what was believed earlier.
pub(crate) enum Baseline<'a> {
    /// No manifest entry for the key: first use, diffed against empty.
    NeverApproved,
    /// The recorded active hash and its exact, verified snapshot text.
    Active { hash: ContentHash, text: &'a [u8] },
    /// The recorded active hash whose snapshot could not be produced. Review
    /// shows the whole candidate as new, the conservative direction; the reason
    /// is review evidence, never authorization.
    Unavailable {
        hash: ContentHash,
        reason: Unavailable,
    },
}

/// One pending source resolved against a locked [`DiffState`].
///
/// The metadata travels with the candidate so the transcript can say *which*
/// source is being approved — its declaration, alias, route scope and `allow`
/// value — without reopening a path and without trusting the pre-lock
/// inspection for anything the store decides.
pub(crate) struct PendingReview<'a> {
    pub(crate) key: &'a PinKey,
    pub(crate) alias: &'a SourceAlias,
    pub(crate) declared: Declaration,
    pub(crate) scope: SourceScope,
    pub(crate) allow: bool,
    pub(crate) candidate: &'a [u8],
    pub(crate) candidate_hash: ContentHash,
    pub(crate) baseline: Baseline<'a>,
}

impl<'a> PendingReview<'a> {
    /// Resolve one pending source's baseline from the locked state.
    pub(crate) fn of(source: &'a PendingSource, state: &'a DiffState) -> Self {
        let candidate_hash = ContentHash::of(&source.candidate);
        let baseline = match state.current.key_state(&source.key) {
            None => Baseline::NeverApproved,
            Some(key_state) => {
                let hash = key_state.active;
                match state.snapshots.get(&hash) {
                    Some(text) => Baseline::Active {
                        hash,
                        text: text.as_bytes(),
                    },
                    None => Baseline::Unavailable {
                        hash,
                        // `read_for_diff` records a reason for every digest it
                        // could not produce, so the fallback only covers a
                        // caller that assembled a `DiffState` by hand.
                        reason: state
                            .unavailable
                            .get(&hash)
                            .cloned()
                            .unwrap_or(Unavailable::Missing),
                    },
                }
            }
        };
        Self {
            key: &source.key,
            alias: &source.alias,
            declared: source.declared,
            scope: source.scope,
            allow: source.allow,
            candidate: &source.candidate,
            candidate_hash,
            baseline,
        }
    }

    /// The one line that says which source this is: declaration and alias, the
    /// route scope the read earned, and the `allow` value that decides what an
    /// approval adopts.
    ///
    /// Every value is validated (an alias is `[a-z][a-z0-9_-]{0,31}`, a
    /// declaration is `sources[<n>]` or one fixed phrase, the scope is one of
    /// two words, `allow` is a bool), so the line is fixed-format and cannot be
    /// forged or made ambiguous by anything a source contains.
    fn declared_line(&self) -> String {
        let scope = match self.scope {
            SourceScope::Checkout => "checkout",
            SourceScope::External => "external",
        };
        format!(
            "==> declared: {} {}, scope {scope}, allow = {}\n",
            self.declared, self.alias, self.allow
        )
    }

    /// The capability warning an `allow = true` approval needs: `allow` is what
    /// makes the source's top-level declarations authority for this launch, so
    /// the question must say that approving them adopts them.
    fn allow_warning(&self) -> Option<String> {
        self.allow.then(|| {
            "==> allow = true: approving also adopts this source's top-level `image`, `mounts`, \
             `network` and `allow_tools`\n"
                .to_owned()
        })
    }
}

/// Which cap an oversized review crossed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cap {
    LineChars,
    SourceLines,
    ChangedRegions,
    ReviewLines,
    ReviewBytes,
}

impl Cap {
    /// The clause a refusal prints, with the exact limit it names.
    pub(crate) fn clause(self) -> String {
        match self {
            Self::LineChars => {
                format!("a diff line is longer than {MAX_LINE_CHARS} characters")
            }
            Self::SourceLines => {
                format!("one source's diff is longer than {MAX_RENDERED_LINES_PER_SOURCE} lines")
            }
            Self::ChangedRegions => {
                format!("one source has more than {MAX_CHANGED_REGIONS_PER_SOURCE} changed regions")
            }
            Self::ReviewLines => {
                format!("the review is longer than {MAX_RENDERED_LINES_BATCH} diff lines")
            }
            Self::ReviewBytes => {
                format!("the review is larger than {MAX_RENDERED_BYTES_BATCH} bytes")
            }
        }
    }
}

/// A review that must not be shown in part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TooLarge {
    /// The source whose rendering crossed the cap; the first one to do so.
    pub(crate) key: PinKey,
    /// The exact candidate whose review crossed it, so the refusal names the
    /// version it could not show.
    pub(crate) candidate: ContentHash,
    pub(crate) cap: Cap,
}

impl<'a> Baseline<'a> {
    /// The banner's reason for the review.
    fn banner(&self) -> String {
        match self {
            Self::NeverApproved => "never approved".to_owned(),
            Self::Active { .. } => "changed since it was last approved".to_owned(),
            Self::Unavailable { hash, reason } => format!(
                "last approved {hash} is unavailable ({}) so every line is shown as new",
                escape_review_line(reason.reason().as_bytes())
            ),
        }
    }

    /// The `---` header's parenthetical.
    fn old_label(&self) -> String {
        match self {
            Self::NeverApproved => "never approved: empty".to_owned(),
            Self::Active { hash, .. } => format!("last approved {hash}"),
            Self::Unavailable { hash, reason } => format!(
                "last approved {hash} unavailable: {}; shown as empty",
                escape_review_line(reason.reason().as_bytes())
            ),
        }
    }
}

/// Render every pending review, or refuse as a whole.
///
/// All-or-nothing is the point: a caller that receives `Err` prints the refusal
/// instead, so no transcript ever contains a partial diff.
pub(crate) fn render_review(reviews: &[PendingReview<'_>]) -> Result<String, TooLarge> {
    let mut out = String::new();
    let mut budget = Budget::default();
    for review in reviews {
        render_source(review, &mut budget, &mut out)?;
    }
    Ok(out)
}

/// Render one source's banner, headers and hunks into `out`.
fn render_source(
    review: &PendingReview<'_>,
    budget: &mut Budget,
    out: &mut String,
) -> Result<(), TooLarge> {
    // The path is escaped here, once: a key may contain a backslash or any
    // non-ASCII scalar, and a header must not be forgeable from one either.
    let path = escape_review_line(review.key.as_str().as_bytes());
    let banner = format!("==> source {path}: {}\n", review.baseline.banner());
    let declared = review.declared_line();
    let allow_warning = review.allow_warning();
    let old_header = format!("--- {path}\t({})\n", review.baseline.old_label());
    let new_header = format!(
        "+++ {path}\t(current sha256:{})\n",
        review.candidate_hash.hex()
    );
    let mut head = vec![&banner, &declared];
    head.extend(allow_warning.as_ref());
    head.extend([&old_header, &new_header]);
    for text in head {
        budget.bytes += text.len();
        if budget.bytes > MAX_RENDERED_BYTES_BATCH {
            return Err(too_large(review, Cap::ReviewBytes));
        }
        out.push_str(text);
    }

    let base: Vec<&[u8]> = match &review.baseline {
        Baseline::Active { text, .. } => split_lf_lines(text),
        Baseline::NeverApproved | Baseline::Unavailable { .. } => Vec::new(),
    };
    let current = split_lf_lines(review.candidate);
    let old_keys: Vec<String> = base.into_iter().map(diff_key).collect();
    let new_keys: Vec<String> = current.into_iter().map(diff_key).collect();
    let old_refs: Vec<&str> = old_keys.iter().map(String::as_str).collect();
    let new_refs: Vec<&str> = new_keys.iter().map(String::as_str).collect();
    let diff = TextDiff::configure()
        .algorithm(Algorithm::Myers)
        .timeout(DIFF_DEADLINE)
        .diff_slices(&old_refs, &new_refs);

    let groups = diff.grouped_ops(CONTEXT_LINES);
    if groups.len() > MAX_CHANGED_REGIONS_PER_SOURCE {
        return Err(too_large(review, Cap::ChangedRegions));
    }
    let mut source_lines = 0_usize;
    for group in &groups {
        push_line(out, budget, &mut source_lines, &hunk_header(group))
            .map_err(|cap| too_large(review, cap))?;
        for op in group {
            for change in diff.iter_changes(op) {
                let key = change.value();
                let (content, terminated) = match key.strip_suffix('\n') {
                    Some(content) => (content, true),
                    None => (key, false),
                };
                // The rendered alphabet is ASCII, so bytes are characters here.
                if content.len() > MAX_LINE_CHARS {
                    return Err(too_large(review, Cap::LineChars));
                }
                let prefix = match change.tag() {
                    ChangeTag::Equal => ' ',
                    ChangeTag::Delete => '-',
                    ChangeTag::Insert => '+',
                };
                push_line(
                    out,
                    budget,
                    &mut source_lines,
                    &format!("{prefix}{content}\n"),
                )
                .map_err(|cap| too_large(review, cap))?;
                if !terminated {
                    push_line(out, budget, &mut source_lines, NO_NEWLINE_MARKER)
                        .map_err(|cap| too_large(review, cap))?;
                }
            }
        }
    }
    Ok(())
}

fn too_large(review: &PendingReview<'_>, cap: Cap) -> TooLarge {
    TooLarge {
        key: review.key.clone(),
        candidate: review.candidate_hash,
        cap,
    }
}

/// The marker a side's last line gets when it has no final newline.
const NO_NEWLINE_MARKER: &str = "\\ No newline at end of file\n";

/// What is left of the review's line and byte allowance.
#[derive(Default)]
struct Budget {
    lines: usize,
    bytes: usize,
}

fn push_line(
    out: &mut String,
    budget: &mut Budget,
    source_lines: &mut usize,
    text: &str,
) -> Result<(), Cap> {
    *source_lines += 1;
    if *source_lines > MAX_RENDERED_LINES_PER_SOURCE {
        return Err(Cap::SourceLines);
    }
    budget.lines += 1;
    if budget.lines > MAX_RENDERED_LINES_BATCH {
        return Err(Cap::ReviewLines);
    }
    budget.bytes += text.len();
    if budget.bytes > MAX_RENDERED_BYTES_BATCH {
        return Err(Cap::ReviewBytes);
    }
    out.push_str(text);
    Ok(())
}

/// `@@ -old_start,old_len +new_start,new_len @@`, patch(1)'s coordinates.
///
/// A one-line range drops the length and a zero-length range names the line
/// before it, so an insertion at the top reads `-0,0`.
fn hunk_header(group: &[DiffOp]) -> String {
    let first = group.first().expect("a group of diff ops is never empty");
    let last = group.last().expect("a group of diff ops is never empty");
    format!(
        "@@ -{} +{} @@\n",
        hunk_range(first.old_range(), last.old_range()),
        hunk_range(first.new_range(), last.new_range())
    )
}

fn hunk_range(first: std::ops::Range<usize>, last: std::ops::Range<usize>) -> String {
    let length = last.end.saturating_sub(first.start);
    match length {
        0 => format!("{},0", first.start),
        1 => format!("{}", first.start + 1),
        _ => format!("{},{}", first.start + 1, length),
    }
}

/// The diff key for one line: its escaped content, plus the line's own LF.
///
/// Keeping the terminator in the key is what makes a missing final newline a
/// difference: an escaped line never contains a raw LF, so `a` and `a\n` are
/// different keys and can never compare equal.
fn diff_key(line: &[u8]) -> String {
    match line.strip_suffix(b"\n") {
        Some(content) => {
            let mut key = escape_review_line(content);
            key.push('\n');
            key
        }
        None => escape_review_line(line),
    }
}

/// Split strictly on LF, keeping each terminator on its own line.
fn split_lf_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            lines.push(&bytes[start..=index]);
            start = index + 1;
        }
    }
    if start < bytes.len() {
        lines.push(&bytes[start..]);
    }
    lines
}

/// Render bytes as printable ASCII, injectively. See the module docs for the
/// rule and why each class needs its own form.
pub(crate) fn escape_review_line(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some((&first, tail)) = rest.split_first() {
        match first {
            b'\\' => {
                out.push_str("\\\\");
                rest = tail;
            }
            0x20..=0x7e => {
                out.push(first as char);
                rest = tail;
            }
            0x00..=0x1f | 0x7f => {
                let _ = write!(out, "\\x{first:02x}");
                rest = tail;
            }
            _ => match next_scalar(rest) {
                Some((scalar, width)) => {
                    let _ = write!(out, "\\u{{{:04X}}}", scalar as u32);
                    rest = &rest[width..];
                }
                None => {
                    let _ = write!(out, "\\x{first:02x}");
                    rest = tail;
                }
            },
        }
    }
    out
}

/// The scalar at the start of `bytes` and its UTF-8 width, or `None` when the
/// leading bytes are not one complete valid non-ASCII scalar.
fn next_scalar(bytes: &[u8]) -> Option<(char, usize)> {
    let width = match bytes.first()? {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let text = std::str::from_utf8(bytes.get(..width)?).ok()?;
    let mut chars = text.chars();
    let scalar = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    Some((scalar, width))
}

#[cfg(test)]
mod tests;
