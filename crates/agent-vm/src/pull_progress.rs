//! Render microsandbox `PullProgress` events as a per-layer multi-bar
//! display that mirrors `msb pull` exactly.
//!
//! Layout:
//!
//! ```text
//!    ⠙ Pulling      ghcr.io/... (5 layers)
//!      layer 1/5  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  12.0 MiB/12.0 MiB  ✓
//!      layer 2/5  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  48.3 MiB/48.3 MiB  materializing
//!      ...
//! ```
//!
//! One header spinner + one bar per layer. Each bar transitions through
//! three styles: magenta (downloading) → blue (materializing) → checkmark
//! (done). No ETA, no aggregate bar — same as `msb pull`.
//!
//! Kept in lockstep with `vendor/microsandbox/crates/cli/lib/ui.rs`
//! (`PullProgressDisplay`); if msb changes its template, mirror it here, with
//! one deliberate difference documented next.
//!
//! # A cache hit draws nothing (gregwebs/tiny-desk-splitter#185)
//!
//! A fully cached acquisition emits `Resolving`, `Resolved` and `Complete`, and
//! nothing else: the registry short-circuits on cached metadata
//! (`Registry::pull_scoped_inner`) and the SDK create path emits the same three
//! for a cache hit (`emit_cached_pull_progress`). None of the three carries
//! per-layer news — `Resolved` carries only the manifest's layer count — so
//! drawing them paints the whole layer list, every row still reading
//! "downloading 0 B/1 B", for a pull that never happens. That flash is the bug
//! in the ticket. The display therefore stays undrawn, spinner tick thread
//! included, until an event from the layer or stitch stages arrives; a cache hit
//! enters neither. A warm launch prints nothing at all, which is what "nothing to
//! download" should look like.
//!
//! `msb pull` reaches the same end its own way: it checks the cache before
//! starting a display and prints one "already cached" line instead. A launch
//! has no such line to print.
//!
//! What such an event does not prove: `LayerDownloadComplete` and
//! `LayerMaterializeComplete` are also emitted when the layer pipeline reuses
//! work the cache already holds — a layer whose EROFS is already valid
//! (`vendor/microsandbox/crates/image/lib/registry/client.rs`, "layer reused
//! existing EROFS image", both before and after the per-layer lock) and a blob
//! that is already local — a cached tarball, or a `.part` an earlier run
//! finished (`vendor/microsandbox/crates/image/lib/layer/download.rs:100-106`,
//! `:137-143`). A reveal means "the SDK reported layer or stitch work", not
//! "bytes moved".
//!
//! Nor does a reveal mean a refresh draws: a pull that misses the image-metadata
//! cache — `PullPolicy::Always`, which is what the native acquisition uses
//! (`image_acquire.rs`, `AcquireMode::ResolveCurrent`: `image refresh`, `setup`'s
//! pull step, `image set-default`), or metadata that is missing or incomplete —
//! resolves over the network and then enters the layer pipeline only if some
//! artifact is actually missing (`materialize_layer_stage`,
//! `client.rs:954-958`):
//!
//! - Every layer EROFS valid, fsmeta valid, VMDK valid, `force == false`: the
//!   stage returns before spawning a single layer task, so the pull emits only
//!   `Resolving`, `Resolved` and `Complete` and draws nothing. For an up-to-date
//!   image that is the correct result, not a fallback this display papered over.
//! - fsmeta missing: the layer tasks reuse the valid EROFSes and emit
//!   `LayerMaterializeComplete` per layer, and the stitch events follow while
//!   fsmeta and the VMDK are rebuilt (`client.rs:1272-1277`, `:1305-1351`). The
//!   display draws, with rows not yet reached still reading "downloading" — the
//!   "0 B/1 B" picture.
//! - Only the VMDK missing: it re-stitches that alone (`client.rs:961-969` →
//!   `cache/store.rs:443-462`, the latter under `vendor/microsandbox/crates/image/lib/`),
//!   which reports stitch work and no per-layer work.
//! - A layer missing: a real download, which is what the display is for.
//!
//! None of those is the launch this ticket is about — a launch whose cache is
//! warm never gets past the registry short-circuit above — so the rows are left
//! as they are: telling reuse apart from work would need a "this layer is already
//! cached" event that the SDK's event model does not have — the same gap that
//! leaves cached rows reading "0 B/1 B" until they are materialized, which is out
//! of scope here too.
//!
//! Purposefully not taken: spinning the "Resolving" header from the moment the
//! display is built, so a cold pull shows liveness during the manifest and token
//! round-trips. The cache hit and the cold pull send identical `Resolving`
//! events, and the determinism rule forbids guessing with a timer, so there is
//! no event that separates them; the display would have to paint for both. The
//! cold path is instead left blank until its first layer or stitch event; the
//! launch's own notices (the `==> Boot image` line, mounts, egress) precede
//! `create`, so that blank window follows whichever one is last. `agent-vm image
//! refresh` has no such notices and pays the silence.
//!
//! `Complete` also tears the display down rather than the channel close doing
//! it. The SDK holds the progress sender until `create` returns — i.e. through
//! the whole guest boot — so waiting for the close left a finished layer list
//! on screen for the rest of the launch.

use std::io::IsTerminal;
use std::time::Duration;

use console::style;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use microsandbox::sandbox::{PullProgress, PullProgressHandle};

const BRAILLE_TICKS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Drive the progress UI to completion. Returns when the channel closes.
///
/// `reference_label` is `Some(label)` when the acquisition's reference is
/// redacted (the default tier): the SDK's event reference is then never
/// rendered, and the fixed `label` is shown instead. `None` renders the event's
/// own reference, preserving explicit-source behavior.
pub async fn render(mut handle: PullProgressHandle, reference_label: Option<String>) {
    let mut display = PullProgressDisplay::new(reference_label);
    while let Some(event) = handle.recv().await {
        display.handle_event(event);
    }
    display.finish();
}

/// Await the spawned render task, logging any panic so a template typo
/// (or any other panic inside `render`) is visible rather than silently
/// eaten by `JoinHandle::await.ok()`. Cancellation is silent — callers
/// that abort the task on an error path are intentionally tearing it
/// down. Use this from every `agent-vm` command that spawns `render`.
pub async fn await_render(handle: tokio::task::JoinHandle<()>) {
    match handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => eprintln!("warn: progress render task failed: {e}"),
    }
}

/// The display's three states, in order. One value rather than a target, an
/// optional set of bars and a latch, which together allowed states that cannot
/// happen — bars without a target, a draw after the pull finished.
enum Stage {
    /// Nothing is drawn. The target is not `Clone`, so it is owned here and
    /// consumed by the first draw.
    Pending {
        target: ProgressDrawTarget,
        /// Run the header spinner. Only a TTY has a terminal worth repainting.
        ticking: bool,
    },
    /// Boxed because the bars are much larger than what the other variants hold,
    /// which `clippy::large_enum_variant` flags under `-D warnings`.
    Live(Box<Live>),
    /// `Complete` arrived: the pull is over, so a straggling event must not
    /// resurrect the display over the rest of the launch.
    Done,
}

struct PullProgressDisplay {
    stage: Stage,
    reference: String,
    /// The manifest's layer count, from `Resolved`. Held here rather than on
    /// [`Live`] because the rows it sizes are built by [`Self::reveal`].
    ///
    /// The SDK sends `Resolved` before any layer or stitch event, so it is set by
    /// the time a reveal happens; `None` is a fallback that turns an upstream
    /// surprise into a header with no rows, rather than into rows nobody named.
    layer_count: Option<usize>,
    /// When set, the fixed label to show instead of the event's reference.
    fixed_reference: Option<String>,
}

/// Everything that exists only once there is something to draw.
struct Live {
    mp: MultiProgress,
    header: ProgressBar,
    layer_bars: Vec<ProgressBar>,
    /// Per-layer "has already entered materialize style" flag. Parallel
    /// to `layer_bars`. Lets every materialize-phase event force the
    /// style transition if `LayerMaterializeStarted` was dropped by the
    /// bounded try_send channel (or skipped entirely on the cached-EROFS
    /// fast path where Complete arrives without a prior Started).
    materialize_styled: Vec<bool>,
    download_style: ProgressStyle,
    materialize_style: ProgressStyle,
    done_style: ProgressStyle,
}

impl PullProgressDisplay {
    fn new(fixed_reference: Option<String>) -> Self {
        let is_tty = std::io::stderr().is_terminal();
        let target = if is_tty {
            ProgressDrawTarget::stderr_with_hz(10)
        } else {
            ProgressDrawTarget::hidden()
        };
        Self::with_target(fixed_reference, target, is_tty)
    }

    fn with_target(
        fixed_reference: Option<String>,
        target: ProgressDrawTarget,
        ticking: bool,
    ) -> Self {
        Self {
            stage: Stage::Pending { target, ticking },
            reference: String::new(),
            layer_count: None,
            fixed_reference,
        }
    }

    fn handle_event(&mut self, event: PullProgress) {
        match event {
            // The three events a cache hit emits, and the only three it emits:
            // record what a later reveal needs and draw nothing
            // (gregwebs/tiny-desk-splitter#185).
            PullProgress::Resolving { reference } => self.set_reference(&reference),
            PullProgress::Resolved {
                reference,
                layer_count,
                ..
            } => {
                self.set_reference(&reference);
                self.layer_count = Some(layer_count);
            }
            PullProgress::Complete { .. } => self.clear(),
            work => {
                self.reveal();
                self.apply(work);
            }
        }
    }

    fn set_reference(&mut self, reference: &str) {
        if self.reference.is_empty() {
            self.reference = match &self.fixed_reference {
                Some(label) => label.clone(),
                None => reference.to_owned(),
            };
        }
    }

    /// Build the display the first time an event reports layer or stitch work.
    fn reveal(&mut self) {
        // Swapping first makes this a single case analysis: `Pending` builds the
        // bars and anything else is put back untouched, so a repeated call
        // cannot build a second `MultiProgress` or revive a finished display.
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::Pending { target, ticking } => {
                let live = self.live_for(target, ticking);
                self.stage = Stage::Live(Box::new(live));
            }
            other => self.stage = other,
        }
    }

    /// The bars for a display that has just been revealed.
    fn live_for(&self, target: ProgressDrawTarget, ticking: bool) -> Live {
        let mp = MultiProgress::with_draw_target(target);
        let header = mp.add(ProgressBar::new_spinner());
        header.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(BRAILLE_TICKS)
                .template("   {spinner} {msg}")
                .unwrap(),
        );
        header.set_message(Self::header_message(
            "Pulling",
            &self.reference,
            self.layer_count,
        ));
        if ticking {
            header.enable_steady_tick(Duration::from_millis(80));
        }

        let mut live = Live {
            mp,
            header,
            layer_bars: Vec::new(),
            materialize_styled: Vec::new(),
            download_style: ProgressStyle::default_bar()
                .template(
                    "     {prefix}  {bar:36.magenta/238}  {bytes}/{total_bytes}  {msg:.magenta}",
                )
                .unwrap()
                .progress_chars("━━╌"),
            materialize_style: ProgressStyle::default_bar()
                .template("     {prefix}  {bar:36.blue/238}  {bytes}/{total_bytes}  {msg:.blue}")
                .unwrap()
                .progress_chars("━━╌"),
            done_style: ProgressStyle::default_bar()
                .template("     {prefix}  {msg}")
                .unwrap(),
        };
        if let Some(layer_count) = self.layer_count {
            live.add_layer_bars(layer_count);
        }
        live
    }

    /// The header line: a fixed-width verb, the reference, and — when the count
    /// is known — the manifest's layer count. Every header verb uses this so the
    /// shape cannot drift between them.
    fn header_message(verb: &str, reference: &str, layer_count: Option<usize>) -> String {
        match layer_count {
            Some(count) => format!(
                "{verb:<12} {reference} ({count} layer{})",
                if count == 1 { "" } else { "s" }
            ),
            // Only reachable if a layer event beat `Resolved`, which the SDK does
            // not do. An ellipsis says the verb is still in progress and claims
            // nothing about a count.
            None => format!("{verb:<12} {reference}..."),
        }
    }

    /// Apply an event other than the three a cache hit emits.
    fn apply(&mut self, event: PullProgress) {
        let Stage::Live(live) = &mut self.stage else {
            return;
        };
        let reference = self.reference.as_str();
        match event {
            PullProgress::LayerDownloadProgress {
                layer_index,
                downloaded_bytes,
                total_bytes,
                ..
            } => {
                if let Some(pb) = live.layer_bars.get(layer_index) {
                    if let Some(total) = total_bytes {
                        pb.set_length(total);
                    }
                    pb.set_position(downloaded_bytes);
                }
            }
            PullProgress::LayerDownloadComplete {
                layer_index,
                downloaded_bytes,
                ..
            } => {
                if let Some(pb) = live.layer_bars.get(layer_index) {
                    pb.set_length(downloaded_bytes);
                    pb.set_position(downloaded_bytes);
                }
            }
            PullProgress::LayerDownloadVerifying { layer_index, .. } => {
                if let Some(pb) = live.layer_bars.get(layer_index) {
                    pb.set_message("verifying");
                }
            }
            PullProgress::LayerMaterializeStarted { layer_index, .. } => {
                live.ensure_materialize_style(layer_index);
            }
            PullProgress::LayerMaterializeProgress {
                layer_index,
                bytes_read,
                total_bytes,
            } => {
                live.ensure_materialize_style(layer_index);
                if let Some(pb) = live.layer_bars.get(layer_index) {
                    pb.set_length(total_bytes);
                    pb.set_position(bytes_read);
                }
            }
            PullProgress::LayerMaterializeWriting { layer_index } => {
                live.ensure_materialize_style(layer_index);
                if let Some(pb) = live.layer_bars.get(layer_index) {
                    pb.set_position(pb.length().unwrap_or(0));
                    pb.set_message("writing image");
                }
            }
            PullProgress::LayerMaterializeComplete { layer_index, .. } => {
                live.ensure_materialize_style(layer_index);
                if let Some(pb) = live.layer_bars.get(layer_index) {
                    pb.set_position(pb.length().unwrap_or(0));
                    pb.set_style(live.done_style.clone());
                    pb.set_message(format!("{}", style("✓").green().for_stderr()));
                    pb.tick();
                }
            }
            PullProgress::StitchMergingTrees { layer_count } => {
                live.header.set_message(Self::header_message(
                    "Merging",
                    reference,
                    Some(layer_count),
                ));
            }
            PullProgress::StitchWritingFsmeta => {
                live.header
                    .set_message(format!("{:<12} {}", "Writing fsmeta", reference));
            }
            PullProgress::StitchWritingVmdk => {
                live.header
                    .set_message(format!("{:<12} {}", "Writing vmdk", reference));
            }
            PullProgress::StitchComplete => {
                live.header
                    .set_message(format!("{:<12} {}", "Stitched", reference));
            }
            // Consumed by `handle_event`. Drawing any of them would paint a
            // cache hit, which is the bug in
            // gregwebs/tiny-desk-splitter#185. Matched rather than caught by a
            // wildcard so a new SDK variant is a compile error here, and left
            // empty rather than panicking so a reshuffle of `handle_event`
            // cannot take the render task down with it.
            PullProgress::Resolving { .. }
            | PullProgress::Resolved { .. }
            | PullProgress::Complete { .. } => {}
        }
    }

    /// Tear the display down. Idempotent, so both `Complete` and the channel
    /// close can call it.
    fn clear(&mut self) {
        if let Stage::Live(live) = std::mem::replace(&mut self.stage, Stage::Done) {
            live.header.disable_steady_tick();
            let _ = live.mp.clear();
        }
    }

    fn finish(mut self) {
        self.clear();
    }

    /// The bars, when the display is drawing. Tests assert on what reached the
    /// terminal, but this proves *that* nothing was built at all.
    #[cfg(test)]
    fn live(&self) -> Option<&Live> {
        match &self.stage {
            Stage::Live(live) => Some(live.as_ref()),
            Stage::Pending { .. } | Stage::Done => None,
        }
    }
}

impl Live {
    /// One row per layer of the manifest. The count comes from `Resolved`, so
    /// these are the layers this pull will fetch or reuse, not invented rows for
    /// a pull that is not going to happen.
    fn add_layer_bars(&mut self, layer_count: usize) {
        let width = layer_count.to_string().len();
        for index in 0..layer_count {
            let pb = self.mp.add(ProgressBar::new(1));
            pb.set_style(self.download_style.clone());
            pb.set_prefix(format!("layer {:>width$}/{layer_count}", index + 1));
            pb.set_message("downloading");
            self.layer_bars.push(pb);
            self.materialize_styled.push(false);
        }
    }

    /// Force the bar at `layer_index` into `materialize_style` if it
    /// hasn't already transitioned. Idempotent. Covers two skipped-event
    /// scenarios: (a) the bounded try_send progress channel dropped
    /// `LayerMaterializeStarted` under load; (b) the per-layer cached-
    /// EROFS fast path in `registry.rs` emits `Complete` with no prior
    /// `Started`. Without this, the bar would stay in download_style
    /// (magenta with the literal "downloading" tag) while materialize
    /// events update its bytes — visibly misleading.
    fn ensure_materialize_style(&mut self, layer_index: usize) {
        if self
            .materialize_styled
            .get(layer_index)
            .copied()
            .unwrap_or(true)
        {
            return;
        }
        let Some(pb) = self.layer_bars.get(layer_index) else {
            return;
        };
        pb.set_style(self.materialize_style.clone());
        pb.set_position(0);
        pb.set_length(1);
        pb.set_message("materializing");
        self.materialize_styled[layer_index] = true;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use indicatif::{ProgressDrawTarget, TermLike};

    use super::PullProgressDisplay;
    use microsandbox::sandbox::PullProgress;

    /// A terminal that keeps what it was told to draw, so "the user saw this"
    /// is a byte-level assertion rather than an inference from internal state.
    #[derive(Debug)]
    struct Captured {
        written: Arc<Mutex<String>>,
    }

    impl TermLike for Captured {
        fn width(&self) -> u16 {
            200
        }

        fn move_cursor_up(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }

        fn move_cursor_down(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }

        fn move_cursor_right(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }

        fn move_cursor_left(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }

        fn write_line(&self, text: &str) -> std::io::Result<()> {
            let mut written = self.written.lock().unwrap();
            written.push_str(text);
            written.push('\n');
            Ok(())
        }

        fn write_str(&self, text: &str) -> std::io::Result<()> {
            self.written.lock().unwrap().push_str(text);
            Ok(())
        }

        fn clear_line(&self) -> std::io::Result<()> {
            Ok(())
        }

        fn flush(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(
        fixed_reference: Option<&str>,
        ticking: bool,
    ) -> (PullProgressDisplay, Arc<Mutex<String>>) {
        let written = Arc::new(Mutex::new(String::new()));
        let target = ProgressDrawTarget::term_like_with_hz(
            Box::new(Captured {
                written: Arc::clone(&written),
            }),
            10,
        );
        let display =
            PullProgressDisplay::with_target(fixed_reference.map(str::to_owned), target, ticking);
        (display, written)
    }

    /// A display that does not tick. Every assertion about *what* is drawn uses
    /// this, so it cannot depend on timing.
    fn capture_display(fixed_reference: Option<&str>) -> (PullProgressDisplay, Arc<Mutex<String>>) {
        capture(fixed_reference, false)
    }

    /// A display that ticks like it does on a TTY, so the header spinner's own
    /// repaints are part of the evidence.
    fn capture_ticking_display(
        fixed_reference: Option<&str>,
    ) -> (PullProgressDisplay, Arc<Mutex<String>>) {
        capture(fixed_reference, true)
    }

    fn resolving(reference: &str) -> PullProgress {
        PullProgress::Resolving {
            reference: reference.into(),
        }
    }

    fn resolved(reference: &str, layer_count: usize) -> PullProgress {
        PullProgress::Resolved {
            reference: reference.into(),
            manifest_digest: "sha256:manifest".into(),
            layer_count,
            total_download_bytes: None,
        }
    }

    fn completed(reference: &str, layer_count: usize) -> PullProgress {
        PullProgress::Complete {
            reference: reference.into(),
            layer_count,
        }
    }

    fn download_progress(layer_index: usize, downloaded: u64, total: u64) -> PullProgress {
        PullProgress::LayerDownloadProgress {
            layer_index,
            digest: "sha256:layer".into(),
            downloaded_bytes: downloaded,
            total_bytes: Some(total),
        }
    }

    /// The whole of gregwebs/tiny-desk-splitter#185: a warm launch's three
    /// events must reach the terminal as nothing at all.
    #[test]
    fn a_cache_hit_draws_nothing() {
        let (mut display, written) = capture_display(None);
        display.handle_event(resolving("docker.io/library/agent-vm-standard:local"));
        display.handle_event(resolved("docker.io/library/agent-vm-standard:local", 52));
        display.handle_event(completed("docker.io/library/agent-vm-standard:local", 52));

        assert!(display.live().is_none(), "a cache hit has nothing to show");
        assert_eq!(
            written.lock().unwrap().as_str(),
            "",
            "a cache hit must not paint (not even a cleared frame)"
        );
    }

    /// The steady tick was the bulk of the flash: the ticker repaints the header
    /// on its own, whether or not an event arrives, so a cache hit must have no
    /// ticker to repaint with. Waits long enough for a ticker to have painted
    /// several frames — that wait only bounds how much time a hypothetical
    /// ticker gets, so it cannot make the assertion below flaky in the correct
    /// code, where nothing exists to paint.
    #[test]
    fn a_cache_hit_starts_no_ticker() {
        let (mut display, written) = capture_ticking_display(None);
        display.handle_event(resolving("docker.io/library/agent-vm-standard:local"));
        display.handle_event(resolved("docker.io/library/agent-vm-standard:local", 52));
        display.handle_event(completed("docker.io/library/agent-vm-standard:local", 52));

        // Three timer periods: the ticker ticks at 80 ms and the draw target
        // rate-limits at 10 Hz.
        std::thread::sleep(Duration::from_millis(250));

        assert_eq!(
            written.lock().unwrap().as_str(),
            "",
            "a cache hit must not run a spinner ticker"
        );
    }

    #[test]
    fn a_real_pull_draws_its_layers() {
        let (mut display, written) = capture_display(None);
        display.handle_event(resolving("example.test/img:tag"));
        display.handle_event(resolved("example.test/img:tag", 2));
        assert!(display.live().is_none(), "resolved alone is not work");
        display.handle_event(download_progress(0, 512, 1024));

        let live = display.live().expect("a download reveals the display");
        assert_eq!(live.layer_bars.len(), 2);
        assert_eq!(live.layer_bars[0].position(), 512);
        assert!(live.header.message().contains("Pulling"));
        let drawn = written.lock().unwrap().clone();
        assert!(drawn.contains("layer 1/2"), "drew: {drawn:?}");
        assert!(drawn.contains("example.test/img:tag"), "drew: {drawn:?}");
    }

    /// The reveal's condition is the classification of the event, not proof that
    /// bytes moved: `LayerMaterializeComplete` is layer work, so it must build the
    /// bars even with no `LayerMaterializeStarted` before it. This is a synthetic
    /// input — it pins what `handle_event`/`apply` do with that variant, not which
    /// SDK paths emit it or what else such a pull sends; the module doc covers
    /// that.
    #[test]
    fn a_reused_layer_still_reveals_the_display() {
        let (mut display, _written) = capture_display(None);
        display.handle_event(resolved("example.test/img:tag", 1));
        display.handle_event(PullProgress::LayerMaterializeComplete {
            layer_index: 0,
            diff_id: "sha256:layer".into(),
        });

        let live = display.live().expect("a materialized layer is layer work");
        assert_eq!(live.layer_bars.len(), 1);
    }

    /// `Complete` arrives at the end of the pull, but the SDK keeps the sender
    /// alive until `create` returns — the end of the guest boot. Tearing down at
    /// `Complete` is what keeps the finished list off the boot.
    #[test]
    fn complete_tears_the_display_down_and_late_events_cannot_resurrect_it() {
        let (mut display, written) = capture_display(None);
        display.handle_event(resolving("example.test/img:tag"));
        display.handle_event(resolved("example.test/img:tag", 2));
        display.handle_event(download_progress(0, 1024, 1024));
        display.handle_event(completed("example.test/img:tag", 2));
        assert!(display.live().is_none(), "Complete clears the bars");

        let before = written.lock().unwrap().len();
        display.handle_event(download_progress(1, 1024, 1024));
        assert!(display.live().is_none(), "a late event must not redraw");
        assert_eq!(written.lock().unwrap().len(), before);
    }

    #[test]
    fn a_redacted_label_replaces_the_event_reference() {
        let (mut display, written) = capture_display(Some("agent-vm boot image"));
        display.handle_event(resolving("ghcr.io/private/img:tag"));
        display.handle_event(resolved("ghcr.io/private/img:tag", 1));
        display.handle_event(download_progress(0, 1, 2));

        let drawn = written.lock().unwrap().clone();
        assert!(drawn.contains("agent-vm boot image"), "drew: {drawn:?}");
        assert!(
            !drawn.contains("ghcr.io"),
            "leaked the reference: {drawn:?}"
        );
    }

    /// Rows come from the manifest count, so a layer event that arrives without
    /// one must not invent rows for layers nobody named. `Resolved` is the second
    /// of the SDK's events, on a 1024-slot channel, so in practice it always
    /// arrives first; this pins the fallback, which is to draw no rows at all.
    #[test]
    fn a_layer_event_without_a_resolved_count_invents_no_rows() {
        let (mut display, _written) = capture_display(None);
        display.handle_event(download_progress(2, 1, 2));

        let live = display.live().expect("a download reveals the display");
        assert!(
            live.layer_bars.is_empty(),
            "drew {} unnamed rows",
            live.layer_bars.len()
        );
    }
}
