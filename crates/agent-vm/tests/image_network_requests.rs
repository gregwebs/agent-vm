//! Boot-free end-to-end rows for ADR-0060: the image request report, its display
//! store, and `doctor`'s image section (#505).
//!
//! The harness is `image_pin_approval`'s: a loopback OCI registry serves genuine
//! archive bytes, the runtime is the complete fake `msb` + `libkrunfw` pair, and
//! `create` is expected to fail. That failure is the point — report emission and
//! store persistence are therefore always asserted on a launch that never
//! booted.
//!
//! Two runtime oracles, stated rather than implied:
//!
//! - A1, A5 and A10 are causal: they swap in `fake_msb::install_launch_binary` (a
//!   shell script cannot satisfy the SDK's launch-contract selection), which
//!   writes one `MSB-LAUNCH` record per real runtime invocation to **stderr** —
//!   the stream the report is written to. Each launch asserts exactly one new
//!   record, its argv, and that the report precedes the record.
//! - Every other row uses the cheaper `LaunchSeam` script and the weaker oracle
//!   [`reached_pre_create`]: the `[debug] sandbox config JSON` line is present,
//!   which proves the launch reached the create **call**, not that the runtime was
//!   invoked. It is named for what it observes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

#[path = "support/fake_msb.rs"]
mod fake_msb;
#[path = "support/image_archive.rs"]
mod image_archive;
#[path = "support/oci_registry.rs"]
mod oci_registry;
mod support;

use fake_msb::{FakeMsb, Mode};
use image_archive::ArchiveSpec;
use oci_registry::{Image, Server};

const SCOPE: &str = "public or same-name grants (no lookup; DNS, private-answer and TLS client limits still \
                      apply)";
const GRANT_HINT: &str = "==>   to grant: --allow-egress HOST or tcp://HOST:PORT, or --allow-internet-egress; \
                          IP/CIDR, --allow-lan and --allow-host grants are not matched to names";

fn label(name: &str) -> String {
    format!("org.agent-vm.network-requests.{name}")
}

fn labels(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| (label(name), (*value).to_owned()))
        .collect()
}

struct Harness {
    root: tempfile::TempDir,
    _state: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
    state: PathBuf,
    runtime: FakeMsb,
}

impl Harness {
    fn new(mode: Mode) -> Self {
        let root = support::project_tempdir();
        let state = tempfile::Builder::new()
            .prefix("av505-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let project = root.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let bin = root.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let runtime = fake_msb::install_pair(&bin, mode);
        Self {
            root,
            home,
            project,
            state: state.path().to_owned(),
            _state: state,
            runtime,
        }
    }

    /// Swap the script for a real compiled runtime binary, so the SDK selects its
    /// modern launch contract and counts a real launch invocation.
    fn use_launch_runtime(&mut self) {
        let dir = self.runtime.path.parent().unwrap().to_path_buf();
        self.runtime = fake_msb::install_launch_binary(
            &dir,
            &dir.join("msb-invocations.log"),
            &dir.join("msb-environ.log"),
        );
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-vm"));
        command
            .env_clear()
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("AGENT_VM_STATE_DIR", &self.state)
            .env("MSB_PATH", &self.runtime.path)
            .env("AGENT_VM_SHARE_MSB_CACHE", "0")
            .env("AGENT_VM_DEBUG_CONFIG", "1")
            .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.path().join("bin").display()),
            );
        command
    }

    fn launch_with(&self, reference: &str, tool: &str, extra: &[&str]) -> Output {
        let mut command = self.command();
        // `--root` keeps the guest identity patch out of the picture: the fixture
        // rootfs carries a marker file and no `/etc/passwd`, so a non-root launch
        // fails while patching instead of reaching the runtime. Every row uses it,
        // so no comparison here is skewed by the mode.
        // Launch options precede the verb: anything after `shell` is the guest
        // command, so a grant placed there would never reach the plan.
        command.args(["--image", reference, "--root"]);
        command.args(extra);
        command.arg(tool);
        if tool == "shell" {
            command.args(["--", "true"]);
        }
        bounded(command)
    }

    /// `agent-vm --image REF shell -- true`, the shortest real launch shape.
    fn launch(&self, reference: &str) -> Output {
        self.launch_with(reference, "shell", &[])
    }

    fn launch_granted(&self, reference: &str, grants: &[&str]) -> Output {
        let mut extra: Vec<&str> = Vec::new();
        for grant in grants {
            extra.push("--allow-egress");
            extra.push(grant);
        }
        self.launch_with(reference, "shell", &extra)
    }

    /// The default tier: no `--image`, no env override, no configured image.
    fn launch_default(&self) -> Output {
        let mut command = self.command();
        command.args(["--root", "shell", "--", "true"]);
        bounded(command)
    }

    fn refresh(&self, reference: &str) -> Output {
        let mut command = self.command();
        command.args(["image", "refresh", "--image", reference, "--yes"]);
        bounded(command)
    }

    fn set_default(&self, reference: &str) -> Output {
        let mut command = self.command();
        command.args(["image", "set-default", "--image", reference, "--yes"]);
        bounded(command)
    }

    fn image(&self, spec: &ArchiveSpec) -> Image {
        Image::from_archive(&self.root.path().join(format!("{}.tar", spec.marker)), spec)
    }

    /// A labeled image with a distinct marker per fixture.
    fn labeled(&self, marker: &str, pairs: &[(&str, &str)]) -> Image {
        self.image(&ArchiveSpec {
            marker: marker.to_owned(),
            labels: labels(pairs),
            ..Default::default()
        })
    }

    fn cache(&self) -> PathBuf {
        self.state.join("msb-home/cache")
    }

    fn store_path(&self) -> PathBuf {
        self.state.join("image-network-requests.json")
    }

    fn store(&self) -> Option<serde_json::Value> {
        let bytes = fs::read(self.store_path()).ok()?;
        Some(serde_json::from_slice(&bytes).expect("the store is valid JSON"))
    }

    fn store_meta(&self) -> Option<(Vec<u8>, std::time::SystemTime)> {
        let bytes = fs::read(self.store_path()).ok()?;
        let modified = fs::metadata(self.store_path()).ok()?.modified().ok()?;
        Some((bytes, modified))
    }

    /// The recorded set of one group, or `None` when the entry has no recorded set
    /// for it. `"image"` is *every launch*; `"agent.NAME"` is an agent group.
    fn recorded(&self, group: &str) -> Option<Vec<String>> {
        let store = self.store()?;
        let baseline = store["references"][0]["baseline"].as_object()?;
        let set = baseline.get(group)?;
        Some(
            set.as_array()
                .expect("a recorded set is an array")
                .iter()
                .map(|value| value.as_str().expect("a recorded request").to_owned())
                .collect(),
        )
    }

    fn references(&self) -> Vec<String> {
        self.store()
            .map(|store| {
                store["references"]
                    .as_array()
                    .expect("references is an array")
                    .iter()
                    .map(|entry| entry["reference"].as_str().expect("a key").to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn invocations(&self) -> String {
        fs::read_to_string(&self.runtime.invocations).unwrap_or_default()
    }

    /// The SDK's real launch invocations, excluding the `--version` and
    /// `__launch-protocol` probes the preflight makes. The record is the SDK's
    /// own `machine` argv, one line per invocation.
    fn sdk_launch_count(&self) -> usize {
        self.invocations()
            .lines()
            .filter(|line| line.trim_start().starts_with("machine "))
            .count()
    }
}

fn bounded(mut command: Command) -> Output {
    let child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run the compiled CLI");
    let id = child.id();
    let (sender, receiver) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        sender
            .send(child.wait_with_output().expect("collect CLI"))
            .ok();
    });
    let output = receiver.recv_timeout(Duration::from_secs(60));
    if output.is_err() {
        unsafe {
            libc::kill(id as i32, libc::SIGKILL);
        }
    }
    waiter.join().expect("join CLI collector");
    output.expect("CLI exceeded 60 seconds")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The prefix every image report line starts with.
const IMAGE_PREFIX: &str = "==> Image network requests";
/// The first trailer line. The second is the tool report's own `GRANT_HINT`, so
/// only a hint immediately after this notice belongs to the image report.
const IMAGE_NOTICE_PREFIX: &str = "==>   image requests above";

/// Every image report block in stderr, with the byte offset just past its last
/// line.
///
/// A report is one contiguous block: prefixed group/ignored lines, then
/// optionally the notice and the grant hint. The scan **continues after a block
/// ends**, so an unrelated notice between two reports cannot hide the second
/// one; the old stop-at-the-first-unrelated-line extractor did exactly that and a
/// duplicated report passed every row.
fn image_blocks_of(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut lines: Vec<(usize, &str)> = Vec::new();
    let mut offset = 0;
    for raw in text.split_inclusive('\n') {
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        lines.push((offset, line));
        offset += raw.len();
    }
    let mut blocks = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        if !lines[at].1.starts_with(IMAGE_PREFIX) {
            at += 1;
            continue;
        }
        let mut collected = vec![lines[at].1.to_owned()];
        let mut end = lines[at].0 + lines[at].1.len();
        let mut notice_just_printed = false;
        at += 1;
        while at < lines.len() {
            let line = lines[at].1;
            let belongs = line.starts_with(IMAGE_PREFIX)
                || line.starts_with(IMAGE_NOTICE_PREFIX)
                || (notice_just_printed && line == GRANT_HINT);
            if !belongs {
                break;
            }
            notice_just_printed = line.starts_with(IMAGE_NOTICE_PREFIX);
            collected.push(line.to_owned());
            end = lines[at].0 + line.len();
            at += 1;
        }
        blocks.push((end, collected));
    }
    blocks
}

fn image_lines_of(text: &str) -> Vec<String> {
    image_blocks_of(text)
        .into_iter()
        .flat_map(|(_, block)| block)
        .collect()
}

fn image_blocks(out: &Output) -> Vec<Vec<String>> {
    image_blocks_of(&stderr(out))
        .into_iter()
        .map(|(_, block)| block)
        .collect()
}

/// Every image line in the whole of stderr, in order, across every block.
fn image_lines(out: &Output) -> Vec<String> {
    image_lines_of(&stderr(out))
}

/// The report's lines without the two trailer lines.
fn body(out: &Output) -> Vec<String> {
    image_lines(out)
        .into_iter()
        .filter(|line| !line.starts_with("==>   "))
        .collect()
}

const DEBUG_MARKER: &str = "[debug] sandbox config JSON: ";

fn debug_config(out: &Output) -> serde_json::Value {
    let text = stderr(out);
    let start = text
        .find(DEBUG_MARKER)
        .unwrap_or_else(|| panic!("no debug config in:\n{text}"))
        + DEBUG_MARKER.len();
    serde_json::Deserializer::from_str(&text[start..])
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no debug config in:\n{text}"))
        .unwrap_or_else(|error| panic!("unparseable debug config ({error}):\n{text}"))
}

/// The `fake_msb` launch fixture's stderr record of one real runtime invocation.
const LAUNCH_MARKER: &str = "MSB-LAUNCH ";

/// The argv of each runtime launch invocation, read from the shared stream.
fn launch_records(out: &Output) -> Vec<String> {
    stderr(out)
        .lines()
        .filter_map(|line| line.strip_prefix(LAUNCH_MARKER))
        .map(str::to_owned)
        .collect()
}

/// The causal create/ordering oracle for a launch run against the real launch
/// fixture.
///
/// Exactly one runtime launch invocation, whose argv is the SDK's `machine`
/// launch and names this run's sandbox; at least one new record since
/// `launches_before`; and the image report (when there is one) ends before that
/// record, on the same stream. A launch that skips create, or that invokes the
/// runtime before printing the report, fails here.
fn assert_sdk_launch(h: &Harness, out: &Output, launches_before: usize) {
    let text = stderr(out);
    let records = launch_records(out);
    assert_eq!(
        records.len(),
        1,
        "exactly one runtime launch per launch, got {records:?}\n{text}"
    );
    let argv: Vec<&str> = records[0].split(' ').collect();
    assert_eq!(argv[0], "machine", "the SDK launch entry point: {argv:?}");
    let pairs: Vec<(&str, &str)> = argv[1..]
        .chunks(2)
        .map(|pair| {
            assert_eq!(pair.len(), 2, "a flag with no value: {argv:?}");
            (pair[0], pair[1])
        })
        .collect();
    assert_eq!(
        pairs.iter().map(|(flag, _)| *flag).collect::<Vec<_>>(),
        [
            "--name",
            "--sandbox-id",
            "--parent-watch-fd",
            "--vcpus",
            "--memory-mib",
            "--config-fd",
            "--lifecycle-lock-fd",
        ],
        "the launch argv's flags, in order: {argv:?}"
    );
    assert!(
        pairs[0].1.starts_with("agent-vm-"),
        "the sandbox is named for the launch: {argv:?}"
    );
    for (index, flag) in [
        (1, "--sandbox-id"),
        (2, "--parent-watch-fd"),
        (3, "--vcpus"),
        (4, "--memory-mib"),
        (5, "--config-fd"),
        (6, "--lifecycle-lock-fd"),
    ] {
        assert!(
            pairs[index].1.parse::<u32>().is_ok(),
            "{flag} must be a decimal number: {argv:?}"
        );
    }
    assert_eq!(
        h.sdk_launch_count(),
        launches_before + 1,
        "the per-launch record must gain exactly one launch: {}\n{text}",
        h.invocations()
    );

    // One shared stream: the report must finish before the runtime is invoked.
    let marker = text
        .find(LAUNCH_MARKER)
        .expect("the launch record is on the captured stream");
    let blocks = image_blocks_of(&text);
    assert!(
        blocks.len() <= 1,
        "one launch emits at most one image report block: {:?}",
        blocks.iter().map(|(_, block)| block).collect::<Vec<_>>()
    );
    if let Some((end, block)) = blocks.last() {
        assert!(
            *end <= marker,
            "the image report must precede the runtime invocation: {block:?}"
        );
    }
}

/// The weaker oracle for the rows that keep the shell `LaunchSeam` fixture: the
/// launch reached the SDK create **call**, and the image report came before the
/// debug config dump. It is named for what it observes — the marker is printed
/// before `create`, so it cannot show that the runtime was invoked.
///
/// The report block is matched in order from its own first line, so the tool
/// report's identical grant hint earlier in stderr cannot satisfy the check.
fn reached_pre_create(out: &Output) {
    let text = stderr(out);
    let debug = text
        .find(DEBUG_MARKER)
        .unwrap_or_else(|| panic!("the launch never reached the create seam:\n{text}"));
    let lines = image_lines(out);
    let Some(first) = lines.first() else {
        return;
    };
    let mut cursor = text
        .find(first.as_str())
        .unwrap_or_else(|| panic!("no image report:\n{text}"));
    assert!(cursor < debug, "the image report precedes the create seam");
    for line in &lines {
        let at = text[cursor..]
            .find(line.as_str())
            .unwrap_or_else(|| panic!("line out of order: {line:?}"))
            + cursor;
        cursor = at + line.len();
    }
    assert!(
        cursor <= debug,
        "the image report must precede the sandbox config dump"
    );
}

fn report_line(reference: &str, rest: &str) -> String {
    format!("==> Image network requests ({reference}): {rest}")
}

fn change_line(reference: &str, rest: &str) -> String {
    format!("==> Image network requests ({reference}) changed: {rest}")
}

fn trailer() -> Vec<String> {
    vec![
        format!(
            "==>   image requests above are not covered by this launch's {SCOPE}; they never grant access \
                 and the launch continues; each image reference is reported once, then as changes"
        ),
        GRANT_HINT.to_owned(),
    ]
}

/// The extractor is a gate, so it is tested as one: an unrelated line between
/// two reports must not hide the second, and the concatenation must carry both.
#[test]
fn the_image_line_extractor_sees_every_block() {
    let report = format!(
        "{}(r): for codex a.example\n{}\n{GRANT_HINT}\n",
        "==> Image network requests", IMAGE_NOTICE_PREFIX
    );
    let text = format!("{report}an unrelated notice\n{report}");
    let blocks = image_blocks_of(&text);
    assert_eq!(blocks.len(), 2, "a later block is not hidden");
    assert_eq!(image_lines_of(&text).len(), 6, "both blocks are counted");
    assert!(
        blocks[1].0 > blocks[0].0,
        "the second block's end is later in the stream"
    );
    // A block may also end at end of stream, and the trailer's grant hint only
    // counts when the notice precedes it.
    let no_trailer = "==> Image network requests (r): for codex a.example\nnot the hint\n";
    assert_eq!(image_lines_of(no_trailer).len(), 1);
}

// ---------------------------------------------------------------------------
// A1 — the first launch reports, and the entry records on a failed launch
// ---------------------------------------------------------------------------

#[test]
fn a1_first_launch_reports_the_first_form_before_the_runtime_and_records_it() {
    let mut h = Harness::new(Mode::LaunchSeam);
    h.use_launch_runtime();
    let server = Server::new();
    let image = h.labeled(
        "a1",
        &[
            ("image.base", "deb.debian.org"),
            ("agent.codex", "api.openai.com"),
            ("agent.pi", "pi.dev"),
        ],
    );
    let child = server.image("images", "a1", &image);
    let tag = format!("{}/images:a1", server.host);

    let launches_before = h.sdk_launch_count();
    let out = h.launch_with(&tag, "codex", &[]);
    assert!(!out.status.success(), "the fake runtime never boots");
    let text = stderr(&out);
    // The tool report is above the image report, byte for byte.
    let tool = text
        .find("==> Tool network requests (built-in defaults)")
        .unwrap_or_else(|| panic!("no tool report:\n{text}"));
    let image_at = text
        .find("==> Image network requests")
        .unwrap_or_else(|| panic!("no image report:\n{text}"));
    assert!(tool < image_at, "the image report follows the tool report");
    assert_eq!(
        image_lines(&out),
        [
            vec![
                report_line(&tag, "for every launch deb.debian.org"),
                report_line(&tag, "for codex api.openai.com"),
                report_line(&tag, "for pi pi.dev"),
            ],
            trailer(),
        ]
        .concat()
    );
    assert_sdk_launch(&h, &out, launches_before);
    assert_eq!(
        image_blocks(&out).len(),
        1,
        "one image report block per launch: {:?}",
        image_blocks(&out)
    );
    // The SDK is handed the approved digest, and the store keyed by the selection.
    assert_eq!(
        debug_config(&out)["image"]["Oci"]["reference"]
            .as_str()
            .expect("an OCI reference"),
        child
    );
    assert_eq!(h.references(), vec![tag.clone()]);
    assert_eq!(
        h.recorded("image").as_deref(),
        Some(&["deb.debian.org".to_owned()][..])
    );
    assert_eq!(
        h.recorded("agent.codex").as_deref(),
        Some(&["api.openai.com".to_owned()][..])
    );
}

// ---------------------------------------------------------------------------
// A2 — once per reference, and a moved tag changes nothing without a refresh
// ---------------------------------------------------------------------------

#[test]
fn a2_a_second_launch_is_silent_and_a_moved_tag_needs_a_refresh() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.labeled("a2-a", &[("agent.codex", "api.openai.com")]);
    server.image("images", "a2", &image);
    let tag = format!("{}/images:a2", server.host);

    let first = h.launch(&tag);
    assert!(!first.status.success());
    assert_eq!(
        image_lines(&first),
        [
            vec![report_line(&tag, "for codex api.openai.com")],
            trailer(),
        ]
        .concat()
    );
    let before = h.store_meta().expect("the launch wrote the store");

    let second = h.launch(&tag);
    assert!(!second.status.success());
    assert!(
        image_lines(&second).is_empty(),
        "{:?}",
        image_lines(&second)
    );
    assert_eq!(
        h.store_meta().expect("the store still exists"),
        before,
        "a silent launch with the entry already first writes nothing"
    );

    // Moving the tag does not change what the warm approved launch boots, so the
    // report stays silent until `image refresh` moves the approval.
    let moved = h.labeled("a2-b", &[("agent.codex", "api.openai.com,b.example")]);
    server.image("images", "a2", &moved);
    let warm = h.launch(&tag);
    assert!(!warm.status.success());
    assert!(image_lines(&warm).is_empty(), "{:?}", image_lines(&warm));
    assert_eq!(h.store_meta().expect("unchanged"), before);
}

// ---------------------------------------------------------------------------
// A3 — after a refresh, the change form, in group order
// ---------------------------------------------------------------------------

#[test]
fn a3_a_refreshed_reference_reports_changes_per_group() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.labeled(
        "a3-a",
        &[
            ("image.base", "deb.debian.org"),
            ("agent.codex", "a.example,old.example"),
            ("agent.pi", "pi.dev"),
        ],
    );
    server.image("images", "a3", &image);
    let tag = format!("{}/images:a3", server.host);
    assert!(!h.launch(&tag).status.success());

    let refreshed = h.labeled(
        "a3-b",
        &[
            ("image.base", "deb.debian.org,static.rust-lang.org"),
            ("agent.codex", "a.example,b.example"),
            ("agent.claude", "api.anthropic.com"),
        ],
    );
    server.image("images", "a3", &refreshed);
    let refresh = h.refresh(&tag);
    assert!(refresh.status.success(), "{}", stderr(&refresh));

    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![
            change_line(&tag, "for every launch +static.rust-lang.org"),
            report_line(&tag, "for claude api.anthropic.com"),
            change_line(&tag, "for codex +b.example, -old.example"),
            change_line(&tag, "for pi -pi.dev"),
        ]
    );
    assert_eq!(
        image_lines(&out)
            .into_iter()
            .filter(|line| line.starts_with("==>   "))
            .collect::<Vec<_>>(),
        trailer(),
        "unmet additions were shown, so the trailer prints"
    );
    assert_eq!(h.recorded("agent.pi").as_deref(), Some(&[][..]));
    assert_eq!(
        h.recorded("agent.claude").as_deref(),
        Some(&["api.anthropic.com".to_owned()][..])
    );
}

// ---------------------------------------------------------------------------
// A4 — a fresh reference under full coverage is silent and writes nothing
// ---------------------------------------------------------------------------

#[test]
fn a4_a_fresh_reference_under_internet_egress_is_silent_and_creates_no_store() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.labeled(
        "a4-all",
        &[("agent.codex", "api.openai.com"), ("agent.pi", "pi.dev")],
    );
    server.image("images", "a4all", &image);
    let tag = format!("{}/images:a4all", server.host);

    let covered = h.launch_with(&tag, "shell", &["--allow-internet-egress"]);
    assert!(!covered.status.success());
    assert!(
        image_lines(&covered).is_empty(),
        "{:?}",
        image_lines(&covered)
    );
    assert!(
        !h.store_path().exists(),
        "a silent first launch creates no store file"
    );
    reached_pre_create(&covered);

    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![
            report_line(&tag, "for codex api.openai.com"),
            report_line(&tag, "for pi pi.dev"),
        ],
        "the next ungranted launch reports in full"
    );
}

#[test]
fn a4_a_covered_request_and_a_fully_covered_group_are_omitted() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.labeled(
        "a4-one",
        &[
            ("agent.codex", "api.openai.com,b.example"),
            ("agent.pi", "pi.dev"),
        ],
    );
    server.image("images", "a4one", &image);
    let tag = format!("{}/images:a4one", server.host);

    let out = h.launch_granted(&tag, &["api.openai.com"]);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![
            report_line(&tag, "for codex b.example"),
            report_line(&tag, "for pi pi.dev"),
        ]
    );

    // A group that is fully covered is omitted: only its own grant is present.
    let server = Server::new();
    let image = h.labeled(
        "a4-pi",
        &[("agent.codex", "api.openai.com"), ("agent.pi", "pi.dev")],
    );
    server.image("images", "a4pi", &image);
    let other = format!("{}/images:a4pi", server.host);
    let out = h.launch_granted(&other, &["pi.dev"]);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![report_line(&other, "for codex api.openai.com")]
    );
}

// ---------------------------------------------------------------------------
// A5 — a grant change alone never re-shows a request already shown
// ---------------------------------------------------------------------------

#[test]
fn a5_grant_changes_never_re_show_what_was_shown() {
    // The causal fixture: every one of these eight launches must reach a runtime
    // launch, which is what a "skip create after the first launch" edit breaks.
    let mut h = Harness::new(Mode::LaunchSeam);
    h.use_launch_runtime();
    let server = Server::new();
    let image = h.labeled(
        "a5",
        &[
            ("agent.codex", "a.example,b.example"),
            ("agent.pi", "pi.dev"),
        ],
    );
    server.image("images", "a5", &image);
    let tag = format!("{}/images:a5", server.host);

    let launches_before = h.sdk_launch_count();
    let first = h.launch(&tag);
    assert!(!first.status.success());
    assert_eq!(body(&first).len(), 2);
    assert_sdk_launch(&h, &first, launches_before);

    // Add and remove grants for shown requests and for covered ones, in every
    // combination; none of these launches may print an image line.
    for grants in [
        vec!["a.example"],
        vec!["a.example", "b.example"],
        vec!["b.example"],
        vec!["a.example", "pi.dev"],
        vec!["pi.dev"],
        vec![],
    ] {
        let launches_before = h.sdk_launch_count();
        let out = h.launch_granted(&tag, &grants);
        assert!(!out.status.success());
        assert!(
            image_lines(&out).is_empty(),
            "grants {grants:?} must not re-report: {:?}",
            image_lines(&out)
        );
        assert_sdk_launch(&h, &out, launches_before);
    }
    let launches_before = h.sdk_launch_count();
    let covered = h.launch_with(&tag, "shell", &["--allow-internet-egress"]);
    assert!(!covered.status.success());
    assert!(image_lines(&covered).is_empty());
    assert_sdk_launch(&h, &covered, launches_before);
}

// ---------------------------------------------------------------------------
// A6 — a label fixed after being invalid; the form is chosen per group
// ---------------------------------------------------------------------------

#[test]
fn a6a_a_fixed_label_with_no_recorded_set_uses_the_first_form() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let invalid = h.labeled("a6a-bad", &[("agent.codex", "api.openai.com b.example")]);
    server.image("images", "a6a", &invalid);
    let tag = format!("{}/images:a6a", server.host);

    let first = h.launch(&tag);
    assert!(!first.status.success());
    let lines = image_lines(&first);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].starts_with(&format!(
            "==> Image network requests ({tag}): ignored invalid label {}agent.codex (entry 0: ",
            "org.agent-vm.network-requests."
        )),
        "{lines:?}"
    );
    assert!(h.recorded("agent.codex").is_none(), "nothing was recorded");

    let fixed = h.labeled("a6a-good", &[("agent.codex", "api.openai.com")]);
    server.image("images", "a6a", &fixed);
    let refresh = h.refresh(&tag);
    assert!(refresh.status.success(), "{}", stderr(&refresh));

    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        image_lines(&out),
        [
            vec![report_line(&tag, "for codex api.openai.com")],
            trailer()
        ]
        .concat(),
        "no `+`, because codex had no recorded set"
    );
}

#[test]
fn a6b_a_fixed_label_alongside_a_shown_group_still_uses_the_first_form() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let invalid = h.labeled(
        "a6b-bad",
        &[
            ("agent.codex", "api.openai.com b.example"),
            ("agent.pi", "pi.dev"),
        ],
    );
    server.image("images", "a6b", &invalid);
    let tag = format!("{}/images:a6b", server.host);
    let first = h.launch(&tag);
    assert!(!first.status.success());
    let lines = body(&first);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0], report_line(&tag, "for pi pi.dev"));
    assert!(lines[1].contains("ignored invalid label"));

    let fixed = h.labeled(
        "a6b-good",
        &[("agent.codex", "api.openai.com"), ("agent.pi", "pi.dev")],
    );
    server.image("images", "a6b", &fixed);
    assert!(h.refresh(&tag).status.success());

    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![report_line(&tag, "for codex api.openai.com")],
        "codex is first-form and pi is unchanged"
    );
}

#[test]
fn a6c_a_recorded_group_that_turns_invalid_keeps_an_empty_recorded_set() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let good = h.labeled("a6c-good", &[("agent.codex", "api.openai.com")]);
    server.image("images", "a6c", &good);
    let tag = format!("{}/images:a6c", server.host);
    assert!(!h.launch(&tag).status.success());
    assert!(h.recorded("agent.codex").is_some());

    let broken = h.labeled("a6c-bad", &[("agent.codex", "api.openai.com b.example")]);
    server.image("images", "a6c", &broken);
    assert!(h.refresh(&tag).status.success());
    let out = h.launch(&tag);
    assert!(!out.status.success());
    let lines = image_lines(&out);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0], change_line(&tag, "for codex -api.openai.com"));
    assert!(lines[1].contains("ignored invalid label"));
    assert_eq!(
        h.recorded("agent.codex").as_deref(),
        Some(&[][..]),
        "the recorded set is empty, not absent"
    );

    let fixed = h.labeled("a6c-fixed", &[("agent.codex", "api.openai.com")]);
    server.image("images", "a6c", &fixed);
    assert!(h.refresh(&tag).status.success());
    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        image_lines(&out),
        [
            vec![change_line(&tag, "for codex +api.openai.com")],
            trailer()
        ]
        .concat()
    );
}

// ---------------------------------------------------------------------------
// A7 — hostile input never reaches stderr; validated metadata does
// ---------------------------------------------------------------------------

#[test]
fn a7_hostile_label_bytes_never_appear_and_validated_requests_do() {
    const SENTINEL: &str = "SENTINEL505";
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let hostile = h.labeled(
        "a7",
        &[
            // A control byte in the value fails the hostname grammar.
            ("agent.codex", "SENTINEL505\u{1b}[31m,x.example"),
            // A right-to-left override in an unsafe NAME cannot be a group.
            ("agent.SENTINEL505\u{202e}", "evil.example"),
            // A NUL and a newline in a value fail the grammar too.
            ("image.ok", "SENTINEL505\u{0}\napi.example.com"),
            // Controls: both of these are valid and must print.
            ("agent.valid", "sk-test-sensitivevalue"),
        ],
    );
    server.image("images", "a7", &hostile);
    let tag = format!("{}/images:a7", server.host);
    let out = h.launch(&tag);
    assert!(!out.status.success());
    let text = stderr(&out);
    assert!(
        !text.contains(SENTINEL),
        "a rejected byte reached stderr:\n{text}"
    );
    assert!(!text.contains('\u{202e}'));
    for line in image_lines(&out) {
        for byte in line.bytes() {
            assert!(
                byte == b' ' || byte.is_ascii_graphic(),
                "a report line carries {byte:#04x}: {line:?}"
            );
        }
    }
    assert!(
        text.contains("for valid sk-test-sensitivevalue"),
        "a validated hostname is printed, secret-looking or not:\n{text}"
    );

    // A valid, secret-looking NAME is printed as a key when its value is refused.
    let server = Server::new();
    let keyed = h.labeled("a7-key", &[("agent.sk-live-abc", "bad value")]);
    server.image("images", "a7key", &keyed);
    let out = h.launch(&format!("{}/images:a7key", server.host));
    assert!(!out.status.success());
    let text = stderr(&out);
    assert!(
        text.contains(&format!(
            "ignored invalid label {}agent.sk-live-abc",
            "org.agent-vm.network-requests."
        )),
        "{text}"
    );
}

// ---------------------------------------------------------------------------
// A8 — the default tier never renders its reference
// ---------------------------------------------------------------------------

#[test]
fn a8_the_default_tier_renders_a_fixed_reference() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.labeled("a8", &[("agent.codex", "api.openai.com")]);
    let child = server.image("images", "a8", &image);
    let tag = format!("{}/images:a8", server.host);
    let pinned = h.set_default(&tag);
    assert!(pinned.status.success(), "{}", stderr(&pinned));

    let out = h.launch_default();
    assert!(!out.status.success());
    let lines = image_lines(&out);
    assert_eq!(
        lines,
        [
            vec![report_line(
                "the default boot image",
                "for codex api.openai.com"
            )],
            trailer()
        ]
        .concat(),
        "{:?}",
        lines
    );
    let text = stderr(&out);
    assert!(
        !text.contains(&server.host),
        "the default tier must not render its reference:\n{text}"
    );
    assert!(!text.contains(child.rsplit_once('@').unwrap().1));
    assert_eq!(h.references(), vec![child.clone()], "the key is the digest");
}

// ---------------------------------------------------------------------------
// A9 — an unlabeled image and a local rootfs are silent
// ---------------------------------------------------------------------------

#[test]
fn a9_an_unlabeled_image_and_a_local_rootfs_are_silent() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let plain = h.image(&ArchiveSpec {
        marker: "a9".into(),
        ..Default::default()
    });
    server.image("images", "a9", &plain);
    let tag = format!("{}/images:a9", server.host);
    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert!(image_lines(&out).is_empty(), "{:?}", image_lines(&out));
    assert!(!h.store_path().exists());

    let rootfs = h.root.path().join("rootfs");
    fs::write(&rootfs, b"disk").unwrap();
    let local = h.launch(rootfs.to_str().unwrap());
    assert!(!local.status.success());
    assert!(image_lines(&local).is_empty(), "{:?}", image_lines(&local));
    assert!(!h.store_path().exists());
}

// ---------------------------------------------------------------------------
// A10 — a damaged store is rewritten; a non-regular path is never replaced
// ---------------------------------------------------------------------------

fn damaged_store_cases() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("garbage", b"not json".to_vec()),
        (
            "wrong version",
            br#"{"version":9,"references":[]}"#.to_vec(),
        ),
        (
            "unknown field",
            br#"{"version":1,"references":[],"extra":true}"#.to_vec(),
        ),
        ("over the byte bound", {
            let mut bytes = br#"{"version":1,"references":[],"#.to_vec();
            bytes.resize(8 * 1024 * 1024 + 1, b' ');
            bytes
        }),
    ]
}

#[test]
fn a10_a_damaged_regular_store_is_reported_in_full_and_rewritten() {
    let mut h = Harness::new(Mode::LaunchSeam);
    h.use_launch_runtime();
    let server = Server::new();
    let image = h.labeled("a10", &[("agent.codex", "api.openai.com")]);
    server.image("images", "a10", &image);
    let tag = format!("{}/images:a10", server.host);
    assert!(!h.launch(&tag).status.success());
    let healthy = h.store_meta().expect("the healthy store");

    for (name, bytes) in damaged_store_cases() {
        fs::write(h.store_path(), &bytes).unwrap();
        let launches_before = h.sdk_launch_count();
        let out = h.launch(&tag);
        assert!(!out.status.success());
        assert_eq!(
            body(&out),
            vec![report_line(&tag, "for codex api.openai.com")],
            "damage class {name:?} must report in full"
        );
        assert_sdk_launch(&h, &out, launches_before);
        let written = h.store_meta().expect("rewritten");
        assert_eq!(written.0, healthy.0, "{name:?}: rewritten as a valid store");
    }
}

#[test]
fn a10_a_symlinked_store_is_reported_in_full_and_left_in_place() {
    let mut h = Harness::new(Mode::LaunchSeam);
    h.use_launch_runtime();
    let server = Server::new();
    let image = h.labeled("a10l", &[("agent.codex", "api.openai.com")]);
    server.image("images", "a10l", &image);
    let tag = format!("{}/images:a10l", server.host);

    let outside = h.root.path().join("outside.json");
    fs::write(&outside, b"untouched").unwrap();
    std::os::unix::fs::symlink(&outside, h.store_path()).unwrap();

    let launches_before = h.sdk_launch_count();
    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![report_line(&tag, "for codex api.openai.com")]
    );
    assert_sdk_launch(&h, &out, launches_before);
    assert!(h.store_path().is_symlink(), "the link is left in place");
    assert_eq!(fs::read_link(h.store_path()).unwrap(), outside);
    assert_eq!(fs::read(&outside).unwrap(), b"untouched");

    // A repeat launch reports in full again.
    let again = h.launch(&tag);
    assert!(!again.status.success());
    assert_eq!(
        body(&again),
        vec![report_line(&tag, "for codex api.openai.com")]
    );
    assert!(h.store_path().is_symlink());
    assert_eq!(fs::read(&outside).unwrap(), b"untouched");
}

#[test]
fn a10_a_directory_at_the_store_path_is_reported_in_full_and_left_in_place() {
    let mut h = Harness::new(Mode::LaunchSeam);
    h.use_launch_runtime();
    let server = Server::new();
    let image = h.labeled("a10d", &[("agent.codex", "api.openai.com")]);
    server.image("images", "a10d", &image);
    let tag = format!("{}/images:a10d", server.host);

    fs::create_dir(h.store_path()).unwrap();
    fs::write(h.store_path().join("marker"), b"untouched").unwrap();

    let launches_before = h.sdk_launch_count();
    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![report_line(&tag, "for codex api.openai.com")]
    );
    assert_sdk_launch(&h, &out, launches_before);
    assert!(h.store_path().is_dir(), "the directory is untouched");
    assert_eq!(
        fs::read(h.store_path().join("marker")).unwrap(),
        b"untouched"
    );

    let again = h.launch(&tag);
    assert!(!again.status.success());
    assert_eq!(
        body(&again),
        vec![report_line(&tag, "for codex api.openai.com")]
    );
    assert!(h.store_path().is_dir());
}

// ---------------------------------------------------------------------------
// A11 — never authority
// ---------------------------------------------------------------------------

#[test]
fn a11_a_labeled_launch_emits_the_same_network_object_as_an_unlabeled_one() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let labeled = h.labeled("a11-labeled", &[("agent.codex", "api.openai.com")]);
    server.image("images", "a11l", &labeled);
    let plain = h.image(&ArchiveSpec {
        marker: "a11-plain".into(),
        ..Default::default()
    });
    server.image("images", "a11p", &plain);

    let reported = h.launch(&format!("{}/images:a11l", server.host));
    assert!(!reported.status.success());
    assert!(
        !image_lines(&reported).is_empty(),
        "the comparison is only meaningful with at least one unmet labeled host"
    );
    let baseline = h.launch(&format!("{}/images:a11p", server.host));
    assert!(!baseline.status.success());

    let labeled_network = &debug_config(&reported)["network"];
    assert!(
        !labeled_network.is_null(),
        "the sandbox network object must exist"
    );
    assert_eq!(
        labeled_network["policy"]["default_egress"], "deny",
        "the policy denies by default"
    );
    assert_eq!(
        labeled_network,
        &debug_config(&baseline)["network"],
        "labels must not change the sandbox network config"
    );

    // Positive control: the grant does move the object, so the comparison above
    // is not vacuous.
    let granted = h.launch_granted(&format!("{}/images:a11p", server.host), &["api.openai.com"]);
    assert!(!granted.status.success());
    assert_ne!(
        &debug_config(&granted)["network"],
        labeled_network,
        "a grant must change the network object"
    );
}

// ---------------------------------------------------------------------------
// A14 — doctor
// ---------------------------------------------------------------------------

/// Every path under `root`, with its kind, (for a regular file) its bytes, and
/// every entry's mode and mtime.
///
/// The mode and mtime are what make this a *read-only* oracle rather than a
/// content-only one: a doctor that took a lease, touched a lock file, rewrote a
/// cache entry in place or repaired a record would leave the names and bytes of
/// most paths unchanged, and an earlier version of this snapshot missed exactly
/// that (#505 review C's bounded-evidence note). `mtime_nsec` is compared too,
/// so a same-second rewrite cannot hide.
fn tree(root: &Path) -> Vec<(PathBuf, String)> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            out.push((dir, "<unreadable>".to_owned()));
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let stamp = format!(
                "mode={:o} mtime={}.{}",
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec()
            );
            if metadata.is_dir() {
                out.push((path.clone(), format!("<dir> {stamp}")));
                stack.push(path);
            } else if metadata.file_type().is_symlink() {
                out.push((path, format!("<symlink> {stamp}")));
            } else {
                out.push((
                    path.clone(),
                    format!("{:?} {stamp}", fs::read(&path).unwrap()),
                ));
            }
        }
    }
    out.sort();
    out
}

/// `doctor` has no `--image`, so the selection it reports comes from the env,
/// config or the default slot. These rows point `AGENT_VM_IMAGE_TAG` at the same
/// reference the launch used, which is the only way doctor can observe it.
fn doctor_for(h: &Harness, reference: &str) -> Output {
    let mut command = h.command();
    command.env("AGENT_VM_IMAGE_TAG", reference);
    command.arg("doctor");
    bounded(command)
}

/// `doctor` writes its sections to stdout, so the section is read from there.
fn doctor_section_of(out: &Output) -> Vec<String> {
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let start = text
        .find("==> image network requests")
        .unwrap_or_else(|| panic!("no image section in:\n{text}"));
    let rest = &text[start..];
    let end = rest
        .find("\n==> agent-vm doctor: available operations")
        .unwrap_or(rest.len());
    rest[..end].lines().map(str::to_owned).collect()
}

#[test]
fn a14_doctor_shows_every_group_in_full_without_writing_anything() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();

    let tag = format!("{}/images:a14", server.host);
    // Before any acquisition: the not-cached row.
    let empty = doctor_for(&h, &tag);
    assert!(
        doctor_section_of(&empty).join("\n").contains("not cached"),
        "{:?}",
        doctor_section_of(&empty)
    );

    let image = h.labeled(
        "a14",
        &[
            ("image.base", "deb.debian.org"),
            ("agent.codex", "api.openai.com,chatgpt.com"),
            ("agent.pi", ""),
        ],
    );
    server.image("images", "a14", &image);
    assert!(!h.launch_granted(&tag, &["api.openai.com"]).status.success());

    let cache = tree(&h.cache());
    let home = tree(&h.home);
    let state = tree(&h.state);
    let requests_before = server.count();
    let out = doctor_for(&h, &tag);
    assert!(out.status.success(), "{}", stderr(&out));
    let section = doctor_section_of(&out);
    assert_eq!(
        section,
        vec![
            "==> image network requests",
            "for every launch deb.debian.org",
            "for codex api.openai.com, chatgpt.com",
            "for pi (declares no requests)",
            "requests never grant access; a launch reports those its grants do not cover, once per \
             image reference, then as changes",
        ],
        "doctor lists every group in full, covered and empty ones included"
    );
    assert_eq!(tree(&h.cache()), cache, "doctor wrote to the cache");
    assert_eq!(tree(&h.home), home, "doctor wrote to the home");
    assert_eq!(tree(&h.state), state, "doctor wrote to the state root");
    assert_eq!(
        server.count(),
        requests_before,
        "doctor made a registry request"
    );

    // After a refresh, and no launch since, doctor shows the new labels.
    let refreshed = h.labeled("a14-b", &[("agent.codex", "api.openai.com,new.example")]);
    server.image("images", "a14", &refreshed);
    assert!(h.refresh(&tag).status.success());
    let section = doctor_section_of(&doctor_for(&h, &tag));
    assert!(
        section.contains(&"for codex api.openai.com, new.example".to_owned()),
        "{section:?}"
    );
    assert!(!section.contains(&"for every launch deb.debian.org".to_owned()));
}

/// The unapproved-selection read: an image imported into the cache and never
/// launched. Doctor's fallback path hashes the canonical *selection*, so this is
/// the only row that exercises it — the launched rows read the approved digest.
///
/// The import therefore runs under a separate HOME: an explicit import approves
/// its own result reference (#391), which would move this row onto the approved
/// branch and silently lose the coverage. The state root is shared, and that is
/// where the cache lives.
#[test]
fn a14b_doctor_reads_an_imported_image_that_was_never_launched() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    // The archive writer's bytes are a genuine OCI layout, which `image import`
    // accepts directly, labels included.
    let archive = h.root.path().join("a14b.tar");
    let spec = ArchiveSpec {
        marker: "a14b".into(),
        labels: labels(&[("agent.codex", "api.openai.com")]),
        ..Default::default()
    };
    image_archive::write(&archive, &spec);
    let tag = format!("{}/images:a14b", server.host);
    let seed_home = tempfile::Builder::new()
        .prefix("av-seed-home-")
        .tempdir()
        .unwrap();
    let mut command = h.command();
    command.env("HOME", seed_home.path()).args([
        "image",
        "import",
        "--input",
        archive.to_str().unwrap(),
        "--tag",
        &tag,
    ]);
    let imported = bounded(command);
    assert!(imported.status.success(), "{}", stderr(&imported));
    assert!(
        seed_home
            .path()
            .join(".config/agent-vm/image-pins.json")
            .exists(),
        "the fixture import approves its own result reference (#391)"
    );
    assert!(
        !h.home.join(".config/agent-vm/image-pins.json").exists(),
        "the selection must stay unapproved, so doctor reads the fallback path"
    );

    let out = doctor_for(&h, &tag);
    assert!(out.status.success(), "{}", stderr(&out));
    let section = doctor_section_of(&out);
    assert_eq!(
        section,
        vec![
            "==> image network requests",
            "for codex api.openai.com",
            "requests never grant access; a launch reports those its grants do not cover, once per \
             image reference, then as changes",
        ],
        "doctor reads the imported content's labels before any launch approves it"
    );
}

#[test]
fn a14_doctor_states_that_a_65_label_report_is_incomplete() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let mut pairs: Vec<(String, String)> = (0..65)
        .map(|index| {
            (
                label(&format!("agent.g{index:02}")),
                format!("h{index}.example"),
            )
        })
        .collect();
    pairs.sort();
    let image = h.image(&ArchiveSpec {
        marker: "a14-65".into(),
        labels: pairs,
        ..Default::default()
    });
    server.image("images", "a1465", &image);
    let tag = format!("{}/images:a1465", server.host);
    assert!(!h.launch(&tag).status.success());

    let out = doctor_for(&h, &tag);
    let section = doctor_section_of(&out);
    let groups = section
        .iter()
        .filter(|line| line.starts_with("for "))
        .count();
    assert_eq!(groups, 64, "{section:?}");
    assert!(
        section.iter().any(|line| line
            == "ignored 1 request label beyond the first 64 in key order; the requests above are incomplete"),
        "{section:?}"
    );
}

// ---------------------------------------------------------------------------
// A21 — each ignored class prints once, and a covered group is not recorded
// ---------------------------------------------------------------------------

#[test]
fn a21_an_invalid_label_prints_once_and_a_covered_change_stays_pending() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let image = h.labeled(
        "a21",
        &[("agent.codex", "bad value"), ("agent.pi", "pi.dev")],
    );
    server.image("images", "a21", &image);
    let tag = format!("{}/images:a21", server.host);

    // `pi` is fully covered here, and the only line is codex's refusal, so `pi`
    // gets no recorded set.
    let out = h.launch_granted(&tag, &["pi.dev"]);
    assert!(!out.status.success());
    let lines = image_lines(&out);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("ignored invalid label"));
    assert!(h.recorded("agent.pi").is_none(), "pi was not recorded");

    // The next launch without that grant reports pi in the first form.
    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![report_line(&tag, "for pi pi.dev")],
        "the ignored line is not repeated"
    );
}

#[test]
fn a21_an_unrecognized_key_is_counted_once_and_again_when_the_count_changes() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let one = h.labeled("a21-one", &[("Agent.x", "junk"), ("agent.pi", "pi.dev")]);
    server.image("images", "a21u", &one);
    let tag = format!("{}/images:a21u", server.host);
    let first = h.launch(&tag);
    assert!(!first.status.success());
    assert_eq!(
        image_lines(&first),
        [
            vec![
                report_line(&tag, "for pi pi.dev"),
                report_line(
                    &tag,
                    "ignored 1 label under org.agent-vm.network-requests. whose key is not image.NAME \
                     or agent.NAME"
                ),
            ],
            trailer(),
        ]
        .concat()
    );
    let second = h.launch(&tag);
    assert!(!second.status.success());
    assert!(
        image_lines(&second).is_empty(),
        "{:?}",
        image_lines(&second)
    );

    let two = h.labeled(
        "a21-two",
        &[
            ("Agent.x", "junk"),
            ("Agent.y", "junk"),
            ("agent.pi", "pi.dev"),
        ],
    );
    server.image("images", "a21u", &two);
    assert!(h.refresh(&tag).status.success());
    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![report_line(
            &tag,
            "ignored 2 labels under org.agent-vm.network-requests. whose key is not image.NAME or \
             agent.NAME"
        )]
    );
}

#[test]
fn a21_an_excess_label_is_counted_once() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let mut pairs: Vec<(String, String)> = (0..65)
        .map(|index| {
            (
                label(&format!("agent.g{index:02}")),
                format!("h{index}.example"),
            )
        })
        .collect();
    pairs.sort();
    let image = h.image(&ArchiveSpec {
        marker: "a21-excess".into(),
        labels: pairs,
        ..Default::default()
    });
    server.image("images", "a21x", &image);
    let tag = format!("{}/images:a21x", server.host);
    let first = h.launch(&tag);
    assert!(!first.status.success());
    let lines = image_lines(&first);
    assert_eq!(
        lines.last(),
        Some(&GRANT_HINT.to_owned()),
        "the trailer closes the report: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line
            == &report_line(
                &tag,
                "ignored 1 request label beyond the first 64 in key order; this report is partial"
            )),
        "{lines:?}"
    );
    assert_eq!(
        body(&first)
            .iter()
            .filter(|line| line.contains(": for "))
            .count(),
        64
    );
    let second = h.launch(&tag);
    assert!(!second.status.success());
    assert!(
        image_lines(&second).is_empty(),
        "{:?}",
        image_lines(&second)
    );
}

// ---------------------------------------------------------------------------
// A22 — pending changes across launches, asserting the store each time
// ---------------------------------------------------------------------------

/// R18's worked example, run literally: A, then a covered addition, then the same
/// addition unmet, then silence.
#[test]
fn a22i_the_pending_example_runs_across_four_launches() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.labeled("a22i-a", &[("agent.codex", "a.example")]);
    server.image("images", "a22i", &a);
    let tag = format!("{}/images:a22i", server.host);

    assert!(!h.launch(&tag).status.success());
    assert_eq!(
        h.recorded("agent.codex").as_deref(),
        Some(&["a.example".to_owned()][..])
    );

    let b = h.labeled("a22i-b", &[("agent.codex", "a.example,b.example")]);
    server.image("images", "a22i", &b);
    assert!(h.refresh(&tag).status.success());

    let covered = h.launch_granted(&tag, &["b.example"]);
    assert!(!covered.status.success());
    assert!(
        image_lines(&covered).is_empty(),
        "{:?}",
        image_lines(&covered)
    );
    assert_eq!(
        h.recorded("agent.codex").as_deref(),
        Some(&["a.example".to_owned()][..]),
        "the covered addition stays pending"
    );

    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        image_lines(&out),
        [vec![change_line(&tag, "for codex +b.example")], trailer()].concat()
    );
    assert_eq!(
        h.recorded("agent.codex").as_deref(),
        Some(&["a.example".to_owned(), "b.example".to_owned()][..])
    );

    let quiet = h.launch(&tag);
    assert!(!quiet.status.success());
    assert!(image_lines(&quiet).is_empty(), "{:?}", image_lines(&quiet));
}

/// The ignored-only variant: the covered launch prints only an ignored line, and
/// codex still keeps its pending addition.
#[test]
fn a22ii_an_ignored_only_launch_does_not_advance_a_group() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.labeled("a22ii-a", &[("agent.codex", "a.example")]);
    server.image("images", "a22ii", &a);
    let tag = format!("{}/images:a22ii", server.host);
    assert!(!h.launch(&tag).status.success());

    let b = h.labeled(
        "a22ii-b",
        &[
            ("agent.codex", "a.example,b.example"),
            ("agent.bad", "10.0.0.1"),
        ],
    );
    server.image("images", "a22ii", &b);
    assert!(h.refresh(&tag).status.success());

    let covered = h.launch_granted(&tag, &["b.example"]);
    assert!(!covered.status.success());
    let lines = image_lines(&covered);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("ignored invalid label"));
    assert_eq!(
        h.recorded("agent.codex").as_deref(),
        Some(&["a.example".to_owned()][..])
    );

    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        image_lines(&out),
        [vec![change_line(&tag, "for codex +b.example")], trailer()].concat(),
        "the refused label is not repeated"
    );
}

/// Two interleaved references keep independent entries.
#[test]
fn a22iii_two_references_do_not_share_a_recorded_set() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let x = h.labeled("a22iii-x", &[("agent.codex", "a.example")]);
    let y = h.labeled("a22iii-y", &[("agent.codex", "y.example")]);
    server.image("images", "x", &x);
    server.image("images", "y", &y);
    let xt = format!("{}/images:x", server.host);
    let yt = format!("{}/images:y", server.host);

    assert!(!h.launch(&xt).status.success());
    assert!(!h.launch(&yt).status.success());
    assert_eq!(h.references(), vec![yt.clone(), xt.clone()]);

    let x2 = h.labeled("a22iii-x2", &[("agent.codex", "a.example,b.example")]);
    server.image("images", "x", &x2);
    assert!(h.refresh(&xt).status.success());
    let covered = h.launch_granted(&xt, &["b.example"]);
    assert!(!covered.status.success());
    assert!(image_lines(&covered).is_empty());

    let still = h.launch(&yt);
    assert!(!still.status.success());
    assert!(image_lines(&still).is_empty(), "{:?}", image_lines(&still));

    let out = h.launch(&xt);
    assert!(!out.status.success());
    assert_eq!(
        body(&out),
        vec![change_line(&xt, "for codex +b.example")],
        "only X carries the pending change"
    );
    let quiet = h.launch(&yt);
    assert!(!quiet.status.success());
    assert!(image_lines(&quiet).is_empty(), "{:?}", image_lines(&quiet));
}

/// Two groups are independent: one group's line never advances another's, and
/// the absorbed grant does not reprint (the documented residual).
#[test]
fn a22iv_two_groups_are_independent() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.labeled(
        "a22iv-a",
        &[("agent.x", "x1.example"), ("agent.y", "y1.example")],
    );
    server.image("images", "a22iv", &a);
    let tag = format!("{}/images:a22iv", server.host);
    let first = h.launch(&tag);
    assert!(!first.status.success());
    assert_eq!(
        body(&first),
        vec![
            report_line(&tag, "for x x1.example"),
            report_line(&tag, "for y y1.example"),
        ]
    );

    let b = h.labeled(
        "a22iv-b",
        &[
            ("agent.x", "x1.example,x2.example,x3.example"),
            ("agent.y", "y1.example,y2.example"),
        ],
    );
    server.image("images", "a22iv", &b);
    assert!(h.refresh(&tag).status.success());

    let out = h.launch_granted(&tag, &["x3.example", "y2.example"]);
    assert!(!out.status.success());
    assert_eq!(
        image_lines(&out),
        [vec![change_line(&tag, "for x +x2.example")], trailer()].concat(),
        "y's covered addition prints nothing"
    );
    assert_eq!(
        h.recorded("agent.x").as_deref(),
        Some(
            &[
                "x1.example".to_owned(),
                "x2.example".to_owned(),
                "x3.example".to_owned()
            ][..]
        ),
        "x's own line advanced x, absorbing the covered x3"
    );
    assert_eq!(
        h.recorded("agent.y").as_deref(),
        Some(&["y1.example".to_owned()][..]),
        "y kept its recorded set"
    );

    let dropped = h.launch(&tag);
    assert!(!dropped.status.success());
    assert_eq!(
        image_lines(&dropped),
        [vec![change_line(&tag, "for y +y2.example")], trailer()].concat(),
        "y's pending addition surfaces, x's absorbed x3 does not"
    );
    let quiet = h.launch(&tag);
    assert!(!quiet.status.success());
    assert!(image_lines(&quiet).is_empty(), "{:?}", image_lines(&quiet));
}

// ---------------------------------------------------------------------------
// A23 — precedence under `--allow-internet-egress`
// ---------------------------------------------------------------------------

#[test]
fn a23_internet_egress_shows_removals_only_and_a_new_ignored_label_once() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let a = h.labeled("a23-a", &[("agent.codex", "a.example,b.example")]);
    server.image("images", "a23", &a);
    let tag = format!("{}/images:a23", server.host);
    assert!(!h.launch(&tag).status.success());

    // R7's example, run literally.
    let b = h.labeled("a23-b", &[("agent.codex", "a.example")]);
    server.image("images", "a23", &b);
    assert!(h.refresh(&tag).status.success());
    let out = h.launch_with(&tag, "shell", &["--allow-internet-egress"]);
    assert!(!out.status.success());
    assert_eq!(
        image_lines(&out),
        vec![change_line(&tag, "for codex -b.example")],
        "a removal under full coverage prints, with no trailer"
    );
    assert_eq!(
        h.recorded("agent.codex").as_deref(),
        Some(&["a.example".to_owned()][..])
    );

    // A refresh that adds only an invalid label prints only its ignored line.
    let c = h.labeled(
        "a23-c",
        &[("agent.codex", "a.example"), ("agent.bad", "10.0.0.1")],
    );
    server.image("images", "a23", &c);
    assert!(h.refresh(&tag).status.success());
    let out = h.launch_with(&tag, "shell", &["--allow-internet-egress"]);
    assert!(!out.status.success());
    let lines = image_lines(&out);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("ignored invalid label"));
    assert_eq!(
        h.recorded("agent.codex").as_deref(),
        Some(&["a.example".to_owned()][..]),
        "every other group's recorded set is unchanged"
    );

    // The following identical launch is silent and does not rewrite the store.
    let before = h.store_meta().expect("the store");
    let again = h.launch_with(&tag, "shell", &["--allow-internet-egress"]);
    assert!(!again.status.success());
    assert!(image_lines(&again).is_empty(), "{:?}", image_lines(&again));
    assert_eq!(h.store_meta().expect("unchanged"), before);
}

// ---------------------------------------------------------------------------
// A24 — admission and the two count lines
// ---------------------------------------------------------------------------

#[test]
fn a24_sixty_four_unrecognized_keys_do_not_hide_a_valid_group() {
    let h = Harness::new(Mode::LaunchSeam);
    let server = Server::new();
    let mut pairs: Vec<(String, String)> = (0..64)
        .map(|index| (label(&format!("Agent.a{index:02}")), "junk".to_owned()))
        .collect();
    pairs.push((label("agent.zz"), "late.example".to_owned()));
    let image = h.image(&ArchiveSpec {
        marker: "a24".into(),
        labels: pairs,
        ..Default::default()
    });
    server.image("images", "a24", &image);
    let tag = format!("{}/images:a24", server.host);
    let out = h.launch(&tag);
    assert!(!out.status.success());
    assert_eq!(
        image_lines(&out),
        [
            vec![
                report_line(&tag, "for zz late.example"),
                report_line(
                    &tag,
                    "ignored 64 labels under org.agent-vm.network-requests. whose key is not image.NAME \
                     or agent.NAME"
                ),
            ],
            trailer(),
        ]
        .concat()
    );
}
