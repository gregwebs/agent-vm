//! Host-only controls for the config-mounts suite (#697).
//!
//! Ported from the boot-free halves of `script/test/lib/config-mounts.py`
//! (`--self-check`, `--dispatch-check`) and from the inline Python that closed
//! `script/test/config-mounts-contract.sh` (the `ci-contracts.sh` guard-removal
//! mutations). The name avoids "contract" on purpose: `CONTEXT.md` reserves that
//! word for Verus boundary contracts, and these are controls — host-only evidence,
//! never native enforcement evidence.
//!
//! Three groups, each cheap and boot-free:
//!
//! * `receipt` — the evidence receipt tells BLOCKED from FAIL from PASS, and the
//!   GM-N2 host oracle rejects the four ways a commit can be wrong while the row
//!   still looks like a pass.
//! * `dispatch` — the GM group's **real dispatch** over fake launches and a real
//!   `git` fixture: a `GM-MISSING` image blocks every row after one launch, a
//!   commit line naming the seed object fails `GM-N2-host`, and a real commit
//!   passes.
//! * `guard` — each `ci-contracts.sh` guard entry the config-mounts scripts depend
//!   on is removed in a scratch copy, and that copy must refuse by name.
//!
//! Only the launch half is faked in `dispatch`; the oracle stays real, because a
//! row a fake launch can satisfy is exactly the row that cannot detect a faked
//! commit.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde_json::json;

use crate::config_mounts::{
    BLOCKED_NOTE, Baseline, GM_ROWS, GmFixture, GmHost, GmOutcome, Observed, Receipt, Seam,
    build_gm_fixture, gm_commit_row, gm_git, gm_n2_host_row, run_gm_group,
};
use crate::egress_probe::run_command_bounded;

/// A live shell's own bound is not needed here — nothing in these controls starts
/// a candidate — but a scratch `ci-contracts.sh` copy is a real bash process and
/// its exit is bounded rather than trusted.
const GUARD_RUN: Duration = Duration::from_secs(20);

/// The control groups, in the order they run.
const GROUPS: [&str; 3] = ["receipt", "dispatch", "guard"];

/// The rows a successful GM-N1 rendering carries, used by the fake seam.
const GM_RO_ROW: &str = "GM-N1 log=seed diff=tracked.txt write=denied add=denied\n\
                         ==> Git metadata: linked worktree, read-only\n";

#[derive(Debug, clap::Args)]
pub struct ConfigMountsControlsArgs {
    /// The checkout under test: its `script/test` tree is the subject.
    #[arg(long)]
    repo_root: PathBuf,

    /// Run only one group: receipt, dispatch or guard.
    #[arg(long)]
    only: Option<String>,
}

pub fn run(args: ConfigMountsControlsArgs) -> Result<String, String> {
    let repo = args.repo_root.canonicalize().map_err(|error| {
        format!(
            "{}: {error} (pass --repo-root with the checkout under test)",
            args.repo_root.display()
        )
    })?;
    // A selector that quietly matches nothing would report a pass for a group
    // that never ran, which is exactly the control that cannot fail.
    if let Some(only) = args.only.as_deref()
        && !GROUPS.contains(&only)
    {
        return Err(format!(
            "usage: --only must be one of {} (got {only})",
            GROUPS.join(", ")
        ));
    }
    let mut report = Vec::new();
    for group in GROUPS {
        if args.only.as_deref().is_some_and(|only| only != group) {
            continue;
        }
        let line = match group {
            "receipt" => receipt_controls()?,
            "dispatch" => dispatch_controls(&repo)?,
            _ => guard_mutations(&repo)?,
        };
        report.push(line);
    }
    Ok(format!(
        "{}\nconfig mounts host-only controls PASS",
        report.join("\n")
    ))
}

fn scratch(prefix: &str) -> Result<PathBuf, String> {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let path = std::env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()));
    fs::create_dir_all(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    // The scratch holds fixtures these controls own; a symlinked parent would let
    // a control delete outside it, so resolve once.
    path.canonicalize()
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// A named set of comparisons. One failure never hides the next: the whole group
/// runs and reports what it saw, because a control that stops at the first
/// mismatch cannot tell a single break from a broken group.
#[derive(Default)]
struct Checks {
    failures: Vec<String>,
    count: usize,
}

impl Checks {
    fn check<T: PartialEq + std::fmt::Debug>(&mut self, name: &str, expected: T, actual: T) {
        self.count += 1;
        if expected != actual {
            self.failures
                .push(format!("{name}: expected {expected:?}, got {actual:?}"));
        }
    }

    fn fail(&mut self, message: String) {
        self.count += 1;
        self.failures.push(message);
    }

    fn finish(self, line: &str) -> Result<String, String> {
        if !self.failures.is_empty() {
            for failure in &self.failures {
                eprintln!("FAIL: {failure}");
            }
            return Err(format!(
                "{line} FAILED ({} of {} checks)",
                self.failures.len(),
                self.count
            ));
        }
        Ok(format!("{line} ({})", self.count))
    }
}

// --- The receipt and the GM-N2 oracle ---------------------------------------

fn receipt_controls() -> Result<String, String> {
    let mut checks = Checks::default();
    let scratch = scratch("cm-receipt")?;
    let outcome = receipt_checks(&scratch, &mut checks);
    let _ = fs::remove_dir_all(&scratch);
    outcome?;
    checks.finish("config mounts receipt controls passed")
}

/// The boot-free checks of the row logic (#535).
///
/// The native rows are the only place these decisions run, so the decisions
/// themselves are exercised here, without a VM: a missing `git` in the image must
/// produce BLOCKED receipts that count as neither pass nor failure, and the GM-N2
/// commit oracle must reject the ways a commit can be wrong while the row still
/// looks like a pass — an unmoved branch, a commit off the old tip, a commit
/// without the guest's edit and a commit the host cannot read.
fn receipt_checks(scratch: &Path, checks: &mut Checks) -> Result<(), String> {
    let summary = scratch.join("summary.tsv");
    let mut receipt = Receipt::new(&summary, true);
    // One row of each kind, plus a blocked row that arrives with a result: the
    // receipt may never be turned into a pass by what the row happened to say.
    receipt.record("R-pass", Observed::text("same"), Observed::text("same"))?;
    receipt.blocked("R-blocked")?;
    receipt.record_with(
        "R-other-blocked",
        Observed::text(BLOCKED_NOTE),
        Observed::text(BLOCKED_NOTE),
        true,
    )?;
    match receipt.record(
        "R-fail",
        Observed::text("same"),
        Observed::text("different"),
    ) {
        Ok(()) => checks.fail("a failing row did not report a failure".to_owned()),
        Err(error) if error.starts_with("R-fail: ") => checks.check("a failing row", true, true),
        Err(error) => checks.fail(format!("a failing row reported the wrong row: {error}")),
    }
    receipt.record_with(
        "R-blocked-with-output",
        Observed::text("anything"),
        Observed::text("anything"),
        true,
    )?;
    checks.check(
        "totals",
        json!({
            "rows": 5,
            "passed": 1,
            "blocked": ["R-blocked", "R-other-blocked", "R-blocked-with-output"],
            "failed": ["R-fail"],
        }),
        receipt.totals(),
    );
    let written =
        fs::read_to_string(&summary).map_err(|error| format!("{}: {error}", summary.display()))?;
    let statuses: Vec<&str> = written
        .lines()
        .filter_map(|line| line.rsplit_once('\t').map(|(_, status)| status))
        .collect();
    checks.check(
        "summary statuses",
        vec!["PASS", "BLOCKED", "BLOCKED", "FAIL", "BLOCKED"],
        statuses,
    );

    // The GM-N2 oracle, over the observations it must tell apart.
    let baseline = "a".repeat(40);
    let guest_commit = "b".repeat(40);
    let good: Vec<(&'static str, String)> = vec![
        ("branch", guest_commit.clone()),
        ("parent", baseline.clone()),
        ("tracked", "seed\nguest-change\nguest-commit\n".to_owned()),
        ("object", "present".to_owned()),
    ];
    let (expected, actual) = gm_n2_host_row(&guest_commit, &baseline, &good);
    checks.check("the good commit", expected, actual);
    for (name, key, value) in [
        ("unmoved branch", "branch", baseline.clone()),
        ("wrong parent", "parent", "c".repeat(40)),
        ("no guest edit", "tracked", "seed\n".to_owned()),
        ("no object", "object", "absent".to_owned()),
    ] {
        let broken: Vec<(&'static str, String)> = good
            .iter()
            .map(|(observed, current)| {
                if *observed == key {
                    (key, value.clone())
                } else {
                    (*observed, current.clone())
                }
            })
            .collect();
        let (expected, actual) = gm_n2_host_row(&guest_commit, &baseline, &broken);
        checks.check(
            &format!("the GM-N2 oracle accepted a commit with {name}"),
            false,
            expected == actual,
        );
    }

    // A guest line that is not a full object id is not a commit.
    checks.check(
        "a refused commit",
        Observed::text("GM-N2 commit=refused"),
        gm_commit_row("GM-N2 commit=refused").1,
    );
    checks.check(
        "a real commit line",
        Observed::text("GM-N2 commit=<40-hex object id>"),
        gm_commit_row(&format!("GM-N2 commit={guest_commit}")).1,
    );
    Ok(())
}

// --- The GM group's dispatch over fake launches -----------------------------

/// A boot-free stand-in for `(launch, cleanup)`: canned guest output, recorded
/// calls. Only the launch half is faked.
#[derive(Default)]
struct FakeSeam {
    replies: BTreeMap<String, Box<dyn FnMut() -> String>>,
    launched: Vec<(String, String, Vec<String>, Vec<String>)>,
    cleaned: Vec<String>,
}

impl FakeSeam {
    fn reply(&mut self, phase: &str, reply: impl FnMut() -> String + 'static) {
        self.replies.insert(phase.to_owned(), Box::new(reply));
    }

    fn text(&mut self, phase: &str, body: &str) {
        let body = body.to_owned();
        self.reply(phase, move || body.clone());
    }
}

impl Seam for FakeSeam {
    fn launch(
        &mut self,
        row: &str,
        phase: &str,
        flags: &[String],
        extra: &[String],
    ) -> Result<String, String> {
        self.launched.push((
            row.to_owned(),
            phase.to_owned(),
            flags.to_vec(),
            extra.to_vec(),
        ));
        match self.replies.get_mut(phase) {
            Some(reply) => Ok(reply()),
            None => Ok(String::new()),
        }
    }

    fn cleanup(&mut self, row: &str) -> Result<(), String> {
        self.cleaned.push(row.to_owned());
        Ok(())
    }
}

fn dispatch_controls(repo: &Path) -> Result<String, String> {
    let scratch = scratch("cm-dispatch")?;
    let mut checks = Checks::default();
    let outcome = dispatch_checks(repo, &scratch, &mut checks);
    if outcome.is_err() {
        eprintln!("controls scratch retained: {}", scratch.display());
    } else {
        let _ = fs::remove_dir_all(&scratch);
    }
    outcome?;
    checks.finish("config mounts dispatch controls passed")
}

fn dispatch_checks(repo: &Path, scratch: &Path, checks: &mut Checks) -> Result<(), String> {
    let work = scratch.join("work");
    fs::create_dir_all(work.join("home"))
        .map_err(|error| format!("{}: {error}", work.display()))?;
    let gm = build_gm_fixture(
        &work,
        &repo.join("script/test/fixtures/config-mounts/guest-gm-probe.sh"),
    )?;
    let host = GmHost { fixture: gm };
    let baseline = Baseline::measure(&host)?;

    // (a) No `git` in the image: one launch, seven BLOCKED rows, nothing passed,
    //     and no cleanup or launch after it.
    let mut seam = FakeSeam::default();
    seam.text("ro", "GM-MISSING guest image has no git\n");
    let mut receipt = Receipt::new(&scratch.join("blocked.tsv"), true);
    checks.check(
        "(a) dispatch outcome",
        Ok(GmOutcome::Blocked),
        run_gm_group(&mut seam, &host, &mut receipt, &baseline),
    );
    checks.check(
        "(a) launches",
        vec![("GM-N1".to_owned(), "ro".to_owned(), vec![], vec![])],
        seam.launched.clone(),
    );
    checks.check(
        "(a) cleanups",
        vec!["GM-N1".to_owned()],
        seam.cleaned.clone(),
    );
    checks.check(
        "(a) totals",
        json!({"rows": 7, "passed": 0, "blocked": GM_ROWS, "failed": []}),
        receipt.totals(),
    );
    let blocked = fs::read_to_string(scratch.join("blocked.tsv"))
        .map_err(|error| format!("{}: {error}", scratch.display()))?;
    let statuses: Vec<&str> = blocked
        .lines()
        .filter_map(|line| line.rsplit_once('\t').map(|(_, status)| status))
        .collect();
    checks.check(
        "(a) receipt statuses",
        vec![
            "BLOCKED", "BLOCKED", "BLOCKED", "BLOCKED", "BLOCKED", "BLOCKED", "BLOCKED",
        ],
        statuses,
    );

    // (b) The guest prints the *seed* object id without committing: the shape
    //     passes, and the host oracle must catch it.
    let seed = baseline.branch.clone();
    let mut seam = FakeSeam::default();
    seam.text("ro", GM_RO_ROW);
    seam.text("rw", &format!("GM-N2 commit={seed}\n"));
    let mut receipt = Receipt::new(&scratch.join("unmoved.tsv"), true);
    match run_gm_group(&mut seam, &host, &mut receipt, &baseline) {
        Err(error) => checks.check(
            "(b) the failing row",
            true,
            error.starts_with("GM-N2-host: "),
        ),
        Ok(outcome) => checks.fail(format!(
            "(b) a commit line naming the seed object passed the oracle: {outcome:?}"
        )),
    }
    checks.check(
        "(b) totals",
        json!({"rows": 4, "passed": 3, "blocked": [], "failed": ["GM-N2-host"]}),
        receipt.totals(),
    );

    // (c) The positive control: the launch really commits, and the oracle accepts
    //     it. The replies own *paths*, not the fixture this module also reads, so
    //     the oracle stays a real observation of the same repository.
    let mut seam = FakeSeam::default();
    seam.text("ro", GM_RO_ROW);
    seam.reply("rw", committer(&host.fixture));
    seam.text("off", "GM-N3 absent\n");
    seam.reply("control", writer(&host.fixture));
    let mut receipt = Receipt::new(&scratch.join("committed.tsv"), true);
    checks.check(
        "(c) dispatch outcome",
        Ok(GmOutcome::Measured),
        run_gm_group(&mut seam, &host, &mut receipt, &baseline),
    );
    checks.check(
        "(c) totals",
        json!({"rows": 7, "passed": 7, "blocked": [], "failed": []}),
        receipt.totals(),
    );
    checks.check(
        "(c) cleanups",
        vec![
            "GM-N1".to_owned(),
            "GM-N2".to_owned(),
            "GM-N3".to_owned(),
            "GM-N4".to_owned(),
        ],
        seam.cleaned.clone(),
    );
    Ok(())
}

/// The `rw` reply that really commits in the fixture, exactly as the guest probe
/// does: the edit, the add, the commit, then the branch tip.
fn committer(fixture: &GmFixture) -> impl FnMut() -> String + 'static {
    let home = fixture.home.clone();
    let worktree = fixture.worktree.clone();
    let main = fixture.main.clone();
    let tracked = fixture.tracked.clone();
    move || {
        let _ = fs::write(&tracked, "seed\nguest-commit\n");
        let added = gm_git(&home, &worktree, &["add", "tracked.txt"]).is_ok();
        let committed =
            added && gm_git(&home, &worktree, &["commit", "-q", "-m", "gm-probe"]).is_ok();
        let oid = committed
            .then(|| gm_git(&home, &main, &["rev-parse", "gm"]).ok())
            .flatten()
            .map(|out| out.trim().to_owned())
            .unwrap_or_else(|| "<absent>".to_owned());
        format!("GM-N2 commit={oid}\n")
    }
}

/// The `control` reply: the same relative write through the automatic bind's path,
/// which the fixture proves is writable here.
fn writer(fixture: &GmFixture) -> impl FnMut() -> String + 'static {
    let probe = fixture.common.join("objects/gm-probe");
    move || {
        let _ = fs::write(&probe, "gm-probe\n");
        "GM-N4 automatic=denied alias=allowed\n".to_owned()
    }
}

// --- Guard removal mutations ------------------------------------------------

/// The scripts the config-mounts contract depends on. Each must be in both guard
/// lists, and a copy of `ci-contracts.sh` without one entry must refuse by name.
const GUARDED: [&str; 3] = [
    "script/test/config-mounts-live.sh",
    "script/test/config-mounts-contract.sh",
    "script/test/fixtures/config-mounts/guest-cm-probe.sh",
];

fn guard_mutations(repo: &Path) -> Result<String, String> {
    let mut checks = Checks::default();
    let source = fs::read_to_string(repo.join("script/test/ci-contracts.sh"))
        .map_err(|error| format!("script/test/ci-contracts.sh: {error}"))?;
    // The companion must actually run in CI, not merely be listed.
    let run_list = source
        .split("# --- Shell guard rail")
        .next()
        .unwrap_or_default();
    checks.check(
        "the contract is run by ci-contracts.sh",
        true,
        run_list.contains("bash \"$REPO_ROOT/script/test/config-mounts-contract.sh\""),
    );
    for (array, label) in [
        ("syntax_check", "bash -n"),
        ("shellcheck_files", "shellcheck"),
    ] {
        for script in GUARDED {
            let list = format!("{array}=(");
            let start = source
                .find(&list)
                .ok_or_else(|| format!("ci-contracts.sh has no {array} list"))?;
            let end = source[start..]
                .find("\n)")
                .map(|offset| start + offset)
                .ok_or_else(|| format!("the {array} list is unterminated"))?;
            let block = &source[start..end];
            let entry = format!("    {script}\n");
            checks.check(
                &format!("{array} lists {script} once"),
                1,
                block.matches(entry.as_str()).count(),
            );
            checks.check(
                &format!("{label} membership is asserted for {script}"),
                true,
                source.contains(&format!("assert_listed '{label}' '{script}'")),
            );
            let mutated = format!(
                "{}{}{}",
                &source[..start],
                block.replace(&entry, ""),
                &source[end..]
            );
            let (status, stderr) = run_guard_copy(&mutated)?;
            checks.check(
                &format!("removing {script} from {array} fails the guard rail"),
                1,
                status,
            );
            checks.check(
                &format!("the {array} removal names {script} and {label}"),
                true,
                stderr.contains(&format!(
                    "({script}) is missing from the {label} guard list"
                )),
            );
        }
    }
    checks.finish("config mounts guard removal mutations passed")
}

/// Run a scratch copy of `ci-contracts.sh` with its guards alone, bounded.
fn run_guard_copy(source: &str) -> Result<(i32, String), String> {
    let directory = scratch("cm-guard-mutation")?;
    let outcome = (|| -> Result<(i32, String), String> {
        let path = directory.join("script/test/ci-contracts.sh");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        fs::write(&path, source).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut command = Command::new("/bin/bash");
        command.arg(&path).arg("--guard-only");
        let output = run_command_bounded(command, GUARD_RUN)?;
        Ok((output.status, output.stderr))
    })();
    let _ = fs::remove_dir_all(&directory);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn the_receipt_controls_hold() {
        receipt_controls().expect("the receipt controls pass");
    }

    #[test]
    fn the_gm_dispatch_controls_hold() {
        dispatch_controls(&repo_root()).expect("the GM dispatch controls pass");
    }
}
