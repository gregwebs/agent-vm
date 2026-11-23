//! macOS notifications for the refusals a launch did not ask about.
//!
//! Slice 4 (#501) splits the work along one seam: what a banner should say and
//! when it may be replaced is a pure function of the refusals, the prompt's
//! signals and a caller-supplied clock ([`coalesce`]); everything that touches a
//! process, a socket or a file — helper discovery, the NDJSON transport, the
//! click launcher — lives beside it and is added by the phases that need it.
//!
//! This module is the facade and stays thin on purpose:
//!
//! * the **settings** ([`read_settings`]) and the **eligibility rule**
//!   ([`should_notify`], R7);
//! * **sibling-only discovery** of the helper bundle ([`resolve_notifier`], S4);
//! * [`NotifierHandle`], the handle the session owns: a signal channel, a
//!   completion request and the task that must not outlive it.
//!
//! The transport and the driver are [`helper`]'s. [`terminal`] is already reached
//! through the hidden `_notify-click` verb; [`coalesce`] is reached by the
//! driver. `session_control` owns the handle ([`NotifierHandle::start`] once per
//! launch, `finish` in the teardown), and the prompt's loop forwards its signals
//! through [`SignalSink`].

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

pub(crate) mod coalesce;
pub(crate) mod helper;
pub(crate) mod terminal;

pub(crate) use coalesce::{PromptMode, PromptSignal, SessionMeta};
pub(crate) use terminal::{ClickArgs, TerminalChoice, run_click};

use crate::allowances::LiveAllowances;
use crate::env_flag::{self, FlagValue};
use crate::host_paths::current_euid;
use crate::msb_install::ExeLocation;
use crate::refusal::feed::{Hint, LiveRefusals};
use crate::refusal::{SessionId, SessionSnapshot};

/// The opt-out. Truthy disables notifications for the session; a typo warns and
/// leaves them on (the documented default is *on*).
pub(crate) const NO_NOTIFICATIONS_SETTING: &str = "AGENT_VM_NO_NOTIFICATIONS";

/// The notifications-off line, delivered as the session's second
/// [`crate::refusal::feed::Hint`] so it reaches the operator exactly the way
/// ADR-0064's hint does (R6).
pub(crate) const NOTIFICATIONS_OFF: &str = "==> macOS notifications are off for agent-vm; run `agent-vm access` to see refusals (shown once per session)";

/// The helper bundle's path, relative to the bundle root that holds `bin/` and
/// `lib/` (S4).
const NOTIFIER_RELATIVE: &str = "lib/AgentVMNotifier.app/Contents/MacOS/AgentVMNotifier";

/// Where the final `refusals.json` write landed. Only a persisted record may be
/// followed by a final banner: a failed or timed-out write must not claim
/// durability (R9, B5).
///
/// Phase 4's `refusal::feed::FinalWait::wait` returns this, replacing today's
/// `bool`; it is defined here because the notifier is its only consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalWriteStatus {
    Persisted,
    Failed,
    TimedOut,
}

/// Both settings, read once at the launch boundary, with the warnings a typo
/// deserves (R7, S7).
pub(crate) struct Settings {
    pub(crate) notifications: FlagValue,
    /// Already parsed: an unrecognised value keeps the documented default rather
    /// than guessing a terminal the operator did not ask for.
    pub(crate) terminal: TerminalChoice,
    /// One message per typo, for the caller to emit before the session starts.
    pub(crate) warnings: Vec<String>,
}

/// Read both settings. Unset is the documented default, not an error.
pub(crate) fn read_settings() -> Settings {
    let notifications = env_flag::read(NO_NOTIFICATIONS_SETTING);
    let mut warnings = Vec::new();
    if let Some(value) = notifications.unrecognized() {
        warnings.push(format!(
            "==> {NO_NOTIFICATIONS_SETTING}={} is not one of 1/true/yes/on or 0/false/no/off; macOS notifications stay on",
            crate::config::escape_str(value)
        ));
    }
    let terminal = match std::env::var(terminal::TERMINAL_SETTING) {
        Ok(value) => match TerminalChoice::parse(&value) {
            Some(choice) => choice,
            None => {
                warnings.push(format!(
                    "==> {setting}={} is not one of terminal/ghostty/wezterm/alacritty; a click opens Terminal",
                    crate::config::escape_str(&value),
                    setting = terminal::TERMINAL_SETTING
                ));
                TerminalChoice::default()
            }
        },
        Err(_) => TerminalChoice::default(),
    };
    Settings {
        notifications,
        terminal,
        warnings,
    }
}

/// Every fact eligibility reads, measured once (R7).
///
/// Deliberately *only* these four: there is no fifth, ambient override — not in a
/// debug build, not under `--dev` — so no environment variable can turn a
/// notification on where the platform, the host identity or SSH says no.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) disabled: FlagValue,
    pub(crate) is_macos: bool,
    pub(crate) euid: u32,
    pub(crate) ssh_session: bool,
}

impl Facts {
    pub(crate) fn measure(disabled: FlagValue) -> Self {
        Self {
            disabled,
            is_macos: cfg!(target_os = "macos"),
            euid: current_euid(),
            ssh_session: ssh_session(),
        }
    }
}

/// R7's decision, as a pure function of the measured facts.
pub(crate) fn should_notify(facts: &Facts) -> bool {
    facts.disabled != FlagValue::On && facts.is_macos && facts.euid != 0 && !facts.ssh_session
}

/// Whether this is a remote session: any of the three variables ssh sets.
fn ssh_session() -> bool {
    ["SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
}

/// The helper bundle beside this executable, when there is one (S4).
///
/// Exactly one candidate: `<bundle>/lib/AgentVMNotifier.app/Contents/MacOS/AgentVMNotifier`
/// for an executable in `<bundle>/bin/`. There is deliberately no
/// cross-directory fallback — a `target/debug/agent-vm` never picks up
/// `target/macos-dev/lib/AgentVMNotifier.app` — because pairing a launcher with a
/// callback from a different build is worse than posting no banner at all.
///
/// A missing bundle (bare `cargo run`, `--single-binary`, Linux) is `None`, which
/// is the documented silent fallback to the stderr hint and `agent-vm access`.
pub(crate) fn resolve_notifier(exe: &ExeLocation) -> Option<PathBuf> {
    let exe = exe.layout_exe();
    let bin = exe.parent()?;
    if bin.file_name()? != "bin" {
        return None;
    }
    // `<bundle>` is `<exe>/../..`: two `parent()` calls rather than a `../..`
    // suffix, because path resolution cannot traverse *through* the executable.
    let candidate = bin.parent()?.join(NOTIFIER_RELATIVE);
    candidate.is_file().then_some(candidate)
}

/// The spelling the wire carries for a terminal choice.
///
/// The helper hands it back to `agent-vm _notify-click --terminal`, which parses
/// it with [`TerminalChoice::parse`], so the two tables must agree;
/// `wire_terminal_round_trips_through_the_parser` pins that.
fn wire_terminal(choice: TerminalChoice) -> &'static str {
    match choice {
        TerminalChoice::Terminal => "terminal",
        TerminalChoice::Ghostty => "ghostty",
        TerminalChoice::WezTerm => "wezterm",
        TerminalChoice::Alacritty => "alacritty",
    }
}

/// The launch facts a banner and a click need (B8).
///
/// `project` and `state_root` are the *effective* values the launch resolved —
/// canonical project, effective state root — because a click hours later must
/// open the session's own report, not whatever a later launch would resolve.
pub(crate) struct Launch {
    pub(crate) session: SessionId,
    pub(crate) project: PathBuf,
    pub(crate) state_root: PathBuf,
    pub(crate) project_hash: String,
    pub(crate) project_name: String,
    pub(crate) terminal: TerminalChoice,
}

/// The session's handle on the driver.
///
/// Owned by the session (Phase 4 puts it beside `hint` on `LiveSession`). Two
/// things reach the driver: prompt signals, and the completion request that
/// carries the final snapshot. Nothing else — the driver subscribes to the
/// refusal and answer feeds itself.
pub(crate) struct NotifierHandle {
    signals: mpsc::UnboundedSender<PromptSignal>,
    requests: mpsc::UnboundedSender<helper::FinishRequest>,
    /// `Some` until this handle is finished or dropped. `Drop` takes it, so the
    /// shutdown it asks for can wait on the same task `finish` does.
    task: Option<tokio::task::JoinHandle<()>>,
    finished: bool,
}

/// A cloneable, non-blocking handle on the driver's signal channel (R12).
///
/// The prompt's loop holds this rather than the driver: `LiveSession` owns
/// [`NotifierHandle`], and an [`mpsc::UnboundedSender::send`] never waits, so no
/// prompt or terminal frame ever waits on a helper.
#[derive(Clone)]
pub(crate) struct SignalSink(mpsc::UnboundedSender<PromptSignal>);

impl SignalSink {
    /// Hand the driver one signal. A driver that is gone drops it: the session
    /// outlives no notification obligation.
    pub(crate) fn signal(&self, signal: PromptSignal) {
        let _ = self.0.send(signal);
    }
}

#[cfg(test)]
impl SignalSink {
    /// A sink and its receiver, so a test can count what the prompt forwards.
    pub(crate) fn for_tests() -> (Self, mpsc::UnboundedReceiver<PromptSignal>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self(sender), receiver)
    }
}

impl NotifierHandle {
    /// Start the driver, or `None` when this launch must not notify (R7, S4).
    ///
    /// `settings` is the value [`read_settings`] already returned, so the launch
    /// boundary reads the environment once.
    pub(crate) fn start(
        launch: Launch,
        mode: PromptMode,
        settings: &Settings,
        refusals: Arc<LiveRefusals>,
        allowances: Arc<LiveAllowances>,
        notifications_off: Arc<Hint>,
    ) -> Option<Self> {
        if !should_notify(&Facts::measure(settings.notifications.clone())) {
            return None;
        }
        let helper = resolve_notifier(&ExeLocation::from_process()?)?;
        let click = helper::ClickUserInfo::try_from_paths(
            &launch.session,
            &launch.project,
            &launch.state_root,
            wire_terminal(launch.terminal),
        )?;
        let meta = SessionMeta {
            project_hash: launch.project_hash,
            project_name: launch.project_name,
            session_id: launch.session,
        };
        Some(Self::spawn(
            helper::DriverInputs {
                refusals,
                allowances,
                notifications_off,
                meta,
                mode,
                click,
                #[cfg(test)]
                before_commit: None,
            },
            Box::new(helper::ChildHelperSpawner::new(helper)),
        ))
    }

    /// Start a driver over an injected backend (the unit tests' seam).
    #[cfg(test)]
    pub(crate) fn start_with_spawner(
        inputs: helper::DriverInputs,
        spawner: Box<dyn helper::HelperSpawner>,
    ) -> Self {
        Self::spawn(inputs, spawner)
    }

    fn spawn(inputs: helper::DriverInputs, spawner: Box<dyn helper::HelperSpawner>) -> Self {
        let (signals_tx, signals) = mpsc::unbounded_channel();
        let (requests_tx, requests) = mpsc::unbounded_channel();
        Self {
            signals: signals_tx,
            requests: requests_tx,
            task: Some(tokio::spawn(helper::run(
                inputs, signals, spawner, requests,
            ))),
            finished: false,
        }
    }

    /// The non-blocking sink the prompt's loop forwards its sequenced signals
    /// through. A sender clone rather than the handle: the loop must never wait on
    /// a helper, and a driver that has gone makes the send a no-op (R12).
    pub(crate) fn signals(&self) -> SignalSink {
        SignalSink(self.signals.clone())
    }

    /// The signal channel, for a test that has to inject at a driver-internal
    /// instant rather than through [`Self::signal`].
    #[cfg(test)]
    pub(crate) fn signal_sender(&self) -> mpsc::UnboundedSender<PromptSignal> {
        self.signals.clone()
    }

    /// Finish the session: fold the last drained snapshot in, flush a final post
    /// when the final write persisted, then close the helper gracefully
    /// (R9, B5). Called after `close_socket()`.
    ///
    /// Bounded by [`helper::NOTIFY_FINISH_WAIT`]. A driver that does not answer in
    /// time is aborted, and the child's own guard then kills and reaps it.
    pub(crate) async fn finish(&mut self, snapshot: SessionSnapshot, status: FinalWriteStatus) {
        if self.finished {
            return;
        }
        self.finished = true;
        let (done, wait) = oneshot::channel();
        let request = helper::FinishRequest {
            plan: helper::FinishPlan::Session { snapshot, status },
            done,
        };
        if self.requests.send(request).is_err() {
            return;
        }
        let Some(task) = self.task.as_mut() else {
            return;
        };
        if tokio::time::timeout(helper::NOTIFY_FINISH_WAIT, wait)
            .await
            .is_err()
        {
            // The driver did not answer in time. Aborting drops its future, and
            // with it the child — whose guard kills and reaps it. Waiting for the
            // handle here is what makes that true before the caller finishes its
            // own teardown. Bounded, because a runtime that is already shutting
            // down must not hold this up.
            task.abort();
            let _ = tokio::time::timeout(helper::QUIT_WAIT, task).await;
        }
    }
}

impl Drop for NotifierHandle {
    /// Never leave a driver — or the helper it owns — behind (F3).
    ///
    /// The plan had `Drop` abort the driver and lean on `kill_on_drop(true)`, but
    /// an abort only *signals* the child: the reap is left to tokio's orphan
    /// queue, which a shutting-down runtime never runs. So `Drop` asks for the
    /// same bounded close [`Self::finish`] uses and aborts only if that close does
    /// not arrive. `Drop` cannot await, so the wait lives in a task.
    ///
    /// Without a runtime there is nothing that could run either half: abort, and
    /// let the child's guard do what it can synchronously (signal, `try_wait`).
    fn drop(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        if self.finished {
            // `finish` already closed (or aborted) the driver.
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            task.abort();
            return;
        };
        let (done, wait) = oneshot::channel();
        let request = helper::FinishRequest {
            plan: helper::FinishPlan::Abandoned,
            done,
        };
        if self.requests.send(request).is_err() {
            // The driver is already gone: nothing is left to ask.
            task.abort();
            return;
        }
        handle.spawn(async move {
            let mut task = task;
            if tokio::time::timeout(helper::NOTIFY_FINISH_WAIT, wait)
                .await
                .is_err()
            {
                task.abort();
                let _ = tokio::time::timeout(helper::QUIT_WAIT, &mut task).await;
            }
        });
    }
}

#[cfg(test)]
mod tests;
