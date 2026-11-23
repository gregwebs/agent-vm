// The macOS notification bridge that `agent-vm` spawns beside itself.
//
// Two halves, one process:
//
//   * `serve` is the launcher's child: NDJSON v1 on stdin/stdout, one banner at
//     a time, in the order the launcher asked for it.
//   * a bare launch is LaunchServices replaying a click on a banner whose
//     launcher is long gone. Nothing is served; the click spawns
//     `.../bin/agent-vm _notify-click` and the process exits with it.
//
// `crates/agent-vm/src/notify/helper.rs` owns both halves of the wire. This file
// must not invent a field, a tag or a version: the Rust side is authoritative,
// and it tolerates unknown *events* so an older launcher survives a newer
// helper, never the other way round.
//
// Everything before `NSApplication.shared` is deliberate: `--version` and
// `--check-bundle` are the only checks a headless macOS CI runner can make, so
// they are answered with Foundation alone and never start AppKit.

import AppKit
import Foundation
import UserNotifications

/// The only protocol version either side speaks.
let protocolVersion = 1

/// The longest frame either side reads (`helper.rs::MAX_HELPER_LINE_BYTES`). A
/// longer line is dropped up to its newline rather than buffered, so a runaway
/// writer cannot grow this process.
let maxFrameBytes = 16 * 1024

/// How many operations may wait behind the one in flight. The launcher is
/// strictly serial — it writes the next command only after this helper
/// acknowledged the previous one — so this bound only ever bites a writer that
/// breaks that contract, and it bites instead of growing without limit.
let maxPendingOps = 32

/// The identity every copy of the helper shares, so System Settings shows one
/// "agent-vm" toggle (`Info.plist.in`, plan §4.2 "mixed-copy identity").
let bundleIdentifier = "dev.agent-vm.notifier"

/// An unanswered first-run authorization dialog gets this long at shutdown.
let authDrain: TimeInterval = 1.5

/// The whole shutdown drain, including `authDrain`.
let totalDrain: TimeInterval = 2.0

/// A cold click must not leave this helper alive behind a child that never
/// exits. The child keeps running; only the helper gives up.
let coldClickDrain: TimeInterval = 10.0

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

/// One line of JSON on stdout, written whole.
///
/// The lock is what makes a frame a frame: three threads emit (main, the `add`
/// completion, the stdin reader's hop to main) and an interleaved half-line would
/// cost the launcher every event behind it.
final class Wire {
    private let lock = NSLock()
    private let out = FileHandle.standardOutput

    func emit(_ fields: [String: Any]) {
        var frame = fields
        frame["v"] = protocolVersion
        guard let data = try? JSONSerialization.data(withJSONObject: frame, options: [.sortedKeys]) else {
            return
        }
        var line = data
        line.append(0x0A)
        lock.lock()
        defer { lock.unlock() }
        try? out.write(contentsOf: line)
    }
}

/// What a click needs hours later (B8). Every field becomes one `argv` operand
/// for `_notify-click`, so every field is checked before a launch is attempted: a
/// session that is not eight lowercase hex digits would open a different session,
/// and a relative path or an unknown terminal would spend a process to fail in
/// Rust where this can answer at once (S4).
struct ClickInfo {
    let session: String
    let project: String
    let stateDir: String
    let terminal: String

    private init(session: String, project: String, stateDir: String, terminal: String) {
        self.session = session
        self.project = project
        self.stateDir = stateDir
        self.terminal = terminal
    }

    /// Why a notification's click fields cannot become `_notify-click` operands.
    struct Problem: Error {
        let reason: String
    }

    /// The four validated operands, or why these values cannot be operands. The
    /// reason is what a click reports in `open_failed`, so a launch that cannot
    /// work is never attempted (S4).
    static func make(session: Any?, project: Any?, stateDir: Any?, terminal: Any?) -> Result<ClickInfo, Problem> {
        func problem(_ reason: String) -> Result<ClickInfo, Problem> {
            .failure(Problem(reason: reason))
        }
        guard let session = session as? String else {
            return problem("the notification carried no session")
        }
        guard isSessionIdentifier(session) else {
            return problem("session is not eight lowercase hex digits")
        }
        guard let project = project as? String, isAbsolutePath(project) else {
            return problem("project is not an absolute path")
        }
        guard let stateDir = stateDir as? String, isAbsolutePath(stateDir) else {
            return problem("state_dir is not an absolute path")
        }
        guard let terminal = terminal as? String, isTerminalChoice(terminal) else {
            return problem("terminal is not one of terminal/ghostty/wezterm/alacritty")
        }
        return .success(ClickInfo(session: session, project: project, stateDir: stateDir, terminal: terminal))
    }

    /// `^[0-9a-f]{8}$`, spelled as bytes so no locale or regex engine decides it.
    static func isSessionIdentifier(_ text: String) -> Bool {
        text.utf8.count == 8 && text.utf8.allSatisfy { byte in
            (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
        }
    }

    /// `argv` cannot carry a NUL, and an empty operand names nothing.
    static func isOperand(_ text: String) -> Bool {
        !text.isEmpty && !text.contains("\0")
    }

    /// The launcher sends the effective project and state root, always absolute
    /// (`helper.rs::wire_path`), and `_notify-click` refuses a relative path.
    static func isAbsolutePath(_ text: String) -> Bool {
        isOperand(text) && text.hasPrefix("/")
    }

    /// The four spellings `_notify-click --terminal` parses
    /// (`notify.rs::wire_terminal`). Anything else would only become a warning and
    /// a default choice in the child.
    static func isTerminalChoice(_ text: String) -> Bool {
        ["terminal", "ghostty", "wezterm", "alacritty"].contains(text)
    }
}

struct PostCommand {
    let seq: UInt64
    let id: String
    let thread: String
    let title: String
    let subtitle: String
    let body: String
    let passive: Bool
    let click: ClickInfo
}

enum Command {
    case post(PostCommand)
    case remove(seq: UInt64, id: String)
    case quit
}

/// The number as a signed 64-bit integer, or `nil`.
///
/// `JSONSerialization` hands back an `NSNumber` for `true`, `1` and `1.5` alike, so
/// a Swift cast decides nothing: the Rust side's serde types accept a JSON integer
/// and reject a bool or a float, and this must accept exactly the same set (S3).
func integerValue(_ value: Any?) -> Int64? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
        return nil
    }
    switch String(cString: number.objCType) {
    case "s", "i", "l", "q", "S", "I", "L", "Q":
        return number.int64Value
    default:
        return nil
    }
}

/// A JSON bool, and only a JSON bool: `1` is not `true` for serde either (S3).
func boolValue(_ value: Any?) -> Bool? {
    guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
        return nil
    }
    return number.boolValue
}

/// Decode one frame. `nil` for anything this helper must skip — not the
/// launcher's protocol version, not JSON, not a shape v1 defines — because a
/// frame this build cannot read is a frame it must not act on (S6).
///
/// Every v1 field is required with the type serde declares: a frame missing one,
/// or carrying `1.0` where `u64` belongs, is a frame from something that is not
/// this protocol, and a banner posted from a guess would be worse than none (S3).
func decodeCommand(_ line: Data) -> Command? {
    guard line.count <= maxFrameBytes,
          let parsed = try? JSONSerialization.jsonObject(with: line),
          let fields = parsed as? [String: Any],
          integerValue(fields["v"]) == Int64(protocolVersion),
          let op = fields["op"] as? String
    else {
        return nil
    }
    switch op {
    case "post":
        guard let seq = integerValue(fields["seq"]), seq >= 0,
              let id = fields["id"] as? String, ClickInfo.isOperand(id),
              let thread = fields["thread"] as? String,
              let title = fields["title"] as? String,
              let subtitle = fields["subtitle"] as? String,
              let body = fields["body"] as? String,
              let passive = boolValue(fields["passive"]),
              let clickFields = fields["click"] as? [String: Any],
              case .success(let click) = ClickInfo.make(
                  session: clickFields["session"],
                  project: clickFields["project"],
                  stateDir: clickFields["state_dir"],
                  terminal: clickFields["terminal"]
              )
        else {
            return nil
        }
        return .post(
            PostCommand(
                seq: UInt64(seq),
                id: id,
                thread: thread,
                title: title,
                subtitle: subtitle,
                body: body,
                passive: passive,
                click: click
            )
        )
    case "remove":
        guard let seq = integerValue(fields["seq"]), seq >= 0,
              let id = fields["id"] as? String, ClickInfo.isOperand(id)
        else {
            return nil
        }
        return .remove(seq: UInt64(seq), id: id)
    case "quit":
        return .quit
    default:
        return nil
    }
}

/// Read stdin as NDJSON until EOF, on its own thread.
///
/// A blocking `read(2)` rather than `FileHandle.readabilityHandler`: the handler
/// can be re-entered while a previous chunk is still being parsed, and any
/// exception in it silently detaches stdin. Here the worst case is a skipped
/// frame, and a skipped frame is exactly what v1 allows.
///
/// Decoding also happens here, so a line costs one main-queue hop only when it is
/// a command v1 defines (S2). `onCommand` therefore runs on this thread; `onEnd`
/// runs on the main queue.
func readStdinFrames(onCommand: @escaping (Command) -> Void, onEnd: @escaping () -> Void) {
    let thread = Thread {
        var pending = [UInt8]()
        var discarding = false
        var buffer = [UInt8](repeating: 0, count: maxFrameBytes)
        while true {
            let count = buffer.withUnsafeMutableBytes { chunk in
                read(STDIN_FILENO, chunk.baseAddress, chunk.count)
            }
            if count < 0 {
                if errno == EINTR { continue }
                break
            }
            if count == 0 { break }
            for byte in buffer[0..<count] {
                if byte == 0x0A {
                    // An oversize frame ends at its newline: everything up to it
                    // was dropped, and the next byte starts a fresh frame.
                    if discarding {
                        discarding = false
                    } else {
                        var line = Data(pending)
                        if line.last == 0x0D { line.removeLast() }
                        if let command = decodeCommand(line) { onCommand(command) }
                    }
                    pending.removeAll(keepingCapacity: true)
                    continue
                }
                if discarding { continue }
                if pending.count >= maxFrameBytes {
                    discarding = true
                    pending.removeAll(keepingCapacity: true)
                    continue
                }
                pending.append(byte)
            }
        }
        DispatchQueue.main.async { onEnd() }
    }
    thread.stackSize = 512 * 1024
    thread.start()
}

// ---------------------------------------------------------------------------
// The helper
// ---------------------------------------------------------------------------

final class Helper: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    /// Whether this process is the launcher's child (`serve`) or a cold click.
    private let serving: Bool
    private let wire = Wire()
    private lazy var center = UNUserNotificationCenter.current()

    /// Not-in-flight operations, oldest first. Main queue only.
    private var pending: [Command] = []
    private var running = false
    /// The intake channel: commands admit one at a time from the reader thread,
    /// bounded at [`maxPendingOps`]. It is the backlog bound, so a full channel is
    /// answered on the spot instead of growing the main queue (S2).
    private let intakeSlots = DispatchSemaphore(value: maxPendingOps)
    /// Reader thread only: the first `quit` wins, and later ones are dropped. A
    /// quit is not an operation, so it never takes a slot and cannot be refused.
    private var quitForwarded = false

    /// The authorization answer has arrived. Until then a shutdown waits
    /// `authDrain` for it and gives up (B6).
    private var authSettled = false
    private var notificationsOff = false

    private var shuttingDown = false
    private var shutdownStarted = Date()

    init(serving: Bool) {
        self.serving = serving
        super.init()
    }

    // -- launch ------------------------------------------------------------

    func applicationDidFinishLaunching(_ notification: Notification) {
        center.delegate = self
        if serving {
            wire.emit(["type": "launched", "serving": true, "pid": Int(getpid())])
            readStdinFrames(
                onCommand: { [weak self] command in self?.intake(command) },
                onEnd: { [weak self] in self?.stdinClosed() }
            )
            reportAuthorization()
        } else {
            // A cold launch is only ever a replayed click. If none arrives, this
            // process has no reason to exist.
            DispatchQueue.main.asyncAfter(deadline: .now() + coldClickDrain) { [weak self] in
                guard let self, !self.serving else { return }
                self.leave()
            }
        }
    }

    // -- authorization -----------------------------------------------------

    /// Two `auth` frames, and the first is emitted before the dialog is asked.
    ///
    /// The launcher starts its acknowledgement timer when it writes, so a
    /// human-paced dialog must never withhold the answer: `notDetermined` says the
    /// dialog is up, and the launcher decides what to do with a post it cannot get
    /// acknowledged yet (S1). The second frame is the settled answer.
    private func reportAuthorization() {
        center.getNotificationSettings { [weak self] settings in
            DispatchQueue.main.async {
                guard let self else { return }
                self.emitAuthorization(
                    settings: settings,
                    granted: settings.authorizationStatus == .authorized,
                    error: nil,
                    settled: settings.authorizationStatus != .notDetermined
                )
                // Asked only after the first frame went out, so the settled frame
                // is always the last one a launcher sees.
                self.requestAuthorization()
            }
        }
    }

    private func requestAuthorization() {
        center.requestAuthorization(options: [.alert]) { [weak self] granted, error in
            guard let self else { return }
            self.center.getNotificationSettings { settings in
                DispatchQueue.main.async {
                    self.emitAuthorization(settings: settings, granted: granted, error: error, settled: true)
                }
            }
        }
    }

    /// `status` is the field the launcher acts on, and it acts on `denied` alone;
    /// the rest is there for a human reading a log.
    private func emitAuthorization(settings: UNNotificationSettings, granted: Bool, error: Error?, settled: Bool) {
        if settled { authSettled = true }
        notificationsOff = settings.authorizationStatus == .denied
        wire.emit([
            "type": "auth",
            "granted": granted,
            "status": statusName(settings.authorizationStatus),
            "alertStyle": alertStyleName(settings.alertStyle),
            "error": error.map { $0.localizedDescription } ?? "",
        ])
        maybeFinishDrain()
    }

    private func statusName(_ status: UNAuthorizationStatus) -> String {
        switch status {
        case .notDetermined: return "notDetermined"
        case .denied: return "denied"
        case .authorized: return "authorized"
        case .provisional: return "provisional"
        case .ephemeral: return "ephemeral"
        @unknown default: return "unknown"
        }
    }

    private func alertStyleName(_ style: UNAlertStyle) -> String {
        switch style {
        case .none: return "none"
        case .banner: return "banner"
        case .alert: return "alert"
        @unknown default: return "unknown"
        }
    }

    // -- stdin -------------------------------------------------------------

    /// Called on the stdin reader thread. It can touch only what is thread-safe:
    /// `Wire` locks, the channel semaphore is a semaphore, and `quitForwarded` is
    /// read and written by this thread alone. The queue and every
    /// `UNUserNotificationCenter` call stay on the main queue.
    private func intake(_ command: Command) {
        if case .quit = command {
            guard !quitForwarded else { return }
            quitForwarded = true
        } else if intakeSlots.wait(timeout: .now()) != .success {
            // The backlog is full: answer now, from this thread, rather than grow
            // either queue. `ok: false` is the truth — what is showing is unknown.
            reject(command, reason: "queue_full")
            return
        }
        DispatchQueue.main.async { [weak self] in self?.enqueue(command) }
    }

    private func stdinClosed() {
        wire.emit(["type": "stdin_closed"])
        beginShutdown()
    }

    // -- the serial op queue ----------------------------------------------

    /// Main queue: take the command the reader admitted and let the queue decide
    /// what happens to it.
    ///
    /// Ordering is the whole point: `center.add` and the removal run one at a
    /// time, each after the previous one completed, so a late `add` can never
    /// undo a later removal — which is the one interleaving a banner must not
    /// have (B6).
    private func enqueue(_ command: Command) {
        // A queued post that a newer post for the same banner replaces would only
        // ever be overwritten on screen, so keep the newest and answer the one it
        // superseded honestly: whether a banner shows is unknown until the
        // survivor completes.
        if case .post(let post) = command,
           let index = pending.firstIndex(where: { queued in
               if case .post(let older) = queued { return older.id == post.id }
               return false
           })
        {
            reject(take(index), reason: "coalesced")
        }
        pending.append(command)
        pump()
    }

    /// Remove one queued command and release the intake slot it holds. One place,
    /// so the slot count cannot drift: a quit never held one.
    private func take(_ index: Int) -> Command {
        let command = pending.remove(at: index)
        if case .quit = command {} else { intakeSlots.signal() }
        return command
    }

    /// Answers a command without running it. Safe from any thread: `Wire` locks.
    private func reject(_ command: Command, reason: String) {
        switch command {
        case .post(let post):
            emitPosted(post, ok: false, denied: false, error: reason)
        case .remove(let seq, let id):
            wire.emit(["type": "removed", "seq": seq, "id": id, "ok": false])
        case .quit:
            break
        }
    }

    private func pump() {
        guard !shuttingDown, !running, !pending.isEmpty else { return }
        let command = take(0)
        running = true
        switch command {
        case .post(let post):
            add(post) { [weak self] error in
                guard let self else { return }
                self.running = false
                if let error {
                    self.emitPosted(post, ok: false, denied: self.notificationsOff || self.notificationsNotAllowed(error), error: "\(error)")
                } else {
                    self.emitPosted(post, ok: true, denied: false, error: "")
                }
                self.pump()
                self.maybeFinishDrain()
            }
        case .remove(let seq, let id):
            // Synchronous and already ordered behind the previous `add`
            // completion, so the acknowledgement is immediate and truthful.
            center.removeDeliveredNotifications(withIdentifiers: [id])
            wire.emit(["type": "removed", "seq": seq, "id": id, "ok": true])
            running = false
            pump()
            maybeFinishDrain()
        case .quit:
            // Nothing queued is owed once the launcher is on its way out; the
            // operations behind a quit are dropped rather than started.
            running = false
            beginShutdown()
        }
    }

    private func add(_ command: PostCommand, completion: @escaping (Error?) -> Void) {
        let content = UNMutableNotificationContent()
        content.title = command.title
        content.subtitle = command.subtitle
        content.body = command.body
        content.threadIdentifier = command.thread
        // No `content.sound`: the specification says sound is off by default, and a
        // banner that may arrive once every 3 s for a guest retrying a blocked host
        // must not be audible. The authorization request above asks for `.alert`
        // alone so the permission prompt never implies sound either.
        content.interruptionLevel = command.passive ? .passive : .active
        content.userInfo = [
            "session": command.click.session,
            "project": command.click.project,
            "state_dir": command.click.stateDir,
            "terminal": command.click.terminal,
        ]
        // `trigger: nil` delivers now: a refusal is news, not a schedule.
        let request = UNNotificationRequest(identifier: command.id, content: content, trigger: nil)
        center.add(request) { error in
            // The completion arrives on an arbitrary queue; every mutation in
            // this class happens on the main queue.
            DispatchQueue.main.async { completion(error) }
        }
    }

    private func emitPosted(_ post: PostCommand, ok: Bool, denied: Bool, error: String) {
        wire.emit([
            "type": "posted",
            "seq": post.seq,
            "id": post.id,
            "ok": ok,
            "denied": denied,
            "error": error,
        ])
    }

    private func notificationsNotAllowed(_ error: Error) -> Bool {
        let error = error as NSError
        return error.domain == UNErrorDomain && error.code == UNError.Code.notificationsNotAllowed.rawValue
    }

    // -- shutdown ----------------------------------------------------------

    /// Two bounds, in the order they can matter: an unanswered first-run dialog
    /// gets `authDrain`, and everything gets `totalDrain` (B6). Nothing claims a
    /// banner was posted while permission is undecided.
    private func beginShutdown() {
        guard !shuttingDown else { return }
        shuttingDown = true
        shutdownStarted = Date()
        if !authSettled {
            DispatchQueue.main.asyncAfter(deadline: .now() + authDrain) { [weak self] in
                self?.maybeFinishDrain()
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + totalDrain) { [weak self] in
            guard let self, self.shuttingDown else { return }
            self.leave()
        }
        maybeFinishDrain()
    }

    private func maybeFinishDrain() {
        guard shuttingDown, !running else { return }
        if !authSettled && Date().timeIntervalSince(shutdownStarted) < authDrain { return }
        leave()
    }

    private func leave() {
        center.delegate = nil
        NSApp.terminate(nil)
    }

    // -- presentation ------------------------------------------------------

    /// A passive update refreshes the entry in Notification Center without
    /// popping a banner; anything else is news the operator has not seen (S1).
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        if notification.request.content.interruptionLevel == .passive {
            completionHandler([.list])
        } else {
            completionHandler([.banner, .list])
        }
    }

    // -- click -------------------------------------------------------------

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        completionHandler()
        guard response.actionIdentifier == UNNotificationDefaultActionIdentifier else { return }
        let userInfo = response.notification.request.content.userInfo
        switch ClickInfo.make(
            session: userInfo["session"],
            project: userInfo["project"],
            stateDir: userInfo["state_dir"],
            terminal: userInfo["terminal"]
        ) {
        case .success(let click):
            open(click)
        case .failure(let reason):
            // A launch that cannot work is not attempted: the reason is the whole
            // record of why the click did nothing (S4).
            wire.emit([
                "type": "open_failed",
                "session": userInfo["session"] as? String ?? "",
                "error": reason,
            ])
            finishColdClick()
        }
    }

    /// Hand the click to Rust, which owns validation, the script and the terminal
    /// argv. Never `execve`: a serving helper must survive its own child, and the
    /// child must not inherit this process's stdin — the launcher's pipe — so all
    /// three standard handles are isolated here.
    private func open(_ click: ClickInfo) {
        guard let launcher = Helper.clickLauncher() else {
            wire.emit([
                "type": "open_failed",
                "session": click.session,
                "error": "the bundle has no sibling bin/agent-vm to open the session",
            ])
            finishColdClick()
            return
        }
        let child = Process()
        child.executableURL = launcher
        child.arguments = [
            "_notify-click",
            "--session", click.session,
            "--project", click.project,
            "--state-dir", click.stateDir,
            "--terminal", click.terminal,
        ]
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice
        child.standardError = Pipe()
        child.terminationHandler = { [weak self] finished in
            let status = finished.terminationStatus
            DispatchQueue.main.async {
                // A launcher that could not open the session says so in its own
                // dialog only if it was asked to; this is the helper's record.
                if status != 0 {
                    self?.wire.emit([
                        "type": "open_failed",
                        "session": click.session,
                        "error": "agent-vm _notify-click exited with status \(status)",
                    ])
                }
                self?.finishColdClick()
            }
        }
        do {
            try child.run()
        } catch {
            wire.emit([
                "type": "open_failed",
                "session": click.session,
                "error": "could not start \(launcher.path): \(error.localizedDescription)",
            ])
            finishColdClick()
        }
    }

    /// `<bundle>/lib/AgentVMNotifier.app` and `<bundle>/bin/agent-vm` are
    /// siblings two levels apart, which is why the generation directory stays
    /// inside `lib/`: the depth is the same whether the `.app` path is resolved
    /// or not (Phase 0 finding 1).
    static func clickLauncher() -> URL? {
        let candidate = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("bin/agent-vm")
        // Executable, not merely present: a copy that lost its mode bits would
        // make every click a launch that fails after the process starts (S5).
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory),
              !isDirectory.boolValue,
              FileManager.default.isExecutableFile(atPath: candidate.path)
        else {
            return nil
        }
        return candidate
    }

    /// A cold click's process ends with its child: nothing is left to serve, and
    /// an idle AppKit process in the operator's process list would be a leak.
    private func finishColdClick() {
        guard !serving else { return }
        leave()
    }
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

enum Mode {
    case version
    case checkBundle
    case serve
    /// Bare launch: LaunchServices replaying a click on a delivered banner.
    case coldClick
}

func modeFor(_ arguments: [String]) -> Mode {
    switch arguments.first {
    case "--version"?: return .version
    case "--check-bundle"?: return .checkBundle
    case "serve"?: return .serve
    default: return .coldClick
    }
}

func bundleVersion() -> String {
    Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
}

/// What a build or a support session can ask of the installed bundle without a
/// GUI session, as one JSON line. The `type` is not a v1 launcher event, which is
/// deliberate: a launcher that reads it must skip it, and skipping unknown
/// events is something v1 already guarantees.
func checkBundle() -> Int32 {
    let identifier = Bundle.main.bundleIdentifier ?? ""
    let launcher = Helper.clickLauncher()
    let ok = identifier == bundleIdentifier && launcher != nil
    var fields: [String: Any] = [
        "type": "check_bundle",
        "bundle_id": identifier,
        "bundle_path": Bundle.main.bundleURL.path,
        "click_launcher": launcher?.path ?? "",
        "ok": ok,
        "error": "",
    ]
    if identifier != bundleIdentifier {
        fields["error"] = "CFBundleIdentifier is \(identifier.isEmpty ? "unreadable" : identifier), not \(bundleIdentifier)"
    } else if launcher == nil {
        fields["error"] = "no executable sibling at bin/agent-vm, so a click could not open a session"
    }
    Wire().emit(fields)
    return ok ? 0 : 1
}

let mode = modeFor(Array(CommandLine.arguments.dropFirst()))

switch mode {
case .version:
    print("agent-vm-notifier \(bundleVersion())")
    exit(0)
case .checkBundle:
    exit(checkBundle())
case .serve, .coldClick:
    // A bare `swiftc` output is not a bundle, and `UNUserNotificationCenter`
    // raises an uncaught exception (exit 134) rather than failing when it has no
    // bundle to register against. A cold click from such a binary has nothing to
    // open anyway, so it says so and leaves (S6). `serve` is exempt because the
    // launcher can only spawn it from the resolved `.app` path.
    let identifier = Bundle.main.bundleIdentifier ?? ""
    if mode == .coldClick, identifier != bundleIdentifier {
        FileHandle.standardError.write(
            Data("agent-vm-notifier: refusing a cold click outside an agent-vm bundle (CFBundleIdentifier is \(identifier.isEmpty ? "missing" : identifier))\n".utf8)
        )
        exit(1)
    }
    let helper = Helper(serving: mode == .serve)
    let application = NSApplication.shared
    application.delegate = helper
    application.setActivationPolicy(.accessory)
    application.run()
    // `NSApp.terminate` already exits; this is the path where the run loop
    // returned without one.
    exit(0)
}
