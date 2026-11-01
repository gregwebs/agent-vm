// PROTOTYPE — throwaway spike for "Try host OS notifications for sandbox blocks".
// A background (LSUIElement) app that posts native notifications and, on click,
// opens a host terminal showing one session's blocks. A click only navigates.
//
//   serve   read {"op":"post"|"remove"|"quit",...} JSON lines on stdin
//   (none)  launched by macOS for a click while not running; handle it, then quit
import AppKit
import UserNotifications

let protoDir = "/tmp/PROTOTYPE-agent-vm-blocks"
let protoRoot = Bundle.main.object(forInfoDictionaryKey: "ProtoRoot") as? String ?? ""

func emit(_ obj: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: obj),
          let line = String(data: data, encoding: .utf8) else { return }
    print(line)
    fflush(stdout)
    try? FileManager.default.createDirectory(atPath: protoDir, withIntermediateDirectories: true)
    if let h = FileHandle(forWritingAtPath: protoDir + "/notifier.log") ?? {
        FileManager.default.createFile(atPath: protoDir + "/notifier.log", contents: nil)
        return FileHandle(forWritingAtPath: protoDir + "/notifier.log")
    }() {
        h.seekToEndOfFile()
        h.write((line + "\n").data(using: .utf8)!)
        h.closeFile()
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    let center = UNUserNotificationCenter.current()

    func applicationDidFinishLaunching(_ note: Notification) {
        center.delegate = self
        let serving = CommandLine.arguments.contains("serve")
        emit(["type": "launched", "serving": serving, "pid": getpid()])
        center.requestAuthorization(options: [.alert, .sound]) { granted, err in
            self.center.getNotificationSettings { s in
                emit(["type": "auth", "granted": granted,
                      "status": ["notDetermined", "denied", "authorized", "provisional", "ephemeral"][min(Int(s.authorizationStatus.rawValue), 4)],
                      "alertStyle": ["none", "banner", "alert"][min(Int(s.alertStyle.rawValue), 2)],
                      "error": err?.localizedDescription ?? ""])
            }
        }
        if serving {
            Thread.detachNewThread {
                while let line = readLine() {
                    guard let d = line.data(using: .utf8),
                          let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
                    DispatchQueue.main.async { self.handle(o) }
                }
                emit(["type": "stdin-closed"])
            }
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 15) { NSApp.terminate(nil) }
        }
    }

    func handle(_ o: [String: Any]) {
        let id = o["id"] as? String ?? ""
        switch o["op"] as? String {
        case "post":
            let c = UNMutableNotificationContent()
            c.title = o["title"] as? String ?? ""
            c.subtitle = o["subtitle"] as? String ?? ""
            c.body = o["body"] as? String ?? ""
            c.threadIdentifier = o["thread"] as? String ?? ""
            c.userInfo = ["session": o["session"] as? String ?? ""]
            c.interruptionLevel = (o["passive"] as? Bool ?? false) ? .passive : .active
            if o["sound"] as? Bool ?? false { c.sound = .default }
            center.add(UNNotificationRequest(identifier: id, content: c, trigger: nil)) { err in
                emit(["type": "posted", "id": id, "error": err?.localizedDescription ?? ""])
            }
        case "remove":
            center.removeDeliveredNotifications(withIdentifiers: [id])
        case "quit":
            NSApp.terminate(nil)
        default:
            break
        }
    }

    func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification,
                                withCompletionHandler h: @escaping (UNNotificationPresentationOptions) -> Void) {
        h([.banner, .list, .sound])
    }

    func userNotificationCenter(_ c: UNUserNotificationCenter, didReceive r: UNNotificationResponse,
                                withCompletionHandler h: @escaping () -> Void) {
        let session = r.notification.request.content.userInfo["session"] as? String ?? ""
        emit(["type": "click", "action": r.actionIdentifier, "session": session])
        if r.actionIdentifier == UNNotificationDefaultActionIdentifier {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            p.arguments = [protoRoot + "/open-terminal.sh", session]
            do { try p.run() } catch { emit(["type": "open-failed", "error": "\(error)"]) }
        }
        h()
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
