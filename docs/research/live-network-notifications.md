# Live network approvals: notification and host entry-point options

Research date: 2026-10-09. For [research ticket #298](https://github.com/gregwebs/agent-vm/issues/298) in the confirmed [wayfinder map #296](https://github.com/gregwebs/agent-vm/issues/296). Agent-vm baseline: `88ea07bb8e4b3dfe4959772536f04f44f2fd87e9`.

## Scope and evidence

This is a bounded, primary-source comparison, **not an implementation or UX decision**. Sources below were retrieved using Python/HTTPS; Apple documentation was read through its official documentation JSON endpoints. All platform behavior is **documentation evidence, not exercised behavior**: no notifications, permission prompts, installed handlers, approval endpoints, or desktop sessions were tested. Current local groundwork is supplied by the brief: launcher stderr banners, no OS notification integration; Zellij is only installed in the image. No submodules were initialized or broad codebase investigation performed.

Required experience: the host-side **launcher** effectively disappears after startup; attached guest-app input stays with the guest app. An unapproved request fails immediately; the human can subsequently allow its host for the **session** or **project permanently**, then manually retry or let the application retry. There is no single-request allowance, queued request resumption, Zellij dependency, or GUI implementation in this research. “Session allowance” means the agent-vm launch/session, not the OS login session. Network allowances are distinct from the existing host-wide **credential authorization** vocabulary in [CONTEXT.md](../../CONTEXT.md).

## Bottom line

- macOS has native local notifications and registered actions through UserNotifications (macOS 10.14+). A background app/helper with a stable identity is a practical packaging candidate; `LSUIElement` permits an agent app without a Dock presence. This does not establish that the current signed CLI distribution is already a notification-capable app. [A1][A2][A5][A6]
- Linux has a session-bus notification protocol usable directly or through libnotify. Buttons and hyperlinks are optional capabilities. GNotification offers application activation after the sender exits, with desktop-entry/D-Bus integration. [L1][L2][L3]
- An independently invoked **host CLI in another terminal or SSH connection** is the lowest desktop-dependency approval entry point. Notification actions can navigate to that host surface, but opening a URI, receiving an action name, or possessing a notification ID must not itself authorize a host. This separation is a security conclusion from the invocation mechanisms, not an OS guarantee of human approval. [A7][L1][L4]
- Notifications are advisory. Permission denial, unsupported actions, unavailable desktops, stale sessions and floods must not change fail-closed network behavior. None of the reviewed APIs supplies an application-independent anti-flood policy for this use case. [A2][L1][L3]

## 1. Practical notification transports

| Mechanism | Documented ability | Distribution/lifecycle constraints | Implication for this question |
|---|---|---|---|
| macOS UserNotifications helper/app | Local notifications, categories, action identifiers and delegate responses; actions can be handled in the background. Symbols are available on macOS 10.14+. [A1][A3] | Requires permission for notification interactions; denial is recorded and later requests do not reprompt. Check settings again because users can change them. App-bundle structure includes executable and `Info.plist`; `LSUIElement` hides a background agent from the Dock. [A2][A5][A6] | Can notify without reading the attach terminal. Packaging an identity-bearing helper is plausible, but cold-start callback delivery, installation/registration and bare-CLI support need validation. |
| macOS Standard Additions `display notification` | Script can supply body, title, subtitle and sound; banners/alerts depend on user settings. Alert “Show” opens the notifying app and may run a script app again. [A4] | Uses system scripting rather than adding a native framework dependency to the CLI. The cited API has no custom action callback/target parameter; identity follows the script/app context. [A4] | Practical informational fallback, not evidence of a reliable “open this specific approval” callback for `osascript`. Do not equate title text with agent-vm identity. |
| Linux direct `org.freedesktop.Notifications` / libnotify | `Notify`, returned ID, atomic replacement, close, optional `ActionInvoked` and `ActivationToken`; `GetCapabilities` advertises actions, hyperlinks and persistence. [L1] | Needs the intended user's session bus and notification server; server autostart is optional. Direct protocol integration avoids requiring a `notify-send` executable, but still needs a D-Bus client implementation. [L1][L4] | Small CLI-compatible notification transport. Keep the callback listener alive off the attach input path; a displayed notification is not a persistent callback service. |
| Linux `notify-send` helper process | Current first-party manual: `--action` implies `--wait`, selected action goes to stdout; replacement ID and dedicated output FDs are available. [L5] | Install libnotify's CLI separately or declare it optional; check installed version rather than assuming current flags. Waiting is for the daemon's event, not a terminal prompt. [L5] | A detached/background child can collect navigation events without consuming guest stdin. Capture its output privately, not on guest stdout. Killing the waiter loses this callback route. |
| Linux Gio GNotification + GApplication | Default/button actions; notifications may survive process exit/reboot if the desktop supports it; application activation delivers the action. [L2][L3] | Requires an installed `.desktop` file matching application ID; app should support D-Bus activation for clicks while stopped. Adds GLib/GIO dependency and installable desktop/service integration rather than only a PATH binary. [L2][L4] | Stronger lifecycle option for an invisible launcher and independently activatable host entry point. Persistence is desktop-dependent; never revive a dead session's authority from an old notification. |

### macOS packaging, signing and authentication are separate matters

Apple's notification APIs are documented in terms of an app and its shared notification center. The reviewed docs do **not** establish a supported recipe for invoking them from an arbitrary unbundled Rust CLI, nor a universal requirement that local notifications need Developer ID or notarization. Treat native app/helper packaging as an option to prove, not a claim that adding a bundle ID or signing the existing CLI is sufficient. Apple's bundle documentation explicitly distinguishes command-line tools from application bundles. [A1][A5]

For outside-App-Store Developer ID distribution, Apple's notarization guidance requires notarization for the documented modern macOS distribution case, valid signatures on executables, Developer ID certificate, hardened runtime and secure timestamp. Ad-hoc/local-development signing is not the notarization certificate path. That is **distribution/Gatekeeper trust**, not permission to send notifications or to widen network policy. It does not imply an App Store requirement. Reusing the current runtime's signing arrangement for a notification helper remains unverified. [A8]

`UNNotificationActionOptions.authenticationRequired` is available on macOS; its documented meaning is “only on an unlocked device,” with an unlock prompt before delivery. It is not an attestation of the requested host, allowance scope, or host-only control-channel provenance. Direct authorization from an authenticated notification action would require a separate threat-model decision and native testing; it is not selected here. [A9]

## 2. Entry points into trusted host approval

```text
untrusted guest request -> host denial/event -> advisory notification
           |                                       |
           +-> immediate failure                   +-> navigate / inspect
                                                        |
                                       independent trusted host approval
                                                        |
                                       session or project-permanent policy
                                                        |
                                  new manual/application request -> retry
```

The diagram is the brief's boundary, not a claim about present implementation. Candidate entry points:

1. **Independent host CLI:** human opens another host terminal and invokes the approval command against a host-owned session/project record. Also usable over a separate authenticated SSH connection. No desktop installation is necessary merely to invoke a CLI. This is an architectural option, not proposed command syntax. Never read the launcher's attached terminal, inject keystrokes, or use guest-provided shell text to launch it.
2. **Notification action → separate host terminal:** Linux desktop entries can declare `Terminal=true` and an `Exec` command; D-Bus activation is another route. The desktop specification supplies invocation conventions, not a guarantee of a new tab/window on every terminal. A default-terminal execution proposal exists but explicitly remains proposed; do not assume `xdg-terminal-exec` is installed or a finalized universal interface. [L6][L8] On macOS, `NSWorkspace.openApplication` can launch a specified installed app; that API alone is not a documented “run this approval command in a fresh Terminal window” contract. Automating Terminal via Apple events adds usage-description/automation considerations: Apple's `NSAppleEventsUsageDescription` key is required for apps using APIs that send Apple events. The exact permission and fresh-window behavior needs a focused test. [A10][A11]
3. **Notification action/deep link → installed host approval application/helper:** macOS custom schemes provide navigation, but Apple warns any app can invoke them and multiple apps can register the same scheme, with undefined target selection. Apple's cited guide includes UIKit examples; it establishes the security risk, not the exact AppKit URL-event implementation. Linux desktop entries support MIME registration and application `Open`/action activation. Prefer an explicit installed host program identity where possible; handler registration is an installation artifact, not something an npm PATH shim alone guarantees. [A7][L6] No GUI is implemented; a future GUI can consume the same host control boundary.
4. **Notification link → host-local browser surface (future option):** `xdg-open` opens preferred applications for URLs but is documented for desktop sessions, not root/headless use. Linux body hyperlinks are optional. [L7][L1] A loopback URL is not proof of a human or exclusive process ownership: RFC 8252 §8.3 documents other apps intercepting native-app loopback redirects. This is corroborating threat evidence, not an approval-server specification. Any future web surface needs independent authentication, CSRF/origin protection, non-mutating navigation, host-private binding and explicit confirmation. No web/GUI design is selected or implemented. [S1]

### Host-only authority and spoofing warnings

These are security implications/requirements for later boundary work, **not protections supplied by notification APIs**:

- Treat body/title, project label, destination text and click payload as untrusted. Render escaped/plain text, bound lengths, and show the canonical host and allowance scope from host-owned records at confirmation. Notifications may appear on lock screens; omit credentials, request bodies, URLs with tokens and unnecessary project details. Linux application name/icon/desktop-entry hints are caller-supplied, not cryptographic origin identity. [A2][L1]
- Navigation identifiers must resolve to current host records. Do not authorize directly from a URL query, `Exec` argument, GAction parameter or notification action string. Apple explicitly describes URL schemes as an attack vector; Linux application actions are invocable through D-Bus, not restricted to the notification UI. [A7][L6]
- Validate D-Bus notification signals against the current server owner and expected notification/action IDs; D-Bus provides routing/authentication primitives, not an attestation of human intent. A host UID/peer check alone does not distinguish an untrusted guest if its processes can reach exported host endpoints: the default guest user numerically matches the host user. [L4][CONTEXT.md](../../CONTEXT.md)
- Keep approval transport, cookies/tokens, sockets and durable allowance files out of guest mounts and guest-reachable proxy/published routes. An XDG runtime directory has user-only ownership/mode requirements, but those are not isolation from a guest with access to that directory. Do not expose the desktop bus to the guest. [L9]
- “Project-permanent” is a scope, not permission for the guest's writable project configuration to approve itself. The eventual persistence location and canonical project identity must preserve host ownership. A session allowance ends with that agent-vm session; stale notifications must not apply it to a successor session or another project. Revocation/races must be rechecked by the control boundary before mutation.

## 3. Session, SSH and headless constraints

Linux notifications address a session-scoped service on the **session bus**, not the system bus. An SSH shell might lack that service/environment; even if it can reach an existing user's desktop bus, it is not thereby notifying the SSH client's desktop. D-Bus recommends local session buses and warns against remote TCP sharing. `xdg-open` is desktop-only. Consequently, desktop detection must not be merely “has a TTY”; successful notification submission must not be equated with visibility. [L1][L4][L7][L3]

The macOS docs describe app/user Notification Center permission and delivery, not a guarantee of meaningful UI from an SSH/headless launch. Whether an SSH-launched CLI can route to the right logged-in user's helper, especially with multiple logins, is **unknown here**. Do not silently launch an approval UI in an unrelated login session. [A1][A2]

For either OS, an independently invoked host CLI is a practical non-desktop fallback. A host-owned denial/event list can retain actionable discovery without repeated banners over a guest application's screen; its retention and discovery experience remain questions for the HITL ticket. A notifier may stay running invisibly or activate on demand, but must not own attached terminal input. Losing notification delivery/listener availability must never make requests wait for human input or permit them automatically.

## 4. Coalescing and flood handling

- **Linux:** `replaces_id` atomically updates an active notification; `CloseNotification` removes obsolete ones. `resident` can keep one after action invocation; `persistence` and hyperlinks/actions must be capability-checked. Neither persistence nor residency proves eventual human acknowledgment or callback recovery. [L1]
- **GNotification:** reuse an application notification ID to replace/show it again; send has no guarantee of immediate display or any display. [L3]
- **macOS:** reuse a request identifier to replace a previously scheduled notification; `threadIdentifier` visually groups related notifications. Pending replacement and visual grouping are not proof of non-disruptive replacement of an already delivered banner. Test delivered-notification behavior separately. [A12][A13]
- **Application-level policy still needed:** the reviewed APIs do not specify portable per-project/per-host debounce, quotas, deduplication or denial-event storage. Coalescing distinct events into a bounded summary, limiting guest-triggered floods and suppressing stale notifications are feasible boundary policies, not OS-provided guarantees. Exact grouping key, thresholds, expiry, quiet behavior and escalation are deliberately undecided. Never use critical urgency as a rate-limit bypass or interpret dismissal as network denial/approval.

## 5. Unknowns and questions for the HITL experience ticket

**Focused technical follow-up (not an implementation in this ticket):**

- macOS: prove app/helper identity and permission behavior for a source-built signed bundle and distributable package; compare running/cold/stopped helper callbacks, lock/unlock, notification denial and update/reinstall identity. Verify native action authentication on target releases; do not extrapolate iOS prose to macOS runtime behavior.
- Linux: sample GNOME and KDE plus a minimal desktop; query actual action/hyperlink/persistence capabilities, callback/listener loss, server restart and GApplication cold activation. Verify oldest supported libnotify/GIO versions and package dependencies.
- Both: test two simultaneous agent-vm sessions/projects, expired IDs, hostile payloads, action invocation without a click, guest reachability and project-file mutation. Demonstrate that attached stdin and guest-app screen ownership remain intact. No such tests were run here.

**Human choices still open:**

1. Should a notification open a separate host CLI, an inspection list, or eventually a GUI? Is one-click navigation sufficient, with explicit host/scope confirmation elsewhere?
2. How should headless/SSH users discover failures without recurring launcher stderr interference? Which host/session is responsible for desktop delivery when the launch is remote?
3. What project/session identity and scope wording must be visible before confirmation? How are project-permanent allowances inspected and revoked?
4. What summary grouping, quiet defaults and rate limits are acceptable? How should notification-disabled users learn about the independent host entry point?
5. How should a successful allowance explain that the original request already failed and only a **new retry** can succeed?

## Conclusion

Native macOS app notifications, Linux D-Bus/libnotify, and Linux GNotification activation are practical documented mechanisms with different packaging and lifecycle costs. A separate host CLI remains viable without a desktop and without borrowing attached input. The OS notification layer can advertise and navigate; the host control boundary must own explicit session/project-permanent authorization and immediate-failure/retry semantics. The evidence supports these alternatives, not a choice of UX or a claim that the current distributions already deliver trusted approvals.

## Primary sources

All retrieved 2026-10-09; moving documentation, not pinned runtime versions.

- [A1] Apple, [UNUserNotificationCenter.current()](https://developer.apple.com/documentation/usernotifications/unusernotificationcenter/current()) and [UNNotificationAction](https://developer.apple.com/documentation/usernotifications/unnotificationaction) (including macOS availability).
- [A2] Apple, [Asking permission to use notifications](https://developer.apple.com/documentation/usernotifications/asking-permission-to-use-notifications).
- [A3] Apple, [Declaring actionable notification types](https://developer.apple.com/documentation/usernotifications/declaring-your-actionable-notification-types) and [Handling notifications and actions](https://developer.apple.com/documentation/usernotifications/handling-notifications-and-notification-related-actions). Shared-framework guides contain iOS/watchOS-specific examples; macOS behavior remains unexercised.
- [A4] Apple, [Mac Automation Scripting Guide: Displaying Notifications](https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/DisplayNotifications.html) (archived).
- [A5] Apple, [Bundle Programming Guide: Bundle Structures](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html) (archived).
- [A6] Apple, [LSUIElement](https://developer.apple.com/documentation/bundleresources/information-property-list/lsuielement).
- [A7] Apple, [Defining a custom URL scheme](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app).
- [A8] Apple, [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).
- [A9] Apple, [authenticationRequired](https://developer.apple.com/documentation/usernotifications/unnotificationactionoptions/authenticationrequired).
- [A10] Apple, [NSWorkspace.openApplication](https://developer.apple.com/documentation/appkit/nsworkspace/openapplication(at:configuration:completionhandler:)).
- [A11] Apple, [NSAppleEventsUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nsappleeventsusagedescription).
- [A12] Apple, [UNNotificationRequest.identifier](https://developer.apple.com/documentation/usernotifications/unnotificationrequest/identifier).
- [A13] Apple, [UNMutableNotificationContent.threadIdentifier](https://developer.apple.com/documentation/usernotifications/unmutablenotificationcontent/threadidentifier).
- [L1] freedesktop.org, [Desktop Notifications Specification](https://specifications.freedesktop.org/notification-spec/latest-single/), especially §§2, 4.1, 8, 9.1–9.2.
- [L2] GLib/GIO, [GNotification](https://docs.gtk.org/gio/class.Notification.html).
- [L3] GLib/GIO, [GApplication.send_notification](https://docs.gtk.org/gio/method.Application.send_notification.html).
- [L4] D-Bus maintainers, [D-Bus Specification](https://dbus.freedesktop.org/doc/dbus-specification.html), especially authentication, message routing, activation and TCP transport warnings.
- [L5] GNOME/libnotify, [notify-send manual source](https://gitlab.gnome.org/GNOME/libnotify/-/raw/master/docs/notify-send.xml). Current source flags may not exist in older distro packages.
- [L6] freedesktop.org, [Desktop Entry Specification 1.5](https://specifications.freedesktop.org/desktop-entry-spec/latest-single/), especially §§6–8, 10–11.
- [L7] xdg-utils, [xdg-open manual](https://portland.freedesktop.org/doc/xdg-open.html).
- [L8] xdg-terminal-exec author, [proposal/reference implementation README](https://github.com/Vladimir-csp/xdg-terminal-exec/blob/master/README.md) (proposal, not adopted platform standard).
- [L9] freedesktop.org, [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/), §3.
- [S1] IETF, [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252.html), §8.3. Its OAuth-specific mitigations are not presented as a network-approval design.
