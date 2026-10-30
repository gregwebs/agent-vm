//! A complete fake runtime **pair** for agent-vm's boot-free harnesses.
//!
//! Harnesses include this with `#[path = "support/fake_msb.rs"] mod fake_msb;`
//! rather than through `support`, so only test crates that spawn a fake runtime
//! compile it. Each crate uses a different subset, hence the `dead_code`
//! allowance.
//!
//! The pair matters: 0.7.4's runtime resolver refuses an `msb` with no adjacent
//! `libkrunfw` ("has no matching libkrunfw"), so a version-only script is not a
//! usable launch seam. [`install_pair`] always writes the platform-named
//! library beside the executable. The library's contents are never read — the
//! resolver checks existence — so no real runtime capability is faked.
//!
//! Three script modes keep each harness's negative oracle calibrated:
//!
//! - [`Mode::VersionOnly`] answers any invocation with the version line.
//! - [`Mode::StrictAcquisition`] answers `--version`, logs every other argv and
//!   exits 93. Boot-free acquisition tests assert no non-version invocation
//!   happened (no VM, no Docker, no host download).
//! - [`Mode::LaunchSeam`] additionally answers `__launch-protocol` with the
//!   exact launch contract a credential-bearing create requires, then fails
//!   every other invocation with 93. It reaches builder/create and the SDK's
//!   native cache consumption, and **never** fakes a successful VM.
//!
//! Docker/buildx/curl/wget decoys stay separate: a host fallback would be a
//! different program, and conflating it with the runtime would hide it.

#![allow(dead_code)]

use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// What the vendored runtime prints for `msb --version`. `point_at_msb`
/// refuses any other version, so this is the one literal to change when the
/// `vendor/microsandbox` pin moves to a new version. It cannot come from
/// `msb_install::expected_msb_version()`: these are black-box tests that spawn
/// the compiled binary and do not link the crate. If it drifts, every harness
/// fails at `point_at_msb`.
pub const VERSION_LINE: &str = "msb 0.7.11";

/// Launch capabilities of the packaged runtime with `net` enabled. Both fakes
/// share this source; the contract test compares it to the bundled CLI handler.
const PROTOCOL_JSON: &str = r#"{"protocols":[2,1],"required_restore_backing":true,"header_credentials":true,"tcp_accept_queue_size":true,"max_inbound_tcp_connections":true,"http_deny_message":true,"http_deny_json":true,"http_connect_proxy":true,"http_connect_proxy_auth":true,"proxy_from_env":true,"guest_clock":true,"fs_state_limit":true,"exec_limits":true}"#;

/// How the fake runtime answers an invocation other than `--version`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Answer everything with the version line (the historical fixture).
    VersionOnly,
    /// Log and fail 93 (a strict acquisition decoy: nothing may launch).
    StrictAcquisition,
    /// Answer the launch-protocol probe, then log and fail 93 for everything
    /// else, so builder/create and native cache consumption are reached.
    LaunchSeam,
}

/// The installed pair and its observation logs.
#[derive(Clone, Debug)]
pub struct FakeMsb {
    pub path: PathBuf,
    /// Every non-`--version` argv, one per line.
    pub invocations: PathBuf,
    /// The environment of every invocation (newline-separated `KEY=VALUE`).
    pub environ: PathBuf,
    /// The adjacent runtime library the resolver requires.
    pub library: PathBuf,
}

/// Write `contents` to `path` as a mode-0755 executable.
///
/// Writes a uniquely named temporary and renames it into place. The rename is
/// atomic replacement, so a reader never sees a half-written script and a test
/// can rewrite a running shim without the writer side failing on `ETXTBSY`. It
/// does not narrow the `execve` race: `ETXTBSY` checks the inode's write count,
/// and `rename` keeps the inode, so a concurrent `fork` that duplicates the
/// temporary's write descriptor still blocks an immediate `exec` of `path`.
/// That race is kernel timing, so a caller that immediately `exec`s the result
/// retries on `ExecutableFileBusy`.
pub fn write_executable(path: &Path, contents: &str) {
    let temp = temp_path(path);
    let result = (|| -> std::io::Result<()> {
        std::fs::write(&temp, contents)?;
        let mut perms = std::fs::metadata(&temp)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&temp, perms)?;
        std::fs::rename(&temp, path)
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temp);
        panic!("write_executable({}) failed: {error}", path.display());
    }
}

/// A process-unique sibling of `path`, so parallel tests writing the same
/// fixture name cannot collide on the temporary.
fn temp_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "fixture".to_owned());
    name.push_str(&format!(".{}.{unique}.tmp", std::process::id()));
    path.with_file_name(name)
}

/// Install the complete `msb` + `libkrunfw` pair in `dir` in `mode`.
///
/// Logs are siblings of the executable (`msb-invocations.log`,
/// `msb-environ.log`) by default; use [`install_pair_with_logs`] to point them
/// elsewhere.
pub fn install_pair(dir: &Path, mode: Mode) -> FakeMsb {
    install_pair_with_logs(
        dir,
        mode,
        &dir.join("msb-invocations.log"),
        &dir.join("msb-environ.log"),
    )
}

/// [`install_pair`] with explicit log paths (e.g. a harness-owned call log).
pub fn install_pair_with_logs(
    dir: &Path,
    mode: Mode,
    invocations: &Path,
    environ: &Path,
) -> FakeMsb {
    let path = dir.join("msb");
    let script = match mode {
        Mode::VersionOnly => format!("#!/bin/sh\necho '{VERSION_LINE}'\nexit 0\n"),
        Mode::StrictAcquisition => format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"--version\" ]; then echo '{VERSION_LINE}'; exit 0; fi\n\
             printf '%s\\n' \"$*\" >> '{log}'\n\
             exit 93\n",
            log = invocations.display()
        ),
        Mode::LaunchSeam => format!(
            "#!/bin/sh\n\
             echo \"$*\" >> '{log}'\n\
             env >> '{environ}'\n\
             if [ \"$1\" = \"--version\" ]; then echo '{VERSION_LINE}'; exit 0; fi\n\
             if [ \"$1\" = \"__launch-protocol\" ]; then\n\
             \x20 echo '{PROTOCOL_JSON}'\n\
             \x20 exit 0\n\
             fi\n\
             exit 93\n",
            log = invocations.display(),
            environ = environ.display()
        ),
    };
    write_executable(&path, &script);
    // Name is platform-specific (`libkrunfw.5.dylib` on macOS,
    // `libkrunfw.so.<version>` elsewhere); nothing reads its contents.
    let library = dir.join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));
    if !library.exists() {
        std::fs::write(&library, b"fixture").expect("write the adjacent libkrunfw fixture");
    }
    FakeMsb {
        path,
        invocations: invocations.to_path_buf(),
        environ: environ.to_path_buf(),
        library,
    }
}

/// Install a **real** `msb` fixture binary that the SDK recognises as a modern
/// runtime, then fails every actual launch.
///
/// A shell script cannot satisfy the SDK's launch-contract selection: it reads
/// the Cargo version from an embedded `__msbver` (Mach-O) / `.msbver` (ELF)
/// section and otherwise falls back to a previous-launch contract that rejects
/// 0.7.x. Without a real binary, `create` fails before the runtime and the
/// native cache consumption the barrier tests order against is never reached.
///
/// So this fixture is compiled once per harness with `rustc` (available wherever
/// Cargo is) from a source this module owns. It answers `--version` and
/// `__launch-protocol` exactly, logs every invocation, and exits 93 for
/// everything else — it never fakes a successful VM.
pub fn install_launch_binary(dir: &Path, invocations: &Path, environ: &Path) -> FakeMsb {
    let source = dir.join("msb-fixture.rs");
    let binary = dir.join("msb");
    let literal = |path: &Path| format!("{:?}", path.to_string_lossy());
    let version_literal = format!("{VERSION_LINE:?}");
    let runtime_version = VERSION_LINE
        .strip_prefix("msb ")
        .expect("VERSION_LINE is `<program> <version>`");
    let body = format!(
        r##"
#[used]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__TEXT,__msbver"))]
#[cfg_attr(any(target_os = "linux", target_os = "windows"), unsafe(link_section = ".msbver"))]
static MSB_VERSION: [u8; {version_len}] = {version_bytes:?};

const PROTOCOL_JSON: &str = {protocol_json:?};

fn main() {{
    // Keep the embedded section reachable through linker garbage collection.
    let _ = std::hint::black_box(&MSB_VERSION);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let first = args.first().cloned().unwrap_or_default();
    if let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open({invocations})
    {{
        use std::io::Write as _;
        let _ = writeln!(log, "{{}}", args.join(" "));
    }}
    if let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open({environ})
    {{
        use std::io::Write as _;
        for (key, value) in std::env::vars() {{
            let _ = writeln!(log, "{{key}}={{value}}");
        }}
    }}
    if first == "--version" {{
        println!("{{}}", {version_literal});
        return;
    }}
    if first == "__launch-protocol" {{
        println!("{{}}", PROTOCOL_JSON);
        return;
    }}
    // A real launch (the SDK's `machine` entry point) must fail: this fixture
    // is evidence of cache consumption, never of a working VM.
    std::process::exit(93);
}}
"##,
        protocol_json = PROTOCOL_JSON,
        version_len = runtime_version.len(),
        version_bytes = runtime_version.as_bytes(),
        invocations = literal(invocations),
        environ = literal(environ),
        version_literal = version_literal,
    );
    std::fs::write(&source, body).expect("write the runtime fixture source");
    let output = std::process::Command::new("rustc")
        .arg("--edition")
        .arg("2021")
        .arg("-O")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("rustc is required to build the launch-runtime fixture");
    assert!(
        output.status.success(),
        "building the launch-runtime fixture failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let library = dir.join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));
    if !library.exists() {
        std::fs::write(&library, b"fixture").expect("write the adjacent libkrunfw fixture");
    }
    FakeMsb {
        path: binary,
        invocations: invocations.to_path_buf(),
        environ: environ.to_path_buf(),
        library,
    }
}

/// Write `dir/msb` in [`Mode::VersionOnly`] and return its path.
///
/// Kept as the minimal fixture for harnesses that only need `--version` to
/// satisfy `point_at_msb`. It installs the complete pair too, so a harness that
/// later reaches the runtime does not fail for a fixture reason.
pub fn write(dir: &Path) -> PathBuf {
    install_pair(dir, Mode::VersionOnly).path
}

/// Write an executable decoy for a host fallback program (`docker`, `buildx`,
/// `curl`, `wget`), logging every call to `log` and failing with `code`.
pub fn write_decoy(path: &Path, log: &Path, code: i32) {
    write_executable(
        path,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$0 $*\" >> '{log}'\nexit {code}\n",
            log = log.display()
        ),
    );
}

/// Create `dir` (0700) if needed, for fixtures that write into it directly.
pub fn ensure_private_dir(dir: &Path) {
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("create {}: {error}", dir.display()),
    }
}

/// Run a freshly installed fixture, retrying the kernel's `ETXTBSY` race.
///
/// `execve` refuses a file that is still open for writing by any process,
/// including a write descriptor another thread duplicated across `fork`. The
/// installer already renames into place, which closes the window for its own
/// descriptor; this bounds the remaining kernel-timing race instead of turning
/// a parallel test into an intermittent failure. Every other error is final,
/// and a retry never masks a fixture that did run.
pub fn output_retrying_busy(mut command: std::process::Command) -> std::process::Output {
    const ATTEMPTS: usize = 50;
    const DELAY: std::time::Duration = std::time::Duration::from_millis(10);
    let mut attempt = 0;
    loop {
        attempt += 1;
        match command.output() {
            Ok(output) => return output,
            Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) && attempt < ATTEMPTS => {
                std::thread::sleep(DELAY);
            }
            Err(error) => panic!("running the fixture failed after {attempt} attempts: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mode_installs_a_complete_pair() {
        for mode in [Mode::VersionOnly, Mode::StrictAcquisition, Mode::LaunchSeam] {
            let dir = tempfile::tempdir().unwrap();
            let fixture = install_pair(dir.path(), mode);
            assert!(fixture.path.exists());
            assert!(
                fixture.library.exists(),
                "{mode:?} must install the adjacent libkrunfw"
            );
            let output = output_retrying_busy({
                let mut command = std::process::Command::new(&fixture.path);
                command.arg("--version");
                command
            });
            assert!(output.status.success());
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), VERSION_LINE);
        }
    }

    #[test]
    fn strict_acquisition_fails_every_non_version_call_and_logs_it() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = install_pair(dir.path(), Mode::StrictAcquisition);
        let output = output_retrying_busy({
            let mut command = std::process::Command::new(&fixture.path);
            command.arg("image");
            command
        });
        assert_eq!(output.status.code(), Some(93));
        assert_eq!(
            std::fs::read_to_string(&fixture.invocations)
                .unwrap()
                .trim(),
            "image"
        );
    }

    #[test]
    fn launch_capabilities_match_the_bundled_net_runtime_handler() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../vendor/microsandbox/crates/cli/bin/main.rs"),
        )
        .unwrap();
        let handler = source
            .split_once("Commands::LaunchProtocol => {")
            .unwrap()
            .1;
        let fields = handler
            .split_once("LaunchCapabilities {")
            .unwrap()
            .1
            .split_once("})")
            .unwrap()
            .0;
        let mut actual = serde_json::Map::new();
        let mut net_gated = 0;
        for line in fields
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let (name, value) = line.trim_end_matches(',').split_once(':').unwrap();
            let value = value.trim();
            let parsed = if value == "cfg!(feature = \"net\")" {
                // The fixture models the packaged net-enabled binary, not a
                // minimal no-net build. Never silently accept other cfgs.
                net_gated += 1;
                serde_json::Value::Bool(true)
            } else if let Some(array) = value.strip_prefix("vec!") {
                serde_json::from_str(array).expect("literal protocol array")
            } else {
                assert!(
                    matches!(value, "true" | "false"),
                    "unknown capability expression: {line}"
                );
                serde_json::from_str(value).unwrap()
            };
            assert!(actual.insert(name.trim().to_owned(), parsed).is_none());
        }
        assert_eq!(
            net_gated, 6,
            "review feature-gating changes at a vendor bump"
        );
        assert_eq!(
            serde_json::Value::Object(actual),
            serde_json::from_str::<serde_json::Value>(PROTOCOL_JSON).unwrap()
        );
    }

    #[test]
    fn launch_seam_answers_the_protocol_and_never_fakes_a_vm() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = install_pair(dir.path(), Mode::LaunchSeam);
        let protocol = output_retrying_busy({
            let mut command = std::process::Command::new(&fixture.path);
            command.arg("__launch-protocol");
            command
        });
        assert!(protocol.status.success());
        let body: serde_json::Value = serde_json::from_slice(&protocol.stdout).unwrap();
        assert_eq!(
            body,
            serde_json::from_str::<serde_json::Value>(PROTOCOL_JSON).unwrap()
        );
        let launch = output_retrying_busy({
            let mut command = std::process::Command::new(&fixture.path);
            command.arg("__run");
            command
        });
        assert_eq!(launch.status.code(), Some(93));
        let log = std::fs::read_to_string(&fixture.invocations).unwrap();
        assert!(log.contains("__launch-protocol"), "{log}");
        assert!(log.contains("__run"), "{log}");
    }
}
