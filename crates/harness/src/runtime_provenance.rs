use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use clap::Args;

const REGISTRY_PREFIX: &str = "registry+https://github.com/rust-lang/crates.io-index";
const FIRMWARE_VERSION: &str = "5.6.1";
const FIRMWARE_ABI: &str = "5";

type Pin = (&'static str, &'static str);
type Pins = BTreeMap<&'static str, Pin>;
type Selected = BTreeMap<String, (String, String, String)>;

fn pins(rows: &[(&'static str, &'static str, &'static str)]) -> Pins {
    rows.iter()
        .map(|(name, version, checksum)| (*name, (*version, *checksum)))
        .collect()
}

fn root_pins() -> Pins {
    pins(&[
        (
            "msb_krun",
            "0.1.42",
            "9cc8c72e61d6342ed8f381f049e5659c3c3c7a2d589eb2407f4abecc5aa633f2",
        ),
        (
            "msb_krun_arch",
            "0.1.42",
            "ac38ac5290daf53011289f0b3420ce69e577db101b39fa4ac8c73869635dc9e1",
        ),
        (
            "msb_krun_arch_gen",
            "0.1.45",
            "bc601bbe7784c2858abd909a4ef7afa79f9f4d5d941e2e21fedb5ca0d4ad46b2",
        ),
        (
            "msb_krun_cpuid",
            "0.1.45",
            "2692ad93a9f3da926d50d5f21e83984fa4fe2345727394da41a4b484e8c7935e",
        ),
        (
            "msb_krun_devices",
            "0.1.42",
            "a030aa4be892ea9b2215c2828d2ce02d77d4b02133f0af6dc842bae5a802ed87",
        ),
        (
            "msb_krun_hvf",
            "0.1.42",
            "b7eafee262ce993bafc612abb3dd6582c102f0f462f15fb22159bf04184dc908",
        ),
        (
            "msb_krun_kernel",
            "0.1.42",
            "51ad8e40e3fe51a18effce0245e099c318e8302e851e7917eef296d46bbe143d",
        ),
        (
            "msb_krun_polly",
            "0.1.42",
            "fad6d7aae45e030546e31349f1c8fe2d257223b95360f84ca80b6bc0ef232f22",
        ),
        (
            "msb_krun_smbios",
            "0.1.45",
            "9a86f61e2babd56b34a1a09fbcd5991b8299f93066b6af897f62b520085f3312",
        ),
        (
            "msb_krun_utils",
            "0.1.42",
            "4b4ecd659171dc62624ff73007f5abdf4fffaf48131ef00fed1ea3d164fb2e6f",
        ),
        (
            "msb_krun_vmm",
            "0.1.42",
            "284e283d6f1b5e5496afe615c6a4912e41b8b0210d40b1e7d4e0647a59ed6175",
        ),
    ])
}

fn nested_pins() -> Pins {
    pins(&[
        (
            "msb_krun",
            "0.1.42",
            "9cc8c72e61d6342ed8f381f049e5659c3c3c7a2d589eb2407f4abecc5aa633f2",
        ),
        (
            "msb_krun_arch",
            "0.1.42",
            "ac38ac5290daf53011289f0b3420ce69e577db101b39fa4ac8c73869635dc9e1",
        ),
        (
            "msb_krun_arch_gen",
            "0.1.42",
            "372c943ecdd64cc741630ff76a4763aad41732f62dba368be0f530b83373ec85",
        ),
        (
            "msb_krun_cpuid",
            "0.1.42",
            "ef38e1dc441567a43111aceade3837b7111d29c1f8c1ca6dd5f4ff82e92b6824",
        ),
        (
            "msb_krun_devices",
            "0.1.42",
            "a030aa4be892ea9b2215c2828d2ce02d77d4b02133f0af6dc842bae5a802ed87",
        ),
        (
            "msb_krun_hvf",
            "0.1.42",
            "b7eafee262ce993bafc612abb3dd6582c102f0f462f15fb22159bf04184dc908",
        ),
        (
            "msb_krun_kernel",
            "0.1.42",
            "51ad8e40e3fe51a18effce0245e099c318e8302e851e7917eef296d46bbe143d",
        ),
        (
            "msb_krun_polly",
            "0.1.42",
            "fad6d7aae45e030546e31349f1c8fe2d257223b95360f84ca80b6bc0ef232f22",
        ),
        (
            "msb_krun_smbios",
            "0.1.42",
            "fdd434257469b722d2920d179a5a927b09e795c95035eca01674c5033bf83caa",
        ),
        (
            "msb_krun_utils",
            "0.1.42",
            "4b4ecd659171dc62624ff73007f5abdf4fffaf48131ef00fed1ea3d164fb2e6f",
        ),
        (
            "msb_krun_vmm",
            "0.1.42",
            "284e283d6f1b5e5496afe615c6a4912e41b8b0210d40b1e7d4e0647a59ed6175",
        ),
    ])
}

#[derive(Debug, Args)]
pub struct RuntimeProvenanceArgs {
    #[arg(long)]
    self_test: bool,
    #[arg(long)]
    repo_root: Option<PathBuf>,
    #[arg(long)]
    root_lock: Option<PathBuf>,
    #[arg(long)]
    nested_lock: Option<PathBuf>,
    #[arg(long)]
    root_manifest: Option<PathBuf>,
    #[arg(long)]
    nested_manifest: Option<PathBuf>,
    #[arg(long)]
    constants: Option<PathBuf>,
    #[arg(long)]
    firmware_dir: Option<PathBuf>,
    #[arg(long)]
    gitlink: Option<String>,
    #[arg(long)]
    gitlink_mode: Option<String>,
    #[arg(long)]
    firmware_head: Option<String>,
    #[arg(long)]
    firmware_dirty: bool,
    #[arg(long)]
    root_metadata: Option<PathBuf>,
    #[arg(long)]
    nested_metadata: Option<PathBuf>,
}

struct Inputs {
    root_lock: PathBuf,
    nested_lock: PathBuf,
    root_manifest: PathBuf,
    nested_manifest: PathBuf,
    constants: PathBuf,
    firmware_dir: PathBuf,
    gitlink: String,
    gitlink_mode: String,
    firmware_head: String,
    firmware_dirty: bool,
    root_metadata: Option<PathBuf>,
    nested_metadata: Option<PathBuf>,
}

impl TryFrom<RuntimeProvenanceArgs> for Inputs {
    type Error = String;

    fn try_from(args: RuntimeProvenanceArgs) -> Result<Self, Self::Error> {
        let required = |value: Option<PathBuf>, name| {
            value.ok_or_else(|| format!("missing required argument --{name}"))
        };
        Ok(Self {
            root_lock: required(args.root_lock, "root-lock")?,
            nested_lock: required(args.nested_lock, "nested-lock")?,
            root_manifest: required(args.root_manifest, "root-manifest")?,
            nested_manifest: required(args.nested_manifest, "nested-manifest")?,
            constants: required(args.constants, "constants")?,
            firmware_dir: required(args.firmware_dir, "firmware-dir")?,
            gitlink: args
                .gitlink
                .ok_or_else(|| "missing required argument --gitlink".to_owned())?,
            gitlink_mode: args
                .gitlink_mode
                .ok_or_else(|| "missing required argument --gitlink-mode".to_owned())?,
            firmware_head: args
                .firmware_head
                .ok_or_else(|| "missing required argument --firmware-head".to_owned())?,
            firmware_dirty: args.firmware_dirty,
            root_metadata: args.root_metadata,
            nested_metadata: args.nested_metadata,
        })
    }
}

pub fn run(args: RuntimeProvenanceArgs) -> Result<String, String> {
    if args.self_test {
        let root = args
            .repo_root
            .as_deref()
            .ok_or_else(|| "--self-test requires --repo-root".to_owned())?;
        self_test(root)?;
        return Ok("runtime provenance tests passed".to_owned());
    }

    let inputs = Inputs::try_from(args)?;
    check(&inputs)?;
    Ok(success_line(&inputs.gitlink))
}

fn parse_toml(path: &Path) -> Result<toml::Value, String> {
    let contents = fs::read_to_string(path).map_err(|error| error.to_string())?;
    toml::from_str(&contents).map_err(|error| error.to_string())
}

fn package_string(package: &toml::value::Table, key: &str) -> String {
    package
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn cohort_packages(path: &Path, pins: &Pins) -> Result<Selected, String> {
    let lock = parse_toml(path)?;
    cohort_packages_value(&lock, pins, &path.display().to_string())
}

fn cohort_packages_value(lock: &toml::Value, pins: &Pins, path: &str) -> Result<Selected, String> {
    let cohort: BTreeSet<_> = pins.keys().copied().collect();
    let unused = lock
        .get("patch")
        .and_then(toml::Value::as_table)
        .and_then(|patch| patch.get("unused"))
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten();
    for package in unused {
        if let Some(name) = package.get("name").and_then(toml::Value::as_str)
            && cohort.contains(name)
        {
            return Err(format!("{path}: unused patch override for {name}"));
        }
    }

    let mut selected = Selected::new();
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(package) = package.as_table() else {
            continue;
        };
        let name = package_string(package, "name");
        if (name == "msb_krun" || name.starts_with("msb_krun_")) && !cohort.contains(name.as_str())
        {
            return Err(format!("{path}: unexpected msb_krun cohort package {name}"));
        }
        let Some((expected_version, expected_checksum)) = pins.get(name.as_str()) else {
            continue;
        };
        let version = package_string(package, "version");
        let source = package_string(package, "source");
        let checksum = package_string(package, "checksum");
        if selected.contains_key(&name) {
            return Err(format!("{path}: duplicate cohort package {name}"));
        }
        if version != *expected_version {
            return Err(format!(
                "{path}: {name} is {version}, expected {expected_version}"
            ));
        }
        if !source.starts_with(REGISTRY_PREFIX) {
            return Err(format!("{path}: {name} has non-registry source '{source}'"));
        }
        if checksum != *expected_checksum {
            return Err(format!(
                "{path}: {name} {version} has checksum '{checksum}', expected {expected_checksum}"
            ));
        }
        selected.insert(name, (version, source, checksum));
    }
    let found: BTreeSet<_> = selected.keys().map(String::as_str).collect();
    if found != cohort {
        let missing: Vec<_> = cohort.difference(&found).collect();
        let extra: Vec<_> = found.difference(&cohort).collect();
        return Err(format!(
            "{path}: cohort mismatch; missing={missing:?}, extra={extra:?}"
        ));
    }
    Ok(selected)
}

fn compare_locks(root: &Selected, nested: &Selected) -> Result<(), String> {
    for (name, (root_version, root_source, root_checksum)) in root {
        let (nested_version, nested_source, nested_checksum) = &nested[name];
        if root_version == nested_version
            && (root_source, root_checksum) != (nested_source, nested_checksum)
        {
            return Err(format!(
                "root and nested Cargo locks disagree on {name} source/checksum"
            ));
        }
    }
    Ok(())
}

fn check_manifest(path: &Path, pins: &Pins) -> Result<(), String> {
    let manifest = parse_toml(path)?;
    check_manifest_value(&manifest, pins, &path.display().to_string())
}

fn check_manifest_value(manifest: &toml::Value, pins: &Pins, path: &str) -> Result<(), String> {
    let cohort: BTreeSet<_> = pins.keys().copied().collect();
    for (table_name, table) in manifest
        .get("patch")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
    {
        let Some(table) = table.as_table() else {
            continue;
        };
        let overlap: Vec<_> = table
            .keys()
            .filter(|name| cohort.contains(name.as_str()))
            .map(String::as_str)
            .collect();
        if !overlap.is_empty() {
            return Err(format!(
                "{path}: patch.{table_name} overrides cohort crate(s): {}",
                overlap.join(", ")
            ));
        }
    }
    Ok(())
}

fn check_metadata(path: &Path, pins: &Pins) -> Result<(), String> {
    let contents = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let metadata: serde_json::Value =
        serde_json::from_str(&contents).map_err(|error| error.to_string())?;
    let cohort: BTreeSet<_> = pins.keys().copied().collect();
    let mut selected = BTreeMap::new();
    for package in metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = package
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if (name == "msb_krun" || name.starts_with("msb_krun_")) && !cohort.contains(name) {
            return Err(format!(
                "{}: unexpected msb_krun cohort package {name}",
                path.display()
            ));
        }
        if !cohort.contains(name) {
            continue;
        }
        if selected.contains_key(name) {
            return Err(format!(
                "{}: cargo metadata has duplicate cohort package {name}",
                path.display()
            ));
        }
        selected.insert(
            name,
            (
                package
                    .get("version")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                package
                    .get("source")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
            ),
        );
    }
    let found: BTreeSet<_> = selected.keys().copied().collect();
    if found != cohort {
        let missing: Vec<_> = cohort.difference(&found).collect();
        let extra: Vec<_> = found.difference(&cohort).collect();
        return Err(format!(
            "{}: metadata cohort mismatch; missing={missing:?}, extra={extra:?}",
            path.display()
        ));
    }
    for (name, (version, source)) in selected {
        let (expected_version, _) = pins[name];
        if version != expected_version || !source.starts_with(REGISTRY_PREFIX) {
            return Err(format!(
                "{}: {name} is {version} from '{source}'; expected registry {expected_version}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn check_firmware(inputs: &Inputs) -> Result<(), String> {
    if inputs.gitlink_mode != "160000" {
        return Err(format!(
            "firmware gitlink mode is '{}', expected '160000'",
            inputs.gitlink_mode
        ));
    }
    if inputs.gitlink.is_empty() {
        return Err("firmware gitlink is empty".to_owned());
    }
    if inputs.firmware_head.is_empty() {
        return Err("firmware recursive submodule is not initialized; run git submodule update --init --recursive".to_owned());
    }
    if inputs.firmware_head != inputs.gitlink {
        return Err(format!(
            "firmware checkout HEAD is {}, expected gitlink {}",
            inputs.firmware_head, inputs.gitlink
        ));
    }
    if inputs.firmware_dirty {
        return Err(
            "firmware source is dirty (tracked modifications or non-ignored untracked files)"
                .to_owned(),
        );
    }
    let constants = fs::read_to_string(&inputs.constants).map_err(|error| error.to_string())?;
    check_constants(&constants)?;
    let patch = fs::read_to_string(
        inputs
            .firmware_dir
            .join("patches/0031-msb-krunfw-increase-kernel-command-line-size.patch"),
    )
    .map_err(|error| error.to_string())?;
    if !patch.contains("COMMAND_LINE_SIZE\t16384") {
        return Err("pinned firmware lacks the 16 KiB command-line patch".to_owned());
    }
    let config = fs::read_to_string(inputs.firmware_dir.join("config-libkrunfw_x86_64"))
        .map_err(|error| error.to_string())?;
    let required = [
        "CONFIG_KVM=y",
        "CONFIG_KVM_INTEL=y",
        "CONFIG_KVM_AMD=y",
        "CONFIG_POSIX_MQUEUE=y",
        "CONFIG_BRIDGE=y",
        "CONFIG_NF_TABLES=y",
    ];
    let missing: Vec<_> = required
        .into_iter()
        .filter(|symbol| !config.contains(symbol))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "pinned firmware lacks required x86 config: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

fn check_constants(constants: &str) -> Result<(), String> {
    if !constants.contains(&format!("LIBKRUNFW_VERSION: &str = \"{FIRMWARE_VERSION}\"")) {
        return Err(format!(
            "firmware version constant is not {FIRMWARE_VERSION}"
        ));
    }
    if !constants.contains(&format!("LIBKRUNFW_ABI: &str = \"{FIRMWARE_ABI}\"")) {
        return Err(format!("firmware ABI constant is not {FIRMWARE_ABI}"));
    }
    Ok(())
}

fn check(inputs: &Inputs) -> Result<(), String> {
    let root_pins = root_pins();
    let nested_pins = nested_pins();
    let root = cohort_packages(&inputs.root_lock, &root_pins)?;
    let nested = cohort_packages(&inputs.nested_lock, &nested_pins)?;
    compare_locks(&root, &nested)?;
    check_manifest(&inputs.root_manifest, &root_pins)?;
    check_manifest(&inputs.nested_manifest, &root_pins)?;
    check_firmware(inputs)?;
    match (&inputs.root_metadata, &inputs.nested_metadata) {
        (None, None) => Ok(()),
        (Some(root), Some(nested)) => {
            check_metadata(root, &root_pins)?;
            check_metadata(nested, &nested_pins)
        }
        _ => Err("both cargo metadata files are required in full mode".to_owned()),
    }
}

fn success_line(gitlink: &str) -> String {
    let root_versions: BTreeSet<_> = root_pins().values().map(|(version, _)| *version).collect();
    let nested_versions: BTreeSet<_> = nested_pins()
        .values()
        .map(|(version, _)| *version)
        .collect();
    format!(
        "runtime provenance: per-lock registry pins, root {} / nested {}; firmware {} version {FIRMWARE_VERSION} ABI {FIRMWARE_ABI}",
        root_versions.into_iter().collect::<Vec<_>>().join("/"),
        nested_versions.into_iter().collect::<Vec<_>>().join("/"),
        gitlink.chars().take(12).collect::<String>()
    )
}

fn fixture_inputs(root: &Path) -> Inputs {
    let gitlink = "fixture-gitlink".to_owned();
    Inputs {
        root_lock: root.join("Cargo.lock"),
        nested_lock: root.join("vendor/microsandbox/Cargo.lock"),
        root_manifest: root.join("Cargo.toml"),
        nested_manifest: root.join("vendor/microsandbox/Cargo.toml"),
        constants: root.join("vendor/microsandbox/crates/utils/lib/lib.rs"),
        firmware_dir: root.join("vendor/microsandbox/vendor/libkrunfw"),
        gitlink: gitlink.clone(),
        gitlink_mode: "160000".to_owned(),
        firmware_head: gitlink,
        firmware_dirty: false,
        root_metadata: None,
        nested_metadata: None,
    }
}

fn mutate_package(contents: &str, name: &str, from: &str, to: &str) -> String {
    let start = contents
        .find(&format!("name = \"{name}\""))
        .expect("checked-in lock has the package");
    let end = contents[start..]
        .find("[[package]]")
        .map_or(contents.len(), |offset| start + offset);
    let mut result = contents.to_owned();
    result.replace_range(start..end, &contents[start..end].replacen(from, to, 1));
    result
}

fn expect_result(label: &str, expected: &str, result: Result<(), String>) -> Result<(), String> {
    match result {
        Ok(()) => Err(format!("expected failure: {label}")),
        Err(error) if error.contains(expected) => Ok(()),
        Err(error) => Err(format!("{label}: missing {expected:?} in: {error}")),
    }
}

fn expect_failure(label: &str, expected: &str, inputs: &Inputs) -> Result<(), String> {
    expect_result(label, expected, check(inputs))
}

fn self_test(root: &Path) -> Result<(), String> {
    let inputs = fixture_inputs(root);
    check(&inputs)?;

    let root_lock = fs::read_to_string(&inputs.root_lock).map_err(|error| error.to_string())?;
    let nested_lock = fs::read_to_string(&inputs.nested_lock).map_err(|error| error.to_string())?;
    let root_manifest =
        fs::read_to_string(&inputs.root_manifest).map_err(|error| error.to_string())?;
    let constants = fs::read_to_string(&inputs.constants).map_err(|error| error.to_string())?;

    let mut case = fixture_inputs(root);
    case.root_lock = PathBuf::from("mutated root version");
    let root_version = mutate_package(
        &root_lock,
        "msb_krun",
        "version = \"0.1.42\"",
        "version = \"0.1.40\"",
    );
    expect_lock_failure(
        "root version",
        "msb_krun is 0.1.40",
        &case,
        &root_version,
        true,
    )?;

    let root_source = mutate_package(
        &root_lock,
        "msb_krun",
        REGISTRY_PREFIX,
        "git+https://example.invalid/msb",
    );
    expect_lock_failure(
        "root source",
        "non-registry source",
        &case,
        &root_source,
        true,
    )?;

    let root_checksum = mutate_package(
        &root_lock,
        "msb_krun",
        "checksum = \"",
        "checksum = \"different-",
    );
    expect_lock_failure(
        "root checksum",
        "msb_krun 0.1.42 has checksum",
        &case,
        &root_checksum,
        true,
    )?;

    for (side, lock, package, version) in [
        (true, &root_lock, "msb_krun_arch_gen", "0.1.45"),
        (false, &nested_lock, "msb_krun_smbios", "0.1.42"),
    ] {
        let mutated = mutate_package(lock, package, "checksum = \"", "checksum = \"different-");
        expect_lock_failure(
            "split checksum",
            &format!("{package} {version} has checksum"),
            &case,
            &mutated,
            side,
        )?;
    }

    expect_text_failure(
        "patch override",
        "overrides cohort crate",
        &(root_manifest + "\n[patch.crates-io]\nmsb_krun = \"0.1.42\"\n"),
        TextInput::RootManifest,
    )?;

    for (side, lock, package, from, target) in [
        (true, &root_lock, "msb_krun_arch_gen", "0.1.45", "0.1.42"),
        (false, &nested_lock, "msb_krun_smbios", "0.1.42", "0.1.45"),
    ] {
        for target in [target, "0.1.44"] {
            let mutated = mutate_package(
                lock,
                package,
                &format!("version = \"{from}\""),
                &format!("version = \"{target}\""),
            );
            expect_lock_failure(
                "per-lock version",
                &format!("{package} is {target}"),
                &case,
                &mutated,
                side,
            )?;
        }
    }

    let source_suffix = mutate_package(
        &root_lock,
        "msb_krun_utils",
        "crates.io-index",
        "crates.io-index#other",
    );
    expect_lock_failure(
        "source suffix",
        "disagree on msb_krun_utils source/checksum",
        &case,
        &source_suffix,
        true,
    )?;
    let nested_checksum = mutate_package(
        &nested_lock,
        "msb_krun_utils",
        "checksum = \"",
        "checksum = \"different-",
    );
    expect_lock_failure(
        "nested checksum",
        "msb_krun_utils 0.1.42 has checksum",
        &case,
        &nested_checksum,
        false,
    )?;

    let mut firmware_case = fixture_inputs(root);
    firmware_case.gitlink_mode = "100644".to_owned();
    expect_failure("gitlink mode", "firmware gitlink mode is", &firmware_case)?;
    firmware_case = fixture_inputs(root);
    firmware_case.gitlink = "deadbeef".to_owned();
    expect_failure("gitlink", "expected gitlink deadbeef", &firmware_case)?;
    firmware_case = fixture_inputs(root);
    firmware_case.firmware_head.clear();
    expect_failure(
        "firmware head",
        "recursive submodule is not initialized",
        &firmware_case,
    )?;
    firmware_case = fixture_inputs(root);
    firmware_case.firmware_dirty = true;
    expect_failure("dirty firmware", "source is dirty", &firmware_case)?;

    expect_text_failure(
        "firmware ABI",
        "ABI constant is not 5",
        &constants.replacen(
            "LIBKRUNFW_ABI: &str = \"5\"",
            "LIBKRUNFW_ABI: &str = \"9\"",
            1,
        ),
        TextInput::Constants,
    )
}

enum TextInput {
    RootManifest,
    Constants,
}

fn expect_text_failure(
    label: &str,
    expected: &str,
    contents: &str,
    input: TextInput,
) -> Result<(), String> {
    match input {
        TextInput::RootManifest => {
            let parsed = toml::from_str(contents).map_err(|error| error.to_string())?;
            expect_result(
                label,
                expected,
                check_manifest_value(&parsed, &root_pins(), "mutated manifest"),
            )
        }
        TextInput::Constants => expect_result(label, expected, check_constants(contents)),
    }
}

fn expect_lock_failure(
    label: &str,
    expected: &str,
    inputs: &Inputs,
    contents: &str,
    root_lock: bool,
) -> Result<(), String> {
    let parsed = toml::from_str(contents).map_err(|error| error.to_string())?;
    let pins = if root_lock {
        root_pins()
    } else {
        nested_pins()
    };
    match cohort_packages_value(&parsed, &pins, "mutated lock") {
        Ok(selected) => {
            let other = if root_lock {
                cohort_packages(&inputs.nested_lock, &nested_pins())?
            } else {
                cohort_packages(&inputs.root_lock, &root_pins())?
            };
            let comparison = if root_lock {
                compare_locks(&selected, &other)
            } else {
                compare_locks(&other, &selected)
            };
            match comparison {
                Ok(()) => Err(format!("expected failure: {label}")),
                Err(error) if error.contains(expected) => Ok(()),
                Err(error) => Err(format!("{label}: missing {expected:?} in: {error}")),
            }
        }
        Err(error) if error.contains(expected) => Ok(()),
        Err(error) => Err(format!("{label}: missing {expected:?} in: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_provenance_rejects_each_ported_lock_mutation() {
        self_test(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .as_path(),
        )
        .unwrap();
    }
}
