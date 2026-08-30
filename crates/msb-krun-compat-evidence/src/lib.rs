use anyhow::{Context, Result, bail};
use dec_from_char::DecimalExtended;
use serde::{Deserialize, Serialize};
use serde_json::{
    Number,
    ser::{Formatter, PrettyFormatter},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Fdt {
    pub interrupts_hex: String,
    pub path: String,
    pub reg_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Virtio {
    pub device: String,
    pub driver: String,
    pub modalias: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Mount {
    pub filesystem: String,
    pub mountpoint: String,
    pub raw: String,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Discovery {
    pub cmdline_bytes: Option<Number>,
    pub fdt: Vec<Fdt>,
    pub mounts: Vec<Mount>,
    pub virtio: Vec<Virtio>,
}

#[derive(Deserialize)]
struct Baseline {
    fdt: Vec<Fdt>,
    virtio: Vec<Virtio>,
}

pub struct DiscoveryRequest<'a> {
    pub guest_log: &'a Path,
    pub output: &'a Path,
    pub expected_mounts: usize,
    pub selected_indexes: Vec<usize>,
    pub baseline: Option<&'a Path>,
}

pub struct ManifestRequest<'a> {
    pub output: &'a Path,
    pub mode: &'a str,
    pub host_os: &'a str,
    pub host_arch: &'a str,
    pub binary: &'a Path,
    pub firmware: &'a Path,
    pub image: &'a str,
    pub image_platform: &'a str,
    pub started_at: f64,
}

pub struct ObservationsRequest<'a> {
    pub output: &'a Path,
    pub host_os: &'a str,
    pub host_arch: &'a str,
    pub last_good: usize,
    pub first_failure: usize,
    pub repeats: usize,
    pub failure_reason: &'a str,
}

struct GuestLogParser {
    current_line: Vec<u8>,
    discovery: Discovery,
    skip_lf_after_cr: bool,
}

impl GuestLogParser {
    fn new() -> Self {
        Self {
            current_line: Vec::new(),
            discovery: Discovery {
                cmdline_bytes: None,
                fdt: vec![],
                mounts: vec![],
                virtio: vec![],
            },
            skip_lf_after_cr: false,
        }
    }

    fn accept(&mut self, byte: u8) {
        match byte {
            b'\r' => {
                self.parse_current_line();
                self.skip_lf_after_cr = true;
            }
            b'\n' if self.skip_lf_after_cr => self.skip_lf_after_cr = false,
            b'\n' => self.parse_current_line(),
            _ => {
                self.skip_lf_after_cr = false;
                self.current_line.push(byte);
            }
        }
    }

    fn parse_current_line(&mut self) {
        let line = String::from_utf8_lossy(&self.current_line);
        parse_guest_line(&line, &mut self.discovery);
        self.current_line.clear();
    }

    fn finish(mut self) -> Discovery {
        if !self.current_line.is_empty() {
            self.parse_current_line();
        }
        self.discovery
    }
}

/// Python's text reader used universal newline handling and replacement decoding.
/// Retaining those rules keeps guest byte streams from changing retained evidence.
pub fn parse_guest_log(bytes: &[u8]) -> Discovery {
    let mut parser = GuestLogParser::new();
    for &byte in bytes {
        parser.accept(byte);
    }
    parser.finish()
}

fn parse_guest_log_file(path: &Path) -> Result<Discovery> {
    let file = File::open(path).with_context(|| format!("read guest log {}", path.display()))?;
    let mut input = BufReader::new(file);
    let mut parser = GuestLogParser::new();

    loop {
        let consumed = {
            let bytes = input
                .fill_buf()
                .with_context(|| format!("read guest log {}", path.display()))?;
            if bytes.is_empty() {
                break;
            }
            for &byte in bytes {
                parser.accept(byte);
            }
            bytes.len()
        };
        input.consume(consumed);
    }

    Ok(parser.finish())
}

fn parse_guest_line(line: &str, result: &mut Discovery) {
    if let Some(rest) = line.strip_prefix("FDT|") {
        let mut parts = rest.splitn(3, '|');
        if let (Some(path), Some(reg_hex), Some(interrupts_hex)) =
            (parts.next(), parts.next(), parts.next())
        {
            result.fdt.push(Fdt {
                interrupts_hex: interrupts_hex.into(),
                path: path.into(),
                reg_hex: reg_hex.into(),
            });
        }
    } else if let Some(rest) = line.strip_prefix("VIRTIO|") {
        let mut parts = rest.splitn(3, '|');
        if let (Some(device), Some(modalias), Some(driver)) =
            (parts.next(), parts.next(), parts.next())
        {
            result.virtio.push(Virtio {
                device: device.into(),
                driver: driver.into(),
                modalias: modalias.into(),
            });
        }
    } else if let Some(raw) = line.strip_prefix("MOUNTINFO|") {
        let fields: Vec<_> = raw.split_whitespace().collect();
        if let Some(separator) = fields.iter().position(|field| *field == "-")
            && fields.len() >= 7
            && separator + 2 < fields.len()
        {
            result.mounts.push(Mount {
                filesystem: fields[separator + 1].into(),
                mountpoint: unescape_mount(fields[4]),
                raw: raw.into(),
                source: fields[separator + 2].into(),
            });
        }
    } else if let Some(value) = line.strip_prefix("CMDLINE_BYTES|")
        && let Some(value) = parse_python_int(value)
    {
        result.cmdline_bytes = Some(value);
    }
}

fn parse_python_int(value: &str) -> Option<Number> {
    let value = value.trim();
    let (negative, digits) = match value.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, value.strip_prefix('+').unwrap_or(value)),
    };
    let digits = normalize_python_decimal_digits(digits)?;
    let digits = digits.trim_start_matches('0');
    let canonical = if digits.is_empty() {
        "0".to_owned()
    } else if negative {
        format!("-{digits}")
    } else {
        digits.to_owned()
    };
    Number::from_str(&canonical).ok()
}

fn normalize_python_decimal_digits(value: &str) -> Option<String> {
    let mut normalized = String::new();
    let mut previous_was_digit = false;
    for character in value.chars() {
        if let Some(digit) = character.to_decimal_utf8() {
            normalized.push(char::from(b'0' + digit));
            previous_was_digit = true;
        } else if character == '_' && previous_was_digit {
            previous_was_digit = false;
        } else {
            return None;
        }
    }
    previous_was_digit.then_some(normalized)
}

fn unescape_mount(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut output = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '\\'
            && index + 3 < chars.len()
            && chars[index + 1..index + 4]
                .iter()
                .all(|character| ('0'..='7').contains(character))
        {
            let number = chars[index + 1..index + 4].iter().collect::<String>();
            output.push(
                char::from_u32(u32::from_str_radix(&number, 8).expect("octal was validated"))
                    .expect("octal is scalar"),
            );
            index += 4;
        } else {
            output.push(chars[index]);
            index += 1;
        }
    }
    output
}

pub fn write_discovery(request: DiscoveryRequest<'_>) -> Result<()> {
    let current = parse_guest_log_file(request.guest_log)?;
    write_parsed_discovery(current, request)
}

fn write_parsed_discovery(current: Discovery, request: DiscoveryRequest<'_>) -> Result<()> {
    if let Some(baseline_path) = request.baseline {
        let baseline: Baseline = serde_json::from_reader(
            File::open(baseline_path)
                .with_context(|| format!("open baseline {}", baseline_path.display()))?,
        )
        .with_context(|| format!("parse baseline {}", baseline_path.display()))?;
        let fdt_delta = current.fdt.len() as isize - baseline.fdt.len() as isize;
        let virtio_delta =
            virtio_fs_count(&current.virtio) as isize - virtio_fs_count(&baseline.virtio) as isize;
        if fdt_delta != request.expected_mounts as isize {
            bail!(
                "FDT virtio-mmio delta {fdt_delta}, expected {}",
                request.expected_mounts
            );
        }
        if virtio_delta != request.expected_mounts as isize {
            bail!(
                "virtio-fs driver delta {virtio_delta}, expected {}",
                request.expected_mounts
            );
        }

        let (selected, numbered) = validate_numbered_mounts(
            &current.mounts,
            request.expected_mounts,
            &request.selected_indexes,
        )?;
        write_pretty(
            request.output,
            &DiscoveryComparison {
                baseline: baseline_path.display().to_string(),
                cmdline_bytes: current.cmdline_bytes,
                fdt: &current.fdt,
                fdt_delta,
                mounts: &current.mounts,
                selected_mounts: selected
                    .into_iter()
                    .map(|mount| (mount.clone(), numbered[&mount]))
                    .collect(),
                virtio: &current.virtio,
                virtio_fs_delta: virtio_delta,
            },
        )
    } else {
        write_pretty(request.output, &current)
    }
}

fn validate_numbered_mounts<'a>(
    mounts: &'a [Mount],
    expected_mounts: usize,
    selected_indexes: &[usize],
) -> Result<(Vec<String>, BTreeMap<String, &'a Mount>)> {
    let mut numbered = BTreeMap::new();
    for mount in mounts {
        numbered.insert(mount.mountpoint.clone(), mount);
    }
    let required: Vec<_> = (0..expected_mounts)
        .map(|index| format!("/m{index:03}"))
        .collect();
    let missing: Vec<_> = required
        .iter()
        .filter(|mount| !numbered.contains_key(*mount))
        .cloned()
        .collect();
    if !missing.is_empty() {
        bail!("missing virtiofs mountinfo entries: {}", missing.join(", "));
    }
    let wrong: Vec<_> = required
        .iter()
        .filter(|mount| {
            numbered[*mount].filesystem != "virtiofs" || numbered[*mount].source.is_empty()
        })
        .cloned()
        .collect();
    if !wrong.is_empty() {
        bail!("invalid virtiofs mountinfo entries: {}", wrong.join(", "));
    }
    let sources: Vec<_> = required
        .iter()
        .map(|mount| numbered[mount].source.as_str())
        .collect();
    let distinct: BTreeSet<_> = sources.iter().copied().collect();
    if distinct.len() != sources.len() {
        bail!("numbered virtiofs mount tags/sources are not distinct");
    }
    let selected: Vec<_> = selected_indexes
        .iter()
        .map(|index| format!("/m{index:03}"))
        .collect();
    let absent: Vec<_> = selected
        .iter()
        .filter(|mount| !numbered.contains_key(*mount))
        .cloned()
        .collect();
    if !absent.is_empty() {
        bail!(
            "selected virtiofs mountinfo entries are missing: {}",
            absent.join(", ")
        );
    }
    Ok((selected, numbered))
}

fn virtio_fs_count(items: &[Virtio]) -> usize {
    items
        .iter()
        .filter(|item| matches!(item.driver.as_str(), "virtiofs" | "virtio_fs"))
        .count()
}

#[derive(Serialize)]
struct DiscoveryComparison<'a> {
    baseline: String,
    cmdline_bytes: Option<Number>,
    fdt: &'a [Fdt],
    fdt_delta: isize,
    mounts: &'a [Mount],
    selected_mounts: BTreeMap<String, &'a Mount>,
    virtio: &'a [Virtio],
    virtio_fs_delta: isize,
}

pub fn assert_baseline_stable(before: &Path, after: &Path) -> Result<()> {
    let before: Baseline = serde_json::from_reader(File::open(before)?)?;
    let after: Baseline = serde_json::from_reader(File::open(after)?)?;
    let mut before_virtio: Vec<_> = before.virtio.iter().map(virtio_fingerprint).collect();
    let mut after_virtio: Vec<_> = after.virtio.iter().map(virtio_fingerprint).collect();
    before_virtio.sort();
    after_virtio.sort();
    if before.fdt != after.fdt || before_virtio != after_virtio {
        bail!("Darwin zero-bind device inventory drifted during the suite");
    }
    Ok(())
}

fn virtio_fingerprint(item: &Virtio) -> (&str, &str, &str) {
    (&item.device, &item.driver, &item.modalias)
}

pub fn write_manifest(request: ManifestRequest<'_>) -> Result<()> {
    write_pretty(
        request.output,
        &Manifest {
            mode: request.mode,
            host: Host {
                os: request.host_os,
                arch: request.host_arch,
            },
            binary: request.binary.display().to_string(),
            binary_sha256: sha256(request.binary)?,
            firmware: request.firmware.display().to_string(),
            firmware_sha256: sha256(request.firmware)?,
            image: request.image,
            image_platform: request.image_platform,
            started_at: request.started_at,
            logs: "logs",
        },
    )
}

#[derive(Serialize)]
struct Host<'a> {
    os: &'a str,
    arch: &'a str,
}

#[derive(Serialize)]
struct Manifest<'a> {
    mode: &'a str,
    host: Host<'a>,
    binary: String,
    binary_sha256: String,
    firmware: String,
    firmware_sha256: String,
    image: &'a str,
    image_platform: &'a str,
    started_at: f64,
    logs: &'static str,
}

fn sha256(path: &Path) -> Result<String> {
    let mut source = File::open(path)?;
    let mut digest = Sha256::new();
    std::io::copy(&mut source, &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}

pub fn current_unix_time() -> Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}

pub fn write_observations(request: ObservationsRequest<'_>) -> Result<()> {
    write_pretty(
        request.output,
        &Observations {
            host: Host {
                os: request.host_os,
                arch: request.host_arch,
            },
            discovery_kind: if request.host_os == "Darwin" {
                "fdt-sysfs"
            } else {
                "x86-cmdline"
            },
            observed_successful_mounts: request.last_good,
            first_attempted_failure: (request.first_failure != 0).then_some(request.first_failure),
            failure_reason: (!request.failure_reason.is_empty()).then_some(request.failure_reason),
            repeats: request.repeats,
            reviewed_profile_candidate: (request.host_os == "Darwin").then_some(Profile {
                boundary_mounts: [4, 64],
                high_mounts: 112,
                stress_mounts: 64,
            }),
            capacity_note: (request.host_os == "Darwin").then_some(
                "128 was the highest successful tested count; 256 was the first attempted failure; 129-255 were not exhaustively tested; exact maximum unmeasured.",
            ),
        },
    )
}

#[derive(Serialize)]
struct Profile {
    boundary_mounts: [usize; 2],
    high_mounts: usize,
    stress_mounts: usize,
}

#[derive(Serialize)]
struct Observations<'a> {
    host: Host<'a>,
    discovery_kind: &'static str,
    observed_successful_mounts: usize,
    first_attempted_failure: Option<usize>,
    failure_reason: Option<&'a str>,
    repeats: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    reviewed_profile_candidate: Option<Profile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capacity_note: Option<&'static str>,
}

struct PythonPrettyFormatter<'a> {
    pretty: PrettyFormatter<'a>,
}

impl<'a> PythonPrettyFormatter<'a> {
    fn new() -> Self {
        Self {
            pretty: PrettyFormatter::new(),
        }
    }
}

impl Formatter for PythonPrettyFormatter<'_> {
    fn begin_array<W: ?Sized + Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.pretty.begin_array(writer)
    }
    fn end_array<W: ?Sized + Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.pretty.end_array(writer)
    }
    fn begin_array_value<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        self.pretty.begin_array_value(writer, first)
    }
    fn end_array_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.pretty.end_array_value(writer)
    }
    fn begin_object<W: ?Sized + Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.pretty.begin_object(writer)
    }
    fn end_object<W: ?Sized + Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.pretty.end_object(writer)
    }
    fn begin_object_key<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> std::io::Result<()> {
        self.pretty.begin_object_key(writer, first)
    }
    fn begin_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.pretty.begin_object_value(writer)
    }
    fn end_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        self.pretty.end_object_value(writer)
    }

    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        for character in fragment.chars() {
            match character {
                '\u{20}'..='\u{7e}' => writer.write_all(&[character as u8])?,
                '\u{0}'..='\u{ffff}' => write!(writer, "\\u{:04x}", character as u32)?,
                character => {
                    let scalar = character as u32 - 0x1_0000;
                    write!(
                        writer,
                        "\\u{:04x}\\u{:04x}",
                        0xd800 + (scalar >> 10),
                        0xdc00 + (scalar & 0x3ff)
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn write_pretty(path: &Path, value: &impl Serialize) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create evidence {}", path.display()))?;
    let mut output = BufWriter::new(file);
    value.serialize(&mut serde_json::Serializer::with_formatter(
        &mut output,
        PythonPrettyFormatter::new(),
    ))?;
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::{Value, json};
    use std::{fs, process::Command};
    use tempfile::tempdir;

    fn write(path: &Path, contents: impl AsRef<[u8]>) {
        fs::write(path, contents).unwrap();
    }

    fn baseline_json() -> &'static str {
        r#"{"fdt":[{"interrupts_hex":"base-irq","path":"/base","reg_hex":"base-reg"}],"virtio":[{"device":"virtio-base","driver":"virtiofs","modalias":"base"}]}"#
    }

    fn valid_log(mounts: usize) -> String {
        let mut log =
            String::from("FDT|/base|base-reg|base-irq\nVIRTIO|virtio-base|base|virtiofs\n");
        for index in 0..mounts {
            log.push_str(&format!(
                "FDT|/m{index:03}|reg-{index}|irq-{index}\nVIRTIO|virtio-{index}|modalias-{index}|virtiofs\nMOUNTINFO|36 25 0:30 / /m{index:03} rw - virtiofs tag-{index} rw\n"
            ));
        }
        log
    }

    fn discovery_request<'a>(
        log: &'a Path,
        output: &'a Path,
        baseline: &'a Path,
        expected_mounts: usize,
        selected_indexes: Vec<usize>,
    ) -> DiscoveryRequest<'a> {
        DiscoveryRequest {
            guest_log: log,
            output,
            expected_mounts,
            selected_indexes,
            baseline: Some(baseline),
        }
    }

    #[test]
    fn parser_golden_matches_python_text_rules() {
        let log = b"ignored\rFDT|/one|reg|irq\r\nFDT|missing|field\nVIRTIO|virtio0|modalias|virtiofs|with-pipe\r\nMOUNTINFO|36 25 0:30 / /m000\\040first rw - virtiofs tag-first rw\rMOUNTINFO|37 25 0:31 / /m000 rw - ext4 ignored rw\nMOUNTINFO|malformed\nCMDLINE_BYTES|bad\rCMDLINE_BYTES| 202 \nCMDLINE_BYTES|999999999999999999999999999999999999999999999999\xff";
        let parsed = parse_guest_log(log);
        let expected = json!({
            "cmdline_bytes": 202,
            "fdt": [{"interrupts_hex": "irq", "path": "/one", "reg_hex": "reg"}],
            "mounts": [
                {"filesystem": "virtiofs", "mountpoint": "/m000 first", "raw": "36 25 0:30 / /m000\\040first rw - virtiofs tag-first rw", "source": "tag-first"},
                {"filesystem": "ext4", "mountpoint": "/m000", "raw": "37 25 0:31 / /m000 rw - ext4 ignored rw", "source": "ignored"}
            ],
            "virtio": [{"device": "virtio0", "driver": "virtiofs|with-pipe", "modalias": "modalias"}]
        });
        assert_eq!(serde_json::to_value(parsed).unwrap(), expected);

        let large =
            parse_guest_log(b"CMDLINE_BYTES| 999999999999999999999999999999999999999999999999 ");
        assert_eq!(
            large.cmdline_bytes.unwrap().to_string(),
            "999999999999999999999999999999999999999999999999"
        );
        assert_eq!(
            parse_guest_log(b"CMDLINE_BYTES|1_024\n")
                .cmdline_bytes
                .unwrap()
                .to_string(),
            "1024"
        );
        for (input, expected) in [
            ("١٢٣", "123"),
            ("１_٢𝟛", "123"),
            (" -٠ ", "0"),
            ("+ 1", "invalid"),
            ("١__٢", "invalid"),
            ("²", "invalid"),
        ] {
            let parsed = parse_guest_log(format!("CMDLINE_BYTES|{input}").as_bytes());
            match expected {
                "invalid" => assert!(parsed.cmdline_bytes.is_none(), "{input}"),
                expected => assert_eq!(
                    parsed.cmdline_bytes.unwrap().to_string(),
                    expected,
                    "{input}"
                ),
            }
        }
    }

    proptest! {
        #[test]
        fn arbitrary_logs_never_panic_and_baseline_free_schema_is_json(bytes: Vec<u8>) {
            let parsed = parse_guest_log(&bytes);
            let json = serde_json::to_string(&parsed).unwrap();
            let value: Value = serde_json::from_str(&json).unwrap();
            prop_assert!(value.get("fdt").is_some());
            prop_assert!(value.get("virtio").is_some());
            prop_assert!(value.get("mounts").is_some());
            prop_assert!(value.get("cmdline_bytes").is_some());
        }
    }

    #[test]
    fn darwin_discovery_comparison_golden() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("guest.log");
        let baseline = dir.path().join("baseline.json");
        let output = dir.path().join("discovery.json");
        write(&log, valid_log(2));
        write(&baseline, baseline_json());

        write_discovery(discovery_request(&log, &output, &baseline, 2, vec![0, 1])).unwrap();
        let value: Value = serde_json::from_reader(File::open(&output).unwrap()).unwrap();
        assert_eq!(value["fdt_delta"], 2);
        assert_eq!(value["virtio_fs_delta"], 2);
        assert_eq!(value["selected_mounts"].as_object().unwrap().len(), 2);
        assert_eq!(value["selected_mounts"]["/m001"]["source"], "tag-1");
    }

    #[test]
    fn rust_discovery_matches_historical_python_bytes() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("guest.log");
        let baseline = dir.path().join("baseline.json");
        let rust_output = dir.path().join("rust.json");
        let python_output = dir.path().join("python.json");
        let reference = dir.path().join("historical.py");
        write(&baseline, baseline_json());
        write(&log, b"ignored\rFDT|/base|base-reg|base-irq\r\nVIRTIO|virtio-base|base|virtiofs\nFDT|/m000|r\xc3\xa9g|irq\xf0\x9f\x98\x80\rVIRTIO|virtio-new|modalias|virtiofs\nMOUNTINFO|36 25 0:30 / /extra\\040name rw - ext4 ignored rw\nMOUNTINFO|36 25 0:30 / /m000 rw - virtiofs stale rw\nMOUNTINFO|36 25 0:30 / /m000 rw - virtiofs final rw\rCMDLINE_BYTES| \xef\xbc\x91_\xd9\xa2\xf0\x9d\x9f\x9b \nCMDLINE_BYTES|bad\runknown|x|y\nFDT|missing|field");
        write(
            &reference,
            r#"import json, re, sys
log_path, output_path, expected, selected, baseline_path = sys.argv[1:]
expected = int(expected)
selected_indexes = [] if not selected else [int(value) for value in selected.split(',')]
def unescape_mount(value): return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)
def parse(path):
    result = {"fdt": [], "virtio": [], "mounts": [], "cmdline_bytes": None}
    with open(path, encoding="utf-8", errors="replace") as source:
        for raw in source:
            line = raw.rstrip("\n")
            if line.startswith("FDT|"):
                parts = line.split("|", 3)
                if len(parts) == 4: result["fdt"].append({"path": parts[1], "reg_hex": parts[2], "interrupts_hex": parts[3]})
            elif line.startswith("VIRTIO|"):
                parts = line.split("|", 3)
                if len(parts) == 4: result["virtio"].append({"device": parts[1], "modalias": parts[2], "driver": parts[3]})
            elif line.startswith("MOUNTINFO|"):
                fields = line[len("MOUNTINFO|"):].split()
                if "-" in fields and len(fields) >= 7:
                    separator = fields.index("-")
                    if separator + 2 < len(fields): result["mounts"].append({"mountpoint": unescape_mount(fields[4]), "filesystem": fields[separator + 1], "source": fields[separator + 2], "raw": line[len("MOUNTINFO|"): ]})
            elif line.startswith("CMDLINE_BYTES|"):
                try: result["cmdline_bytes"] = int(line.split("|", 1)[1])
                except ValueError: pass
    return result
current = parse(log_path)
with open(baseline_path, encoding="utf-8") as source: baseline = json.load(source)
delta_fdt = len(current["fdt"]) - len(baseline["fdt"])
delta_fs = sum(item["driver"] in {"virtiofs", "virtio_fs"} for item in current["virtio"]) - sum(item["driver"] in {"virtiofs", "virtio_fs"} for item in baseline["virtio"])
current["baseline"] = baseline_path; current["fdt_delta"] = delta_fdt; current["virtio_fs_delta"] = delta_fs
if delta_fdt != expected: raise SystemExit("bad fdt")
if delta_fs != expected: raise SystemExit("bad virtio")
numbered = {item["mountpoint"]: item for item in current["mounts"]}
current["selected_mounts"] = {f"/m{index:03d}": numbered[f"/m{index:03d}"] for index in selected_indexes}
with open(output_path, "x", encoding="utf-8") as output: json.dump(current, output, indent=2, sort_keys=True)
"#,
        );
        write_discovery(discovery_request(&log, &rust_output, &baseline, 1, vec![0])).unwrap();
        let status = Command::new("python3")
            .arg(&reference)
            .arg(&log)
            .arg(&python_output)
            .arg("1")
            .arg("0")
            .arg(&baseline)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            fs::read(&rust_output).unwrap(),
            fs::read(&python_output).unwrap()
        );
    }

    #[test]
    fn darwin_validation_failures_leave_no_output() {
        struct Case {
            name: &'static str,
            log: String,
            expected: usize,
            selected: Vec<usize>,
            message: &'static str,
        }
        let valid = valid_log(2);
        let cases = vec![
            Case {
                name: "fdt delta",
                log: valid.replacen("FDT|/m001|reg-1|irq-1\n", "", 1),
                expected: 2,
                selected: vec![],
                message: "FDT virtio-mmio delta",
            },
            Case {
                name: "virtio delta",
                log: valid.replacen("VIRTIO|virtio-1|modalias-1|virtiofs\n", "", 1),
                expected: 2,
                selected: vec![],
                message: "virtio-fs driver delta",
            },
            Case {
                name: "missing mount",
                log: valid.replacen(
                    "MOUNTINFO|36 25 0:30 / /m001 rw - virtiofs tag-1 rw\n",
                    "",
                    1,
                ),
                expected: 2,
                selected: vec![],
                message: "missing virtiofs",
            },
            Case {
                name: "wrong mount",
                log: valid.replacen("- virtiofs tag-1 rw", "- ext4 tag-1 rw", 1),
                expected: 2,
                selected: vec![],
                message: "invalid virtiofs",
            },
            Case {
                name: "duplicate source",
                log: valid.replacen("tag-1", "tag-0", 1),
                expected: 2,
                selected: vec![],
                message: "not distinct",
            },
            Case {
                name: "selected missing",
                log: valid,
                expected: 2,
                selected: vec![2],
                message: "selected virtiofs",
            },
        ];
        let dir = tempdir().unwrap();
        let baseline = dir.path().join("baseline.json");
        write(&baseline, baseline_json());
        for case in cases {
            let log = dir.path().join(format!("{}.log", case.name));
            let output = dir.path().join(format!("{}.json", case.name));
            write(&log, case.log);
            let result = write_discovery(discovery_request(
                &log,
                &output,
                &baseline,
                case.expected,
                case.selected,
            ));
            assert!(result.is_err(), "{}", case.name);
            let error = result.unwrap_err();
            assert!(error.to_string().contains(case.message), "{}", case.name);
            assert!(!output.exists(), "{}", case.name);
        }

        let output = dir.path().join("empty-source.json");
        let error = write_parsed_discovery(
            Discovery {
                cmdline_bytes: None,
                fdt: vec![
                    Fdt {
                        path: "/base".into(),
                        reg_hex: "base-reg".into(),
                        interrupts_hex: "base-irq".into(),
                    },
                    Fdt {
                        path: "/m000".into(),
                        reg_hex: "reg".into(),
                        interrupts_hex: "irq".into(),
                    },
                ],
                virtio: vec![
                    Virtio {
                        device: "base".into(),
                        modalias: "base".into(),
                        driver: "virtiofs".into(),
                    },
                    Virtio {
                        device: "new".into(),
                        modalias: "new".into(),
                        driver: "virtiofs".into(),
                    },
                ],
                mounts: vec![Mount {
                    filesystem: "virtiofs".into(),
                    mountpoint: "/m000".into(),
                    raw: "synthetic empty source".into(),
                    source: String::new(),
                }],
            },
            discovery_request(
                &dir.path().join("unused.log"),
                &output,
                &baseline,
                1,
                vec![],
            ),
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid virtiofs"));
        assert!(!output.exists());
    }

    #[test]
    fn duplicate_mountpoints_use_the_last_record_through_write_seam() {
        let dir = tempdir().unwrap();
        let baseline = dir.path().join("baseline.json");
        write(&baseline, baseline_json());
        let log = dir.path().join("guest.log");
        let output = dir.path().join("discovery.json");
        let valid = format!(
            "{}MOUNTINFO|36 25 0:30 / /m000 rw - virtiofs stale rw\nMOUNTINFO|36 25 0:30 / /m000 rw - virtiofs final rw\n",
            valid_log(1)
        );
        write(&log, valid);
        write_discovery(discovery_request(&log, &output, &baseline, 1, vec![0])).unwrap();
        assert_eq!(
            serde_json::from_reader::<_, Value>(File::open(&output).unwrap()).unwrap()["selected_mounts"]
                ["/m000"]["source"],
            "final"
        );

        let invalid = dir.path().join("invalid.log");
        let invalid_output = dir.path().join("invalid.json");
        write(
            &invalid,
            format!(
                "{}MOUNTINFO|36 25 0:30 / /m000 rw - ext4 final rw\n",
                valid_log(1)
            ),
        );
        assert!(
            write_discovery(discovery_request(
                &invalid,
                &invalid_output,
                &baseline,
                1,
                vec![]
            ))
            .unwrap_err()
            .to_string()
            .contains("invalid virtiofs")
        );
        assert!(!invalid_output.exists());
    }

    #[test]
    fn baseline_stability_respects_fdt_order_and_virtio_multiset() {
        let dir = tempdir().unwrap();
        let before = dir.path().join("before.json");
        let after = dir.path().join("after.json");
        let baseline = r#"{"fdt":[{"interrupts_hex":"i1","path":"/a","reg_hex":"r1"},{"interrupts_hex":"i2","path":"/b","reg_hex":"r2"}],"virtio":[{"device":"v1","driver":"virtiofs","modalias":"m1"},{"device":"v2","driver":"other","modalias":"m2"}]}"#;
        write(&before, baseline);
        write(
            &after,
            r#"{"fdt":[{"interrupts_hex":"i1","path":"/a","reg_hex":"r1"},{"interrupts_hex":"i2","path":"/b","reg_hex":"r2"}],"virtio":[{"device":"v2","driver":"other","modalias":"m2"},{"device":"v1","driver":"virtiofs","modalias":"m1"}]}"#,
        );
        assert!(assert_baseline_stable(&before, &after).is_ok());

        write(
            &after,
            r#"{"fdt":[{"interrupts_hex":"i2","path":"/b","reg_hex":"r2"},{"interrupts_hex":"i1","path":"/a","reg_hex":"r1"}],"virtio":[]}"#,
        );
        assert!(assert_baseline_stable(&before, &after).is_err());
        write(
            &after,
            r#"{"fdt":[{"interrupts_hex":"i1","path":"/a","reg_hex":"r1"},{"interrupts_hex":"i2","path":"/b","reg_hex":"r2"}],"virtio":[{"device":"v1","driver":"changed","modalias":"m1"},{"device":"v2","driver":"other","modalias":"m2"}]}"#,
        );
        assert!(assert_baseline_stable(&before, &after).is_err());
        write(
            &after,
            r#"{"fdt":[{"interrupts_hex":"i1","path":"/a","reg_hex":"r1"},{"interrupts_hex":"i2","path":"/b","reg_hex":"r2"}],"virtio":[{"device":"v1","driver":"virtiofs","modalias":"m1"},{"device":"v1","driver":"virtiofs","modalias":"m1"}]}"#,
        );
        assert!(assert_baseline_stable(&before, &after).is_err());
    }

    #[test]
    fn emitters_preserve_schema_and_create_new_outputs() {
        let dir = tempdir().unwrap();
        let binary = dir.path().join("binary");
        let firmware = dir.path().join("firmware");
        let manifest = dir.path().join("manifest.json");
        write(&binary, "binary");
        write(&firmware, "firmware");
        write_manifest(ManifestRequest {
            output: &manifest,
            mode: "smoke",
            host_os: "Darwin",
            host_arch: "arm64",
            binary: &binary,
            firmware: &firmware,
            image: "alpine:3.20",
            image_platform: "linux/arm64",
            started_at: 1234.5,
        })
        .unwrap();
        let manifest_json: Value = serde_json::from_reader(File::open(&manifest).unwrap()).unwrap();
        assert_eq!(manifest_json["started_at"], 1234.5);
        assert_eq!(
            manifest_json["binary_sha256"],
            "9a3a45d01531a20e89ac6ae10b0b0beb0492acd7216a368aa062d1a5fecaf9cd"
        );
        assert_eq!(
            manifest_json["firmware_sha256"],
            "c3bf47ea1f4a4a605470313cacb3a44f4a461f68c6faeab07e737610cb5ac835"
        );

        let darwin = dir.path().join("darwin.json");
        write_observations(ObservationsRequest {
            output: &darwin,
            host_os: "Darwin",
            host_arch: "arm64",
            last_good: 128,
            first_failure: 256,
            repeats: 3,
            failure_reason: "-failure",
        })
        .unwrap();
        let darwin_json: Value = serde_json::from_reader(File::open(&darwin).unwrap()).unwrap();
        assert_eq!(darwin_json["failure_reason"], "-failure");
        assert!(darwin_json.get("reviewed_profile_candidate").is_some());

        let linux = dir.path().join("linux.json");
        write_observations(ObservationsRequest {
            output: &linux,
            host_os: "Linux",
            host_arch: "x86_64",
            last_good: 0,
            first_failure: 0,
            repeats: 1,
            failure_reason: "",
        })
        .unwrap();
        let linux_json: Value = serde_json::from_reader(File::open(&linux).unwrap()).unwrap();
        assert_eq!(linux_json["first_attempted_failure"], Value::Null);
        assert_eq!(linux_json["failure_reason"], Value::Null);
        assert!(linux_json.get("reviewed_profile_candidate").is_none());
        assert!(linux_json.get("capacity_note").is_none());

        let retained = fs::read(&manifest).unwrap();
        assert!(
            write_manifest(ManifestRequest {
                output: &manifest,
                mode: "smoke",
                host_os: "Darwin",
                host_arch: "arm64",
                binary: &binary,
                firmware: &firmware,
                image: "alpine:3.20",
                image_platform: "linux/arm64",
                started_at: 1234.5
            })
            .is_err()
        );
        assert_eq!(fs::read(&manifest).unwrap(), retained);
    }

    #[test]
    fn emitters_match_exact_python_json_dump_goldens() {
        let dir = tempdir().unwrap();
        let binary = dir.path().join("binary");
        let firmware = dir.path().join("firmware");
        let manifest = dir.path().join("manifest.json");
        write(&binary, "binary");
        write(&firmware, "firmware");
        write_manifest(ManifestRequest {
            output: &manifest,
            mode: "smök😀",
            host_os: "Darwin",
            host_arch: "arm64",
            binary: &binary,
            firmware: &firmware,
            image: "alpine:3.20",
            image_platform: "linux/arm64",
            started_at: 1234.5,
        })
        .unwrap();
        assert_eq!(
            String::from_utf8(fs::read(&manifest).unwrap()).unwrap(),
            format!(
                r#"{{
  "mode": "sm\u00f6k\ud83d\ude00",
  "host": {{
    "os": "Darwin",
    "arch": "arm64"
  }},
  "binary": "{}",
  "binary_sha256": "9a3a45d01531a20e89ac6ae10b0b0beb0492acd7216a368aa062d1a5fecaf9cd",
  "firmware": "{}",
  "firmware_sha256": "c3bf47ea1f4a4a605470313cacb3a44f4a461f68c6faeab07e737610cb5ac835",
  "image": "alpine:3.20",
  "image_platform": "linux/arm64",
  "started_at": 1234.5,
  "logs": "logs"
}}"#,
                binary.display(),
                firmware.display()
            )
        );

        let darwin = dir.path().join("darwin.json");
        write_observations(ObservationsRequest {
            output: &darwin,
            host_os: "Darwin",
            host_arch: "arm64",
            last_good: 128,
            first_failure: 256,
            repeats: 3,
            failure_reason: "é😀",
        })
        .unwrap();
        assert_eq!(
            String::from_utf8(fs::read(&darwin).unwrap()).unwrap(),
            r#"{
  "host": {
    "os": "Darwin",
    "arch": "arm64"
  },
  "discovery_kind": "fdt-sysfs",
  "observed_successful_mounts": 128,
  "first_attempted_failure": 256,
  "failure_reason": "\u00e9\ud83d\ude00",
  "repeats": 3,
  "reviewed_profile_candidate": {
    "boundary_mounts": [
      4,
      64
    ],
    "high_mounts": 112,
    "stress_mounts": 64
  },
  "capacity_note": "128 was the highest successful tested count; 256 was the first attempted failure; 129-255 were not exhaustively tested; exact maximum unmeasured."
}"#
        );

        let linux = dir.path().join("linux.json");
        write_observations(ObservationsRequest {
            output: &linux,
            host_os: "Linux",
            host_arch: "x86_64",
            last_good: 0,
            first_failure: 0,
            repeats: 1,
            failure_reason: "",
        })
        .unwrap();
        assert_eq!(
            String::from_utf8(fs::read(&linux).unwrap()).unwrap(),
            r#"{
  "host": {
    "os": "Linux",
    "arch": "x86_64"
  },
  "discovery_kind": "x86-cmdline",
  "observed_successful_mounts": 0,
  "first_attempted_failure": null,
  "failure_reason": null,
  "repeats": 1
}"#
        );
    }
}
