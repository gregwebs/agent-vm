use std::{
    collections::HashMap,
    fs,
    io::{self, Cursor, Read},
    path::PathBuf,
};

use clap::Args;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const INDEX_MEDIA_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];
const MANIFEST_MEDIA_TYPES: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];
const CONFIG_MEDIA_TYPES: [&str; 2] = [
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
];
const LAYER_MEDIA_TYPES: [&str; 4] = [
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];

#[derive(Debug, Args)]
pub struct BuildArchiveOracleArgs {
    /// Reject known bad mutations of an OCI build archive.
    #[arg(long)]
    controls: bool,

    /// Run the boot-free archive oracle controls.
    #[arg(long, conflicts_with_all = ["controls", "archive"])]
    self_test: bool,

    /// OCI archive emitted by buildx.
    #[arg(value_name = "ARCHIVE")]
    archive: Option<PathBuf>,
}

struct ArchiveMember {
    name: String,
    header: tar::Header,
    data: Option<Vec<u8>>,
}

struct Inspector<'a> {
    members: HashMap<&'a str, &'a ArchiveMember>,
    host: &'static str,
    leaves: Vec<String>,
    visited: usize,
}

pub fn run(args: BuildArchiveOracleArgs) -> Result<String, String> {
    if args.self_test {
        self_test()?;
        return Ok("build archive oracle controls passed".to_owned());
    }
    let archive = args.archive.ok_or("archive oracle requires ARCHIVE")?;
    if args.controls {
        controls(&archive)?;
        Ok("archive oracle negative controls passed".to_owned())
    } else {
        let report = inspect(&archive)?;
        Ok(report.json())
    }
}

struct Report {
    platform: String,
    manifests: Vec<String>,
    descriptors: usize,
}

impl Report {
    // Python's json.dumps(sort_keys=True) uses these separators; e2e keeps this
    // evidence byte-for-byte compatible with the former oracle.
    fn json(&self) -> String {
        let manifests = self
            .manifests
            .iter()
            .map(|digest| serde_json::to_string(digest).expect("digest serializes"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"{{"descriptors": {}, "manifests": [{}], "platform": {}}}"#,
            self.descriptors,
            manifests,
            serde_json::to_string(&self.platform).expect("platform serializes")
        )
    }
}

fn inspect(path: &PathBuf) -> Result<Report, String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read archive: {error}"))?;
    inspect_bytes(&bytes)
}

fn inspect_bytes(bytes: &[u8]) -> Result<Report, String> {
    let members = archive_members(Cursor::new(bytes))?;
    inspect_members(&members)
}

fn archive_members(reader: impl Read) -> Result<Vec<ArchiveMember>, String> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|error| format!("cannot read archive: {error}"))?;
    let mut members = Vec::new();
    for entry in entries {
        let mut entry = entry.map_err(|error| format!("cannot read archive: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| format!("cannot read archive member name: {error}"))?;
        let name = path.to_str().ok_or("archive member name is not UTF-8")?;
        let name = name.strip_prefix("./").unwrap_or(name).to_owned();
        let header = entry.header().clone();
        let data = if header.entry_type().is_file() {
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(|error| format!("cannot read archive member: {error}"))?;
            Some(data)
        } else {
            None
        };
        members.push(ArchiveMember { name, header, data });
    }
    Ok(members)
}

fn inspect_members(entries: &[ArchiveMember]) -> Result<Report, String> {
    if entries.len() >= 100_000 {
        return Err("member bound".to_owned());
    }
    let mut members = HashMap::with_capacity(entries.len());
    for member in entries {
        if members.insert(member.name.as_str(), member).is_some() {
            return Err("duplicate archive members".to_owned());
        }
    }
    let host = host_arch()?;
    let mut inspector = Inspector {
        members,
        host,
        leaves: Vec::new(),
        visited: 0,
    };
    let index = inspector.json_member("index.json")?;
    clean(&index)?;
    for descriptor in array_field(&index, "manifests")? {
        inspector.walk(descriptor, &[])?;
    }
    if inspector.leaves.len() != 1 {
        return Err("must export exactly one runnable image".to_owned());
    }
    Ok(Report {
        platform: format!("linux/{}", inspector.host),
        manifests: inspector.leaves,
        descriptors: inspector.visited,
    })
}

impl<'a> Inspector<'a> {
    fn member(&self, name: &str) -> Result<&'a [u8], String> {
        let member = self
            .members
            .get(name)
            .ok_or_else(|| format!("missing archive member {name}"))?;
        member.data.as_deref().ok_or("nonregular blob".to_owned())
    }

    fn json_member(&self, name: &str) -> Result<Value, String> {
        serde_json::from_slice(self.member(name)?)
            .map_err(|error| format!("invalid JSON in {name}: {error}"))
    }

    fn blob(&self, descriptor: &Value) -> Result<Vec<u8>, String> {
        let digest = string_field(descriptor, "digest")?;
        let (algorithm, hex) = digest.split_once(':').ok_or("unknown digest")?;
        if algorithm != "sha256" {
            return Err("unknown digest".to_owned());
        }
        let data = self.member(&format!("blobs/sha256/{hex}"))?;
        if data.len() as u64 != u64_field(descriptor, "size")? {
            return Err("size mismatch".to_owned());
        }
        if sha256_hex(data) != hex {
            return Err("digest mismatch".to_owned());
        }
        Ok(data.to_vec())
    }

    fn walk(&mut self, descriptor: &Value, ancestors: &[String]) -> Result<(), String> {
        self.visited += 1;
        if self.visited > 128 || ancestors.len() >= 16 {
            return Err("descriptor bounds".to_owned());
        }
        clean(descriptor)?;
        let digest = string_field(descriptor, "digest")?;
        if ancestors.iter().any(|ancestor| ancestor == digest) {
            return Err("descriptor cycle".to_owned());
        }
        let declared = object_field_if_truthy(descriptor, "platform")?;
        if let Some(platform) = declared
            && (string_object_field(platform, "os")? != "linux"
                || string_object_field(platform, "architecture")? != self.host)
        {
            return Err("foreign platform".to_owned());
        }
        let node: Value = serde_json::from_slice(&self.blob(descriptor)?)
            .map_err(|error| format!("invalid descriptor JSON: {error}"))?;
        clean(&node)?;
        let media = string_field(descriptor, "mediaType")?;
        if INDEX_MEDIA_TYPES.contains(&media) {
            let mut next_ancestors = ancestors.to_vec();
            next_ancestors.push(digest.to_owned());
            for child in array_field(&node, "manifests")? {
                self.walk(child, &next_ancestors)?;
            }
        } else {
            if !MANIFEST_MEDIA_TYPES.contains(&media) {
                return Err("unknown descriptor media type".to_owned());
            }
            if declared.is_none() {
                return Err("leaf must declare platform".to_owned());
            }
            let config = value_field(&node, "config")?;
            clean(config)?;
            if !CONFIG_MEDIA_TYPES.contains(&string_field(config, "mediaType")?) {
                return Err("unknown config media type".to_owned());
            }
            let config: Value = serde_json::from_slice(&self.blob(config)?)
                .map_err(|error| format!("invalid config JSON: {error}"))?;
            if string_field(&config, "os")? != "linux"
                || string_field(&config, "architecture")? != self.host
            {
                return Err("foreign config".to_owned());
            }
            for layer in array_field(&node, "layers")? {
                clean(layer)?;
                if !LAYER_MEDIA_TYPES.contains(&string_field(layer, "mediaType")?) {
                    return Err("unknown layer media type".to_owned());
                }
                self.blob(layer)?;
            }
            self.leaves.push(digest.to_owned());
        }
        Ok(())
    }
}

fn clean(node: &Value) -> Result<(), String> {
    let object = node.as_object().ok_or("metadata is not an object")?;
    if object.contains_key("subject") || object.contains_key("artifactType") {
        return Err("artifact".to_owned());
    }
    let annotations = match object.get("annotations") {
        Some(value) => value.as_object().ok_or("annotations are not an object")?,
        None => return Ok(()),
    };
    if annotations.contains_key("org.opencontainers.image.ref.name") {
        return Err("result alias".to_owned());
    }
    if annotations.iter().any(|(key, value)| {
        key.contains("attestation") || value.to_string().contains("attestation")
    }) {
        return Err("attestation".to_owned());
    }
    Ok(())
}

fn value_field<'a>(node: &'a Value, field: &str) -> Result<&'a Value, String> {
    node.as_object()
        .and_then(|object| object.get(field))
        .ok_or_else(|| format!("missing {field}"))
}

fn string_field<'a>(node: &'a Value, field: &str) -> Result<&'a str, String> {
    value_field(node, field)?
        .as_str()
        .ok_or_else(|| format!("{field} is not a string"))
}

fn u64_field(node: &Value, field: &str) -> Result<u64, String> {
    value_field(node, field)?
        .as_u64()
        .ok_or_else(|| format!("{field} is not an unsigned integer"))
}

fn array_field<'a>(node: &'a Value, field: &str) -> Result<&'a [Value], String> {
    value_field(node, field)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{field} is not an array"))
}

fn object_field_if_truthy<'a>(
    node: &'a Value,
    field: &str,
) -> Result<Option<&'a Map<String, Value>>, String> {
    let Some(value) = node.as_object().and_then(|object| object.get(field)) else {
        return Ok(None);
    };
    if !json_truthy(value) {
        return Ok(None);
    }
    value
        .as_object()
        .map(Some)
        .ok_or_else(|| format!("{field} is not an object"))
}

fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_i64() != Some(0) && number.as_u64() != Some(0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn string_object_field<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{field} is not a string"))
}

fn host_arch() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "aarch64" | "arm64" => Ok("arm64"),
        "x86_64" => Ok("amd64"),
        architecture => Err(format!("unsupported host architecture: {architecture}")),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn controls(path: &PathBuf) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read archive: {error}"))?;
    let entries = archive_members(Cursor::new(&bytes))?;
    inspect_members(&entries)?;
    for mutation in ["alias", "extra-foreign", "extra-attestation"] {
        let altered = mutate_archive(&entries, mutation)?;
        if inspect_bytes(&altered).is_ok() {
            return Err(format!("oracle accepted {mutation}"));
        }
    }
    Ok(())
}

fn mutate_archive(entries: &[ArchiveMember], mutation: &str) -> Result<Vec<u8>, String> {
    let mut output = tar::Builder::new(Vec::new());
    for entry in entries {
        let mut header = entry.header.clone();
        let data = if entry.name == "index.json" {
            let source = entry.data.as_deref().ok_or("nonregular blob")?;
            let mut index: Value = serde_json::from_slice(source)
                .map_err(|error| format!("invalid index JSON: {error}"))?;
            mutate_index(&mut index, mutation)?;
            let data = serde_json::to_vec(&index)
                .map_err(|error| format!("cannot write index JSON: {error}"))?;
            header.set_size(data.len() as u64);
            header.set_cksum();
            Some(data)
        } else {
            entry.data.clone()
        };
        match data {
            Some(data) => output
                .append(&header, Cursor::new(data))
                .map_err(|error| format!("cannot write altered archive: {error}"))?,
            None => output
                .append(&header, io::empty())
                .map_err(|error| format!("cannot write altered archive: {error}"))?,
        }
    }
    output
        .into_inner()
        .map_err(|error| format!("cannot finish altered archive: {error}"))
}

fn mutate_index(index: &mut Value, mutation: &str) -> Result<(), String> {
    let manifest = index
        .get_mut("manifests")
        .and_then(Value::as_array_mut)
        .and_then(|manifests| manifests.first_mut())
        .ok_or("index has no first manifest")?;
    let descriptor = manifest
        .as_object_mut()
        .ok_or("index manifest is not an object")?;
    match mutation {
        "alias" => {
            let annotations = descriptor
                .entry("annotations")
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or("annotations are not an object")?;
            annotations.insert(
                "org.opencontainers.image.ref.name".to_owned(),
                Value::String("alias:dev".to_owned()),
            );
        }
        "extra-foreign" | "extra-attestation" => {
            let mut extra = Value::Object(descriptor.clone());
            if mutation == "extra-foreign" {
                extra.as_object_mut().expect("object just cloned").insert(
                    "platform".to_owned(),
                    serde_json::json!({"os":"linux","architecture":"foreign"}),
                );
            } else {
                let annotations = extra
                    .as_object_mut()
                    .expect("object just cloned")
                    .entry("annotations")
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
                    .ok_or("annotations are not an object")?;
                annotations.insert(
                    "vnd.docker.reference.type".to_owned(),
                    Value::String("attestation-manifest".to_owned()),
                );
            }
            index
                .get_mut("manifests")
                .and_then(Value::as_array_mut)
                .expect("first manifest was present")
                .push(extra);
        }
        _ => return Err(format!("unknown mutation {mutation}")),
    }
    Ok(())
}

fn self_test() -> Result<(), String> {
    let archive = golden_archive(host_arch()?);
    let expected = golden_archive_sha256(host_arch()?);
    if sha256_hex(&archive) != expected {
        return Err("golden archive bytes changed".to_owned());
    }
    let report = inspect_bytes(&archive)?;
    if report.json() != golden_report(host_arch()?) {
        return Err("golden archive report changed".to_owned());
    }
    let mut altered = archive.clone();
    altered[0] ^= 1;
    if sha256_hex(&altered) == expected {
        return Err("golden archive byte mutation was accepted".to_owned());
    }
    let entries = archive_members(Cursor::new(&archive))?;
    for mutation in ["alias", "extra-foreign", "extra-attestation"] {
        let altered = mutate_archive(&entries, mutation)?;
        if inspect_bytes(&altered).is_ok() {
            return Err(format!("oracle accepted {mutation}"));
        }
    }
    Ok(())
}

fn golden_archive_sha256(host: &str) -> &'static str {
    match host {
        "amd64" => "dece131016a8a846dd6109e89fd9670c3e6f521cb1a07128c500e149a5f70f9f",
        "arm64" => "8c5bb64ebad2ac875473c1c397b153244c336cbdba6e0990916075eeb04e20d8",
        _ => unreachable!("host_arch validates its result"),
    }
}

fn golden_report(host: &str) -> String {
    let config = golden_config(host);
    let manifest = golden_manifest(&config);
    format!(
        r#"{{"descriptors": 1, "manifests": ["sha256:{}"], "platform": "linux/{host}"}}"#,
        sha256_hex(&manifest)
    )
}

// This is a fixture writer, not part of the oracle. Every header field is fixed
// so the checksum above is a real archive-byte golden on both supported hosts.
fn golden_archive(host: &str) -> Vec<u8> {
    let config = golden_config(host);
    let manifest = golden_manifest(&config);
    let descriptor = serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": format!("sha256:{}", sha256_hex(&manifest)),
        "size": manifest.len(),
        "platform": {"os": "linux", "architecture": host},
    });
    let index = serde_json::to_vec(&serde_json::json!({"manifests": [descriptor]}))
        .expect("golden index serializes");
    let mut archive = tar::Builder::new(Vec::new());
    append_golden(&mut archive, "index.json", &index);
    append_golden(
        &mut archive,
        &format!("blobs/sha256/{}", sha256_hex(&manifest)),
        &manifest,
    );
    append_golden(
        &mut archive,
        &format!("blobs/sha256/{}", sha256_hex(&config)),
        &config,
    );
    archive.into_inner().expect("golden archive completes")
}

fn golden_config(host: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"os": "linux", "architecture": host}))
        .expect("golden config serializes")
}

fn golden_manifest(config: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": format!("sha256:{}", sha256_hex(config)),
            "size": config.len(),
        },
        "layers": [],
    }))
    .expect("golden manifest serializes")
}

fn append_golden(archive: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
    let mut header = tar::Header::new_ustar();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    archive
        .append_data(&mut header, name, data)
        .expect("append golden archive member");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_archive_is_byte_stable_and_inspected() {
        self_test().expect("golden archive controls pass");
    }

    #[test]
    fn report_matches_python_json_shape() {
        let archive = golden_archive(host_arch().expect("supported host"));
        assert_eq!(
            inspect_bytes(&archive)
                .expect("inspect golden archive")
                .json(),
            golden_report(host_arch().expect("supported host"))
        );
    }
}
