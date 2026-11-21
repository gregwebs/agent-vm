//! The msb cache inventory behind one retained image digest (#700, from #262).
//!
//! The upgrade row claims a *failed* upgrade changes nothing about the image the
//! retained default points at. It proves that by hashing every artifact the
//! runtime cached for that digest before and after, and comparing the two
//! inventories byte for byte. The inventory is the oracle, so it cannot come from
//! the runtime's own reader: this module walks the cache directory and hashes
//! file bytes itself, and it validates the cached metadata against the registry
//! manifest the row fetched independently.
//!
//! What it rejects, rather than tolerates:
//!
//! * a cached manifest whose `manifest_digest` is not the retained digest is not
//!   this image's metadata and is skipped;
//! * a fixture whose bytes do not hash to the digest, a `raw_manifest_json` that
//!   is not the fixture's document, a `raw_config_json` whose hash is not
//!   `config_digest`, and layers that are not the config's `diff_ids` are all
//!   failures — "some metadata exists" is not evidence about *this* image;
//! * no matching metadata at all is a failure, never an empty inventory.
//!
//! A VMDK descriptor is text with one line per extent; the extent paths are read
//! from those lines so a grown or shrunk disk is visible in the inventory.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use clap::Args;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Args)]
pub struct E2eCacheInventoryArgs {
    /// The runtime's cache directory (`<state>/msb-home/cache`).
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    cache: Option<PathBuf>,

    /// The retained reference, `repo@sha256:<child digest>`.
    #[arg(long, value_name = "REF", required_unless_present = "self_test")]
    reference: Option<String>,

    /// The manifest bytes fetched from the registry for that digest.
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    fixture: Option<PathBuf>,

    /// Where to write the inventory JSON.
    #[arg(long, value_name = "PATH", required_unless_present = "self_test")]
    out: Option<PathBuf>,

    /// Run the boot-free controls for the inventory.
    #[arg(long)]
    self_test: bool,
}

pub fn run(args: E2eCacheInventoryArgs) -> Result<String, String> {
    if args.self_test {
        self_test()?;
        return Ok("e2e cache-inventory controls passed".to_owned());
    }
    let cache = args.cache.ok_or("--cache PATH is required")?;
    let reference = args.reference.ok_or("--ref REF is required")?;
    let fixture = args.fixture.ok_or("--fixture PATH is required")?;
    let out = args.out.ok_or("--out PATH is required")?;
    let (count, document) = inventory(&cache, &reference, &fixture)?;
    fs::write(&out, &document)
        .map_err(|error| format!("cannot write {}: {error}", out.display()))?;
    Ok(format!(
        "cache inventory: {count} artifacts for {}",
        digest_of(&reference)?
    ))
}

fn digest_of(reference: &str) -> Result<&str, String> {
    reference
        .split_once('@')
        .map(|(_, digest)| digest)
        .ok_or_else(|| format!("FAIL: {reference} carries no @<digest>"))
}

/// Every cached artifact for `digest`, as a sorted JSON object of
/// `path -> [bytes, sha256]`, with the artifact count. Sorted keys are what let
/// the row `cmp` two runs.
fn inventory(cache: &Path, reference: &str, fixture: &Path) -> Result<(usize, String), String> {
    let digest = digest_of(reference)?;
    let fixture_bytes =
        fs::read(fixture).map_err(|error| format!("cannot read {}: {error}", fixture.display()))?;
    let mut artifacts: Vec<PathBuf> = Vec::new();

    for manifest_path in manifest_files(&cache.join("manifests"))? {
        let doc = read_json(&manifest_path)?;
        if field(&doc, "manifest_digest", &manifest_path)? != digest {
            continue;
        }
        check_metadata(&doc, digest, &fixture_bytes, fixture)?;
        artifacts.push(manifest_path);
        let safe = digest.replace(':', "_");
        artifacts.push(cache.join("fsmeta").join(format!("{safe}.erofs")));
        let descriptor = cache.join("vmdk").join(format!("{safe}.vmdk"));
        artifacts.extend(vmdk_extents(&descriptor)?);
        artifacts.push(descriptor);
        for layer in array(&doc, "layers", "the cached manifest")? {
            let diff_id = field(layer, "diff_id", Path::new("the cached layer"))?;
            let layer_digest = field(layer, "digest", Path::new("the cached layer"))?;
            artifacts.push(
                cache
                    .join("layers")
                    .join(format!("{}.erofs", safe_id(diff_id))),
            );
            let blob = cache
                .join("layers")
                .join(format!("{}.tar.gz", safe_id(layer_digest)));
            // A blob is only present when the metadata referenced one; its absence
            // is not a failure, its presence is part of the inventory.
            if blob.exists() {
                artifacts.push(blob);
            }
        }
    }
    if artifacts.is_empty() {
        return Err(format!(
            "FAIL: no cached metadata for retained digest {digest}"
        ));
    }

    let mut inventory: BTreeMap<String, Value> = BTreeMap::new();
    for path in artifacts {
        let bytes = fs::read(&path)
            .map_err(|error| format!("FAIL: cannot read {}: {error}", path.display()))?;
        let digest = hex(&bytes);
        inventory.insert(
            path.display().to_string(),
            Value::Array(vec![Value::from(bytes.len() as u64), Value::from(digest)]),
        );
    }
    let count = inventory.len();
    let document = serde_json::to_string(&inventory)
        .map_err(|error| format!("FAIL: cannot encode the inventory: {error}"))?;
    Ok((count, document))
}

/// The checks that make a matching `manifest_digest` evidence about *this* image:
/// the fixture is the bytes the digest names, and every hash the metadata claims
/// holds.
fn check_metadata(
    doc: &Value,
    digest: &str,
    fixture_bytes: &[u8],
    fixture: &Path,
) -> Result<(), String> {
    let fixture_digest = format!("sha256:{}", hex(fixture_bytes));
    if fixture_digest != digest {
        return Err(format!(
            "FAIL: {} hashes to {fixture_digest}, not the retained {digest}",
            fixture.display()
        ));
    }
    let raw_manifest = field(doc, "raw_manifest_json", Path::new("the cached metadata"))?;
    let cached: Value = serde_json::from_str(raw_manifest)
        .map_err(|error| format!("FAIL: raw_manifest_json is not JSON: {error}"))?;
    let fetched: Value = serde_json::from_slice(fixture_bytes)
        .map_err(|error| format!("FAIL: the registry manifest is not JSON: {error}"))?;
    if cached != fetched {
        return Err(
            "FAIL: the cached manifest is not the registry manifest for the retained digest"
                .to_owned(),
        );
    }
    let raw_config = field(doc, "raw_config_json", Path::new("the cached metadata"))?;
    if format!("sha256:{}", hex(raw_config.as_bytes()))
        != field(doc, "config_digest", Path::new("the cached metadata"))?
    {
        return Err("FAIL: raw_config_json does not hash to config_digest".to_owned());
    }
    let config: Value = serde_json::from_str(raw_config)
        .map_err(|error| format!("FAIL: raw_config_json is not JSON: {error}"))?;
    let declared = config
        .get("rootfs")
        .and_then(|rootfs| rootfs.get("diff_ids"))
        .and_then(Value::as_array)
        .ok_or("FAIL: the cached image config declares no rootfs.diff_ids")?
        .clone();
    let cached_layers = array(doc, "layers", "the cached metadata")?
        .iter()
        .map(|layer| field(layer, "diff_id", Path::new("the cached layer")).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let declared = declared
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or("FAIL: a rootfs.diff_id is not a string")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if declared != cached_layers {
        return Err(format!(
            "FAIL: the cached layers {cached_layers:?} are not the config's diff_ids {declared:?}"
        ));
    }
    Ok(())
}

fn manifest_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        // No metadata directory at all is "no cached metadata", which the caller
        // reports; it is not a read failure.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(files),
        Err(error) => {
            return Err(format!(
                "FAIL: cannot list {}: {error}",
                directory.display()
            ));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("FAIL: cannot list a cache entry: {error}"))?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("FAIL: cannot read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("FAIL: {} is not JSON: {error}", path.display()))
}

fn field<'a>(value: &'a Value, key: &str, what: &Path) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("FAIL: {} has no string {key}", what.display()))
}

fn array<'a>(value: &'a Value, key: &str, what: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("FAIL: {what} has no array {key}"))
}

/// The extent files a VMDK descriptor names. Lines for other record kinds carry
/// no extent, so only the two that do are parsed.
fn vmdk_extents(descriptor: &Path) -> Result<Vec<PathBuf>, String> {
    let text = fs::read_to_string(descriptor)
        .map_err(|error| format!("FAIL: cannot read {}: {error}", descriptor.display()))?;
    let parent = descriptor.parent().unwrap_or(Path::new("."));
    let mut extents = Vec::new();
    for line in text.lines() {
        if !(line.starts_with("RW ") || line.starts_with("RDONLY ")) {
            continue;
        }
        let quoted = quoted_path(line).ok_or_else(|| {
            format!(
                "FAIL: {} names an extent without a quoted path: {line}",
                descriptor.display()
            )
        })?;
        let extent = PathBuf::from(quoted);
        extents.push(if extent.is_absolute() {
            extent
        } else {
            parent.join(extent)
        });
    }
    Ok(extents)
}

fn quoted_path(line: &str) -> Option<&str> {
    let start = line.find('"')? + 1;
    let end = start + line[start..].find('"')?;
    (end > start).then(|| &line[start..end])
}

fn safe_id(digest: &str) -> String {
    digest.replace(':', "_")
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn self_test() -> Result<(), String> {
    let scratch = crate::scratch::Scratch::new("e2e-cache-inventory")
        .map_err(|error| format!("cannot create the control directory: {error}"))?;
    let cache = scratch.path().join("cache");
    let layer_bytes = b"layer-bytes".to_vec();
    let config = serde_json::json!({
        "architecture": "arm64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{}", hex(&layer_bytes))]},
        "config": {},
    });
    let config_bytes = serde_json::to_vec(&config).map_err(|error| error.to_string())?;
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "config": {"digest": format!("sha256:{}", hex(&config_bytes)), "size": config_bytes.len()},
        "layers": [{"digest": format!("sha256:{}", hex(&layer_bytes)), "size": layer_bytes.len()}],
    });
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
    let digest = format!("sha256:{}", hex(&manifest_bytes));
    let reference = format!("localhost:5000/probe@{}", digest.clone());
    let fixture = scratch.path().join("manifest.json");
    fs::write(&fixture, &manifest_bytes).map_err(describe)?;

    let safe = safe_id(&digest);
    let mut cached = manifest.clone();
    let owner = cached
        .as_object_mut()
        .ok_or("the control manifest is not an object")?;
    owner.insert("manifest_digest".to_owned(), Value::from(digest.clone()));
    owner.insert(
        "raw_manifest_json".to_owned(),
        Value::from(String::from_utf8(manifest_bytes.clone()).map_err(|error| error.to_string())?),
    );
    owner.insert(
        "raw_config_json".to_owned(),
        Value::from(String::from_utf8(config_bytes.clone()).map_err(|error| error.to_string())?),
    );
    owner.insert(
        "config_digest".to_owned(),
        Value::from(format!("sha256:{}", hex(&config_bytes))),
    );
    owner.insert(
        "layers".to_owned(),
        Value::Array(vec![serde_json::json!({
            "diff_id": format!("sha256:{}", hex(&layer_bytes)),
            "digest": format!("sha256:{}", hex(&layer_bytes)),
        })]),
    );

    for directory in ["manifests", "fsmeta", "vmdk", "layers"] {
        fs::create_dir_all(cache.join(directory)).map_err(describe)?;
    }
    fs::write(
        cache.join("manifests").join(format!("{safe}.json")),
        serde_json::to_vec(&cached).map_err(|error| error.to_string())?,
    )
    .map_err(describe)?;
    fs::write(
        cache.join("fsmeta").join(format!("{safe}.erofs")),
        b"fsmeta",
    )
    .map_err(describe)?;
    // The second extent is an absolute path, as a real descriptor may name one.
    let absolute = scratch.path().join("absolute-extent.vmdk");
    fs::write(
        cache.join("vmdk").join(format!("{safe}.vmdk")),
        format!(
            "# Disk DescriptorFile\nRW 65536 SPARSE \"extent-flat.vmdk\"\nRDONLY 128 FLAT \"{}\"\n",
            absolute.display()
        ),
    )
    .map_err(describe)?;
    fs::write(cache.join("vmdk/extent-flat.vmdk"), b"flat").map_err(describe)?;
    fs::write(&absolute, b"absolute-extent").map_err(describe)?;
    fs::write(
        cache.join("layers").join(format!(
            "{}.erofs",
            safe_id(&format!("sha256:{}", hex(&layer_bytes)))
        )),
        b"layer",
    )
    .map_err(describe)?;
    // Metadata for another image is skipped, not merged.
    fs::write(
        cache.join("manifests").join("sha256_other.json"),
        serde_json::to_vec(&serde_json::json!({"manifest_digest": "sha256:other"}))
            .map_err(|error| error.to_string())?,
    )
    .map_err(describe)?;

    let (count, document) = inventory(&cache, &reference, &fixture)?;
    let parsed: BTreeMap<String, Value> =
        serde_json::from_str(&document).map_err(|error| error.to_string())?;
    let manifest_key = cache.join("manifests").join(format!("{safe}.json"));
    for expected in [
        manifest_key.clone(),
        cache.join("fsmeta").join(format!("{safe}.erofs")),
        cache.join("vmdk").join(format!("{safe}.vmdk")),
        cache.join("vmdk/extent-flat.vmdk"),
        absolute.clone(),
    ] {
        if !parsed.contains_key(&expected.display().to_string()) {
            return Err(format!(
                "the inventory is missing {}: {document}",
                expected.display()
            ));
        }
    }
    if count != 6 {
        return Err(format!(
            "the inventory counted {count} artifacts, want 6: {document}"
        ));
    }
    if parsed.keys().any(|key| key.contains("other")) {
        return Err("the inventory merged another image's metadata".to_owned());
    }
    let fsmeta = parsed
        .get(
            &cache
                .join("fsmeta")
                .join(format!("{safe}.erofs"))
                .display()
                .to_string(),
        )
        .and_then(Value::as_array)
        .ok_or("the fsmeta artifact has no record")?;
    if fsmeta[0] != 6_u64 || fsmeta[1] != hex(b"fsmeta") {
        return Err(format!("the fsmeta record is {fsmeta:?}"));
    }
    if inventory(&cache, &reference, &fixture)?.1 != document {
        return Err("the inventory is not stable between runs".to_owned());
    }

    // Mutations the row's claim depends on.
    let wrong_fixture = scratch.path().join("wrong-manifest.json");
    fs::write(&wrong_fixture, b"{}").map_err(describe)?;
    let error = inventory(&cache, &reference, &wrong_fixture)
        .err()
        .ok_or("a fixture that does not hash to the digest was accepted")?;
    if !error.contains("not the retained") {
        return Err(format!(
            "a wrong fixture failed without its message: {error}"
        ));
    }
    let other_reference = "localhost:5000/probe@sha256:nothing".to_owned();
    let error = inventory(&cache, &other_reference, &fixture)
        .err()
        .ok_or("an unmatched digest produced an inventory")?;
    if !error.contains("no cached metadata for retained digest") {
        return Err(format!(
            "an unmatched digest failed without its message: {error}"
        ));
    }
    if digest_of("localhost:5000/probe:tag").is_ok() {
        return Err("a reference without a digest was accepted".to_owned());
    }
    let tampered = cache.join("fsmeta").join(format!("{safe}.erofs"));
    fs::write(&tampered, b"tampered").map_err(describe)?;
    if inventory(&cache, &reference, &fixture)?.1 == document {
        return Err("a tampered artifact left the inventory unchanged".to_owned());
    }
    Ok(())
}

fn describe(error: std::io::Error) -> String {
    format!("control setup failed: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cache_inventory_controls_hold() {
        self_test().expect("e2e cache-inventory controls pass");
    }
}
