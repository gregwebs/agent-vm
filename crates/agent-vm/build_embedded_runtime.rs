//! Build-time payload emission, compiled only for the opt-in release form.
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const ZSTD_LEVEL: i32 = 3;
const MSB_ENV: &str = "AGENT_VM_EMBED_MSB";
const LIBKRUNFW_ENV: &str = "AGENT_VM_EMBED_LIBKRUNFW";

fn fail(path: &Path, error: impl std::fmt::Display) -> ! {
    eprintln!(
        "error: agent-vm feature `embedded-runtime` needs {}: {error}\nBuild the runtime and the single binary together with ./script/build/macos.sh --single-binary, or set AGENT_VM_EMBED_MSB and AGENT_VM_EMBED_LIBKRUNFW.",
        path.display()
    );
    std::process::exit(1)
}

fn source(var: &str, default: Option<PathBuf>, os: &str) -> PathBuf {
    let path = env::var_os(var).map(PathBuf::from).or(default).unwrap_or_else(|| {
        eprintln!("error: agent-vm feature `embedded-runtime` has no default runtime for target OS {os}; set AGENT_VM_EMBED_MSB and AGENT_VM_EMBED_LIBKRUNFW.");
        std::process::exit(1)
    });
    let path = if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .unwrap_or_else(|e| fail(&path, e))
            .join(path)
    };
    if path.to_str().is_none_or(|s| s.contains(['\n', '\r'])) {
        fail(&path, "payload path must be UTF-8 without newlines");
    }
    println!("cargo:rerun-if-changed={}", path.display());
    path
}

fn compress(src: &Path, dst: &Path) -> io::Result<(u64, [u8; 32])> {
    let mut input = File::open(src)?;
    let mut encoder = zstd::stream::write::Encoder::new(File::create(dst)?, ZSTD_LEVEL)?;
    let mut hash = Sha256::new();
    let mut len = 0;
    let mut buf = [0; 64 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        encoder.write_all(&buf[..n])?;
        hash.update(&buf[..n]);
        len += n as u64;
    }
    encoder.finish()?;
    Ok((len, hash.finalize().into()))
}

pub fn emit(repo_root: &Path) {
    println!("cargo:rerun-if-changed=build_embedded_runtime.rs");
    for var in [MSB_ENV, LIBKRUNFW_ENV] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    let os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo supplies target OS");
    let default = (os == "macos").then(|| repo_root.join("vendor/microsandbox/build"));
    let msb = source(MSB_ENV, default.as_ref().map(|p| p.join("msb")), &os);
    let lib = source(
        LIBKRUNFW_ENV,
        default.map(|p| p.join("libkrunfw.5.dylib")),
        &os,
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"))
        .join("embedded-runtime");
    fs::create_dir_all(&out).unwrap_or_else(|e| fail(&out, e));
    let mut expression = String::from("Payload {\n");
    for (name, src) in [("msb", msb), ("libkrunfw", lib)] {
        let (len, sha256) =
            compress(&src, &out.join(format!("{name}.zst"))).unwrap_or_else(|e| fail(&src, e));
        expression.push_str(&format!("{name}: PayloadFile {{ compressed: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/embedded-runtime/{name}.zst\")), len: {len}, sha256: {sha256:?} }},\n"));
    }
    expression.push('}');
    fs::write(out.join("payload.rs"), expression).unwrap_or_else(|e| fail(&out, e));
}
