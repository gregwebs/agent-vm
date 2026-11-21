//! A directory a control may write into, removed on drop.
//!
//! `--self-test` runs in CI on every harness change, so a control that leaves a
//! file behind either pollutes `/tmp` for the next run or fails on a second
//! invocation. The label names the control, which is what shows up in `ls -d
//! /tmp/*` when something *does* die before `Drop`.

use std::{env, fs, io, path::PathBuf, sync::atomic::AtomicUsize};

static NEXT: AtomicUsize = AtomicUsize::new(0);

pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(label: &str) -> io::Result<Self> {
        let path = env::temp_dir().join(format!(
            "agent-vm-harness-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
