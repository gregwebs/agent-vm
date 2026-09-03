use std::{
    ffi::{OsStr, OsString},
    sync::{Mutex, MutexGuard, OnceLock},
};

static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    previous: Vec<(&'static str, Option<OsString>)>,
}

pub(crate) fn guard() -> EnvGuard {
    let lock = ENV_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    EnvGuard {
        _lock: lock,
        previous: Vec::new(),
    }
}

impl EnvGuard {
    pub(crate) fn set_var(&mut self, name: &'static str, value: impl AsRef<OsStr>) {
        self.record(name);
        // Tests cooperate through the process-wide guard, including child spawns.
        unsafe { std::env::set_var(name, value) };
    }

    pub(crate) fn remove_var(&mut self, name: &'static str) {
        self.record(name);
        // Tests cooperate through the process-wide guard, including child spawns.
        unsafe { std::env::remove_var(name) };
    }

    fn record(&mut self, name: &'static str) {
        if !self.previous.iter().any(|(recorded, _)| *recorded == name) {
            self.previous.push((name, std::env::var_os(name)));
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, previous) in self.previous.drain(..).rev() {
            // The mutex remains held until after all exact prior values are restored.
            unsafe {
                match previous {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_restores_the_prior_value_after_panic() {
        let name = "AGENT_VM_TEST_ENV_GUARD";
        let prior = std::env::var_os(name);
        let _ = std::panic::catch_unwind(|| {
            let mut env = guard();
            env.set_var(name, "temporary");
            panic!("test unwind");
        });
        assert_eq!(std::env::var_os(name), prior);
    }

    #[test]
    fn guard_serializes_mutation_restores_the_parent_and_child_snapshot() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let name = "AGENT_VM_TEST_ENV_GUARD_SERIALIZATION";
        let prior = std::env::var_os(name);
        let mut first = guard();
        first.set_var(name, "canary");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let acquired = Arc::new(AtomicBool::new(false));
        let second_acquired = Arc::clone(&acquired);
        let prior_for_second = prior.clone();
        let join = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let _second = guard();
            second_acquired.store(true, Ordering::SeqCst);
            assert_eq!(std::env::var_os(name), prior_for_second);
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!acquired.load(Ordering::SeqCst));
        drop(first);
        join.join().unwrap();
        let _restored = guard();
        assert_eq!(std::env::var_os(name), prior);
        let output = std::process::Command::new("sh")
            .args(["-c", &format!("printf %s \"${name}-\"")])
            .output()
            .unwrap();
        let expected = format!(
            "{}-",
            prior.as_deref().unwrap_or_default().to_string_lossy()
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    }
}
