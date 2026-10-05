//! Read official spec files at the commit pinned in `spec.lock`.
//!
//! Vectors are never copied into this repository. Tests read them from a
//! checkout of `openlfcp/spec` with `git show <commit>:<path>`, so the
//! working tree of that checkout does not matter. The checkout is found at
//! `$LFCP_SPEC_DIR`, or `../spec` next to this repository by default; a
//! relative `LFCP_SPEC_DIR` is resolved against this repository's root.
//!
//! Before reading anything, [`Spec::open`] checks that the locked tag
//! resolves to the locked commit, and panics with a clear message if not.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The pin recorded in `spec.lock`.
pub struct SpecLock {
    pub tag: String,
    pub commit: String,
}

/// A spec checkout verified against `spec.lock`.
pub struct Spec {
    dir: PathBuf,
    lock: SpecLock,
}

impl Spec {
    /// Locate the spec checkout and verify that it matches `spec.lock`.
    pub fn open() -> Spec {
        let root = repo_root();
        let lock = read_lock(&root.join("spec.lock"));
        let dir = match env::var_os("LFCP_SPEC_DIR") {
            Some(dir) => root.join(dir),
            None => root.join("../spec"),
        };

        let resolved = git(
            &dir,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("refs/tags/{}^{{commit}}", lock.tag),
            ],
        )
        .unwrap_or_else(|err| {
            panic!(
                "spec.lock pins tag {} but it does not resolve in the spec checkout at {}: {err}\n\
                     Clone openlfcp/spec there with its tags, or set LFCP_SPEC_DIR.",
                lock.tag,
                dir.display(),
            )
        });
        let resolved = String::from_utf8(resolved).expect("git rev-parse prints UTF-8");
        let resolved = resolved.trim();
        assert_eq!(
            resolved,
            lock.commit,
            "spec tag {} in {} resolves to {resolved}, but spec.lock pins {}. \
             Tags are never moved, so the checkout or spec.lock is wrong.",
            lock.tag,
            dir.display(),
            lock.commit,
        );

        Spec { dir, lock }
    }

    /// The pin this checkout was verified against.
    pub fn lock(&self) -> &SpecLock {
        &self.lock
    }

    /// The bytes of `path` at the locked commit.
    pub fn read(&self, path: &str) -> Vec<u8> {
        git(
            &self.dir,
            &["show", &format!("{}:{path}", self.lock.commit)],
        )
        .unwrap_or_else(|err| {
            panic!(
                "cannot read {path} at spec commit {}: {err}",
                self.lock.commit
            )
        })
    }

    /// `path` at `commit`, a full commit ID of the same checkout, parsed as
    /// JSON. For spec files newer than the locked baseline; each caller
    /// names its commit and says why.
    pub fn read_json_at(&self, commit: &str, path: &str) -> serde_json::Value {
        let bytes = git(&self.dir, &["show", &format!("{commit}:{path}")])
            .unwrap_or_else(|err| panic!("cannot read {path} at spec commit {commit}: {err}"));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|err| panic!("{path} at spec commit {commit} is not JSON: {err}"))
    }

    /// `path` at the locked commit, parsed as JSON.
    pub fn read_json(&self, path: &str) -> serde_json::Value {
        serde_json::from_slice(&self.read(path)).unwrap_or_else(|err| {
            panic!(
                "{path} at spec commit {} is not JSON: {err}",
                self.lock.commit
            )
        })
    }
}

/// The root of this repository (the Cargo workspace).
fn repo_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.canonicalize().unwrap_or(root)
}

fn read_lock(path: &Path) -> SpecLock {
    let text =
        std::fs::read(path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    let value: serde_json::Value = serde_json::from_slice(&text)
        .unwrap_or_else(|err| panic!("{} is not JSON: {err}", path.display()));
    let field = |name: &str| -> String {
        value[name]
            .as_str()
            .unwrap_or_else(|| panic!("{} has no string field {name:?}", path.display()))
            .to_owned()
    };
    let lock = SpecLock {
        tag: field("tag"),
        commit: field("commit"),
    };
    assert!(
        lock.commit.len() == 40
            && lock
                .commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{} must pin a full lowercase 40-hex commit, got {:?}",
        path.display(),
        lock.commit,
    );
    lock
}

/// Run `git -C dir <args>` and return its stdout, or a description of the
/// failure.
fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|err| format!("cannot run git: {err}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "git {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        ))
    }
}
