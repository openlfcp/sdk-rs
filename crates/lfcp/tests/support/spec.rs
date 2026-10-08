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
//!
//! [`Spec::open_sections`] reads `spec-sections.lock` instead: a
//! development pin of the shared sections documents and corpus (MVP 0.2)
//! before their baseline is tagged. It has no tag; its commit must exist in
//! the same checkout. Only the shared sections files are read through it.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The pin recorded in `spec.lock`.
pub struct SpecLock {
    /// The baseline tag, or `None` for a development commit pin.
    pub tag: Option<String>,
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
        Spec::open_lock("spec.lock")
    }

    /// The development pin of the shared sections files,
    /// `spec-sections.lock` (no tag; the commit must exist).
    #[allow(dead_code)]
    pub fn open_sections() -> Spec {
        let spec = Spec::open_lock("spec-sections.lock");
        assert!(
            spec.lock.tag.is_none(),
            "spec-sections.lock pins a commit, not a tag"
        );
        spec
    }

    fn open_lock(name: &str) -> Spec {
        let root = repo_root();
        let lock = read_lock(&root.join(name));
        let dir = match env::var_os("LFCP_SPEC_DIR") {
            Some(dir) => root.join(dir),
            None => root.join("../spec"),
        };

        match &lock.tag {
            Some(tag) => {
                let resolved = git(
                    &dir,
                    &[
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        &format!("refs/tags/{tag}^{{commit}}"),
                    ],
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "spec.lock pins tag {tag} but it does not resolve in the spec checkout at {}: {err}\n\
                             Clone openlfcp/spec there with its tags, or set LFCP_SPEC_DIR.",
                        dir.display(),
                    )
                });
                let resolved = String::from_utf8(resolved).expect("git rev-parse prints UTF-8");
                let resolved = resolved.trim();
                assert_eq!(
                    resolved,
                    lock.commit,
                    "spec tag {tag} in {} resolves to {resolved}, but spec.lock pins {}. \
                     Tags are never moved, so the checkout or spec.lock is wrong.",
                    dir.display(),
                    lock.commit,
                );
            }
            None => {
                git(
                    &dir,
                    &["cat-file", "-e", &format!("{}^{{commit}}", lock.commit)],
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "spec.lock pins commit {} but the spec checkout at {} does not have it: {err}",
                        lock.commit,
                        dir.display(),
                    )
                });
            }
        }

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

    /// The file names in directory `dir` at the locked commit, sorted.
    pub fn list(&self, dir: &str) -> Vec<String> {
        let out = git(
            &self.dir,
            &[
                "ls-tree",
                "--name-only",
                &self.lock.commit,
                &format!("{}/", dir.trim_end_matches('/')),
            ],
        )
        .unwrap_or_else(|err| {
            panic!(
                "cannot list {dir} at spec commit {}: {err}",
                self.lock.commit
            )
        });
        let mut names: Vec<String> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|line| line.rsplit('/').next().unwrap().to_owned())
            .collect();
        names.sort();
        names
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
        tag: value["tag"].as_str().map(str::to_owned),
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
