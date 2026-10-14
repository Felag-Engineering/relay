//! Local Template Operation loading — the distribution-less half of the
//! template tier (ADR-0021, ADR-0002 trust root).
//!
//! Templates load from **root-owned local files beside `policy.toml`**, never
//! over the wire: the Relay may *read* a Node's template set (that is what the
//! fingerprint and the reported descriptors are for) but can never author or
//! modify it. ADR-0002's model applies to templates verbatim — widening a
//! Node's vocabulary requires local or out-of-band access (config management,
//! SSH), exactly like widening its Policy.
//!
//! # Layout and the template-pack convention
//!
//! ```text
//! /etc/relay-daemon/
//!   policy.toml                     # the Node's Policy (ADR-0002)
//!   templates.d/                    # the template root (RELAY_TEMPLATE_DIR)
//!     local.toml                    # loose operator-authored file
//!     relay-read/                   # a PACK: installed and versioned as a unit
//!       catalog.toml
//! ```
//!
//! A **template pack** is one immediate subdirectory of the template root,
//! installed and versioned as a unit (the shipped read catalog, #293, is the
//! first one). Loose `*.toml` files directly in the root are equally valid for
//! an operator's own templates. Nesting stops there: a directory inside a pack
//! is skipped with a warning rather than silently traversed, so what loads is
//! always exactly what an operator can see in two levels of `ls`.
//!
//! # Fail-closed, whole-set
//!
//! Every failure mode — an insecure file, a parse error, a template that would
//! shadow a Native Operation, a duplicate name — fails the **whole set**, not
//! just the offending file. A partial vocabulary is the dangerous outcome: it
//! silently changes which Operations a Node answers while looking healthy. An
//! unloadable set leaves the Node with **no** Template Operations (every
//! template dispatch reports `unsupported`) and reports the
//! [`UNLOADABLE_FINGERPRINT`] sentinel, so the failure is visible fleet-wide in
//! the registry instead of hiding as a plausible-looking hash.
//!
//! # File hardening
//!
//! Each template file is opened and validated exactly like the Policy file
//! (`policy::load_policy`), through the one shared open both
//! loaders use (`hardened_open`): a single descriptor, `O_NOFOLLOW`
//! (symlinks refused), `O_NONBLOCK` (a FIFO cannot stall the daemon at boot),
//! `fstat` on that descriptor for regular-file/mode/owner checks, and the bytes
//! read from the same descriptor — so the bytes validated are the bytes loaded.
//! Directory entries are typed with `DirEntry::file_type` (an `lstat`, no
//! follow), so a symlinked file or pack is refused before it is ever opened.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::gen::{TemplateDescriptor, TemplateSlot, TemplateSnapshot};
use crate::hardened_open::{open_hardened, HardenedRejection};
use crate::operations::registry::{ResolvedOp, REGISTRY};
use crate::operations::template::{compile, TemplateDef, TemplateError, TemplateOp};
use crate::policy::{LintFinding, LintSeverity};

// ---------------------------------------------------------------------------
// Bounds — a template root is operator-controlled, but a bounded loader is
// still the right posture for anything that runs before the daemon is up.
// ---------------------------------------------------------------------------

/// Largest single template file the loader will read.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Largest number of template files (loose + packed) in one root.
const MAX_FILES: usize = 256;

/// Largest number of Template Operations one Node may load.
const MAX_TEMPLATES: usize = 512;

/// The `template_set_fingerprint` reported when the local template set failed
/// to load. Deliberately **not** 64-hex, so it can never be mistaken for a real
/// digest: an operator (or the Console) sees at a glance that this Node's
/// template vocabulary is empty because loading failed, not because no
/// templates are installed (which reports the empty string).
pub const UNLOADABLE_FINGERPRINT: &str = "unloadable";

/// Domain-separation prefix for the fingerprint stream, so a template-set
/// fingerprint can never collide with a Policy fingerprint (raw file bytes)
/// even for identical content.
const FINGERPRINT_DOMAIN: &[u8] = b"relay-template-set-v1\n";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from loading a Node's local template set. Every variant is
/// fail-closed: the caller ends up with an empty template vocabulary.
#[derive(Debug, thiserror::Error)]
pub enum TemplateLoadError {
    #[error("template root {path} is a symlink; refusing to follow (fail closed)")]
    SymlinkRoot { path: PathBuf },

    #[error("template root {path} is not a directory; refusing to load (fail closed)")]
    RootNotDirectory { path: PathBuf },

    #[error("template path {path} is a symlink; refusing to follow (fail closed)")]
    SymlinkEntry { path: PathBuf },

    #[error("template file {path} is not a regular file; refusing to load (fail closed)")]
    NotRegularFile { path: PathBuf },

    #[error("template file {path} has insecure permissions (mode {mode:#o}); group/world-writable — refusing to load (fail closed)")]
    InsecurePermissions { path: PathBuf, mode: u32 },

    #[error("template file {path} has insecure owner (uid {uid}); must be owned by root or the daemon euid — refusing to load (fail closed)")]
    InsecureOwner { path: PathBuf, uid: u32 },

    #[error("template file {path} exceeds {max} bytes; refusing to load (fail closed)")]
    FileTooLarge { path: PathBuf, max: u64 },

    #[error("template root holds more than {max} template files; refusing to load (fail closed)")]
    TooManyFiles { max: usize },

    #[error("template root declares more than {max} Template Operations; refusing to load (fail closed)")]
    TooManyTemplates { max: usize },

    #[error("template {name:?} (in {path}) is declared more than once in this template set")]
    DuplicateName { name: String, path: PathBuf },

    #[error("template {name:?} (in {path}) would shadow the Native Operation of the same name; the native vocabulary is frozen and cannot be overridden (ADR-0021)")]
    ShadowsNativeOperation { name: String, path: PathBuf },

    #[error("template file {path} is invalid: {source}")]
    Invalid {
        path: PathBuf,
        #[source]
        source: TemplateError,
    },

    #[error("template file {path} failed to parse: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("template file {path} is not valid UTF-8; refusing to load (fail closed)")]
    NotUtf8 { path: PathBuf },

    #[error("template path {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

// ---------------------------------------------------------------------------
// File format
// ---------------------------------------------------------------------------

/// One template file: an array of `[[template]]` blocks.
///
/// `deny_unknown_fields` at the file level so a typo'd top-level key (e.g.
/// `[[templates]]`) is a load error rather than a silently-ignored section that
/// leaves the operator believing a template is live when it is not.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateFile {
    #[serde(default)]
    template: Vec<TemplateDef>,
}

// ---------------------------------------------------------------------------
// The loaded set
// ---------------------------------------------------------------------------

/// A Node's loaded Template Operations, keyed by name, plus the fingerprint of
/// the files they came from.
///
/// Immutable after construction — the wire can never add to it (ADR-0002).
#[derive(Debug)]
pub struct TemplateSet {
    templates: BTreeMap<String, TemplateOp>,
    fingerprint: String,
}

impl TemplateSet {
    /// The empty set: no templates installed. Reports an empty fingerprint.
    pub fn empty() -> TemplateSet {
        TemplateSet {
            templates: BTreeMap::new(),
            fingerprint: String::new(),
        }
    }

    /// The fail-closed set: loading failed, so this Node has NO Template
    /// Operations and says so loudly via [`UNLOADABLE_FINGERPRINT`].
    pub fn unloadable() -> TemplateSet {
        TemplateSet {
            templates: BTreeMap::new(),
            fingerprint: UNLOADABLE_FINGERPRINT.to_string(),
        }
    }

    /// Load every template under `root`, or fail closed.
    ///
    /// A missing root is **not** an error: a Node with no templates installed
    /// is the normal case until a pack is deployed. Everything else — an
    /// insecure file, a bad parse, a name collision — fails the whole set.
    pub fn load(root: &Path) -> Result<TemplateSet, TemplateLoadError> {
        let files = match collect_files(root)? {
            Some(files) => files,
            // Root absent: no templates installed.
            None => return Ok(TemplateSet::empty()),
        };

        let mut contents: Vec<(String, PathBuf, Vec<u8>)> = Vec::with_capacity(files.len());
        for (rel, path) in files {
            let bytes = read_hardened(&path)?;
            contents.push((rel, path, bytes));
        }

        let fingerprint = fingerprint_files(&contents);

        let mut templates: BTreeMap<String, TemplateOp> = BTreeMap::new();
        for (_, path, bytes) in &contents {
            // Parse the exact bytes that were fingerprinted. `from_utf8_lossy`
            // would substitute U+FFFD for invalid sequences, so the compiled
            // template would silently differ from the bytes the fingerprint
            // attests — breaking the "bytes validated are the bytes loaded"
            // guarantee. TOML is required to be UTF-8, so reject non-UTF-8 and
            // fail the whole set closed.
            let text = std::str::from_utf8(bytes)
                .map_err(|_| TemplateLoadError::NotUtf8 { path: path.clone() })?;
            let file: TemplateFile =
                toml::from_str(text).map_err(|source| TemplateLoadError::Parse {
                    path: path.clone(),
                    source,
                })?;

            for def in &file.template {
                let op = compile(def).map_err(|source| TemplateLoadError::Invalid {
                    path: path.clone(),
                    source,
                })?;
                // The native vocabulary is frozen (ADR-0021) and is resolved
                // FIRST at dispatch: a template that shares a native name could
                // never run, so accepting it would only mislead. Refuse it.
                if REGISTRY.iter().any(|e| e.name == op.name()) {
                    return Err(TemplateLoadError::ShadowsNativeOperation {
                        name: op.name().to_string(),
                        path: path.clone(),
                    });
                }
                if templates.contains_key(op.name()) {
                    return Err(TemplateLoadError::DuplicateName {
                        name: op.name().to_string(),
                        path: path.clone(),
                    });
                }
                if templates.len() >= MAX_TEMPLATES {
                    return Err(TemplateLoadError::TooManyTemplates { max: MAX_TEMPLATES });
                }
                templates.insert(op.name().to_string(), op);
            }
        }

        Ok(TemplateSet {
            templates,
            fingerprint,
        })
    }

    /// Load `root`, falling back to the fail-closed empty set on any error.
    ///
    /// The daemon must still come up when its template set is broken — with no
    /// template vocabulary at all, which is the safe direction: every template
    /// dispatch then reports `unsupported` and the registry shows
    /// [`UNLOADABLE_FINGERPRINT`]. Mirrors `main`'s deny-all fallback for an
    /// unreadable Policy file.
    pub fn load_or_fail_closed(root: &Path) -> TemplateSet {
        match TemplateSet::load(root) {
            Ok(set) => {
                tracing::info!(
                    root = %root.display(),
                    templates = set.len(),
                    template_set_fingerprint = %set.fingerprint(),
                    "loaded template set"
                );
                set
            }
            Err(e) => {
                tracing::error!(
                    root = %root.display(),
                    error = %e,
                    "failed to load template set; continuing with NO Template Operations (fail closed)"
                );
                TemplateSet::unloadable()
            }
        }
    }

    /// Build a set directly from in-memory definitions, bypassing the file
    /// layer — for tests that exercise dispatch/scheduling against a template
    /// vocabulary rather than the loader itself.
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_test(defs: &[TemplateDef]) -> TemplateSet {
        let mut templates = BTreeMap::new();
        for def in defs {
            let op = compile(def).expect("test template must compile");
            templates.insert(op.name().to_string(), op);
        }
        TemplateSet {
            templates,
            fingerprint: "0".repeat(64),
        }
    }

    /// A process-wide empty set with a `'static` lifetime, for tests that need
    /// to borrow one across a `tokio::join!` (a temporary `TemplateSet::empty()`
    /// would not live long enough).
    #[cfg(any(test, feature = "test-util"))]
    pub fn empty_static() -> &'static TemplateSet {
        static EMPTY: std::sync::OnceLock<TemplateSet> = std::sync::OnceLock::new();
        EMPTY.get_or_init(TemplateSet::empty)
    }

    /// Resolve a Template Operation by name.
    pub fn lookup(&self, name: &str) -> Option<&TemplateOp> {
        self.templates.get(name)
    }

    /// The template-set fingerprint reported beside the Policy fingerprint:
    /// 64-hex for a loaded set, empty for "no templates installed", and
    /// [`UNLOADABLE_FINGERPRINT`] when loading failed.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Number of loaded Template Operations.
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// Whether no Template Operation is loaded.
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// The wire report of this Node's template vocabulary (display + discovery
    /// only; the daemon stays the sole enforcer). Descriptors are emitted in
    /// name order — the `BTreeMap`'s own — so a snapshot is stable across
    /// reconnects and diffable by eye.
    pub fn snapshot(&self) -> TemplateSnapshot {
        TemplateSnapshot {
            template_set_fingerprint: self.fingerprint.clone(),
            templates: self
                .templates
                .values()
                .map(|op| TemplateDescriptor {
                    name: op.name().to_string(),
                    risk_class: op.risk() as i32,
                    slots: op
                        .slot_specs()
                        .into_iter()
                        .map(|(name, ty)| TemplateSlot {
                            name: name.to_string(),
                            r#type: ty.type_name().to_string(),
                            enum_values: ty.enum_values().to_vec(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Lint API — collect-all diagnostics for `relay-daemon policy check
// --templates <dir>`, mirroring `policy::lint`'s contract
// ---------------------------------------------------------------------------

/// The result of linting a template root: every finding, plus the names that
/// did compile (so the Policy linter can resolve rules naming them).
#[derive(Debug, Default)]
pub struct TemplateLintReport {
    pub findings: Vec<LintFinding>,
    /// Names of the templates that compiled cleanly, in canonical order.
    pub names: Vec<String>,
    /// The subset of [`Self::names`] whose templates declare at least one
    /// `path`-typed slot — the only ones a *path* can legitimately be passed
    /// to, and therefore the only ones the self-reference lint probes with one
    /// (probing a unit-name slot with a path would report a reach that the
    /// template's own typed validation makes impossible).
    pub path_slot_names: Vec<String>,
}

/// Lints every template file under `root`, collecting **all** findings rather
/// than failing closed on the first bad file.
///
/// Contrast [`TemplateSet::load`], which is fail-closed for runtime loading
/// (one bad file ⇒ no vocabulary at all): a pipeline linter needs to report
/// every problem in one pass. This mirrors exactly the `lint` vs
/// `from_toml_str` split on the Policy side.
///
/// Like `policy check`'s Policy read, the linter **does not apply the runtime
/// ownership/mode gate**: it runs pre-deployment on a non-root IaC checkout,
/// where those checks (a runtime-load concern, re-applied by the daemon on the
/// Node) would spuriously reject a perfectly good file. Symlinks are still
/// refused — a symlinked template in the repo is a finding wherever it is read.
///
/// A missing root is not a finding: "no templates" is a valid configuration.
pub fn lint_dir(root: &Path) -> TemplateLintReport {
    let mut report = TemplateLintReport::default();

    let files = match collect_files(root) {
        Ok(Some(files)) => files,
        Ok(None) => return report,
        Err(e) => {
            report.findings.push(LintFinding {
                severity: LintSeverity::Error,
                location: root.display().to_string(),
                message: e.to_string(),
            });
            return report;
        }
    };

    // Where each accepted name came from, so a duplicate names both files.
    let mut seen: BTreeMap<String, String> = BTreeMap::new();

    for (rel, path) in files {
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                report.findings.push(LintFinding {
                    severity: LintSeverity::Error,
                    location: rel.clone(),
                    message: format!("failed to read: {e}"),
                });
                continue;
            }
        };
        if bytes.len() as u64 > MAX_FILE_BYTES {
            report.findings.push(LintFinding {
                severity: LintSeverity::Error,
                location: rel.clone(),
                message: format!("exceeds the {MAX_FILE_BYTES}-byte per-file limit"),
            });
            continue;
        }

        // Reject non-UTF-8 here too so `policy check --templates` catches it
        // before deployment — mirroring the runtime loader, which fails closed
        // rather than lossily substituting U+FFFD (see `load`).
        let text = match std::str::from_utf8(&bytes) {
            Ok(t) => t,
            Err(_) => {
                report.findings.push(LintFinding {
                    severity: LintSeverity::Error,
                    location: rel.clone(),
                    message: "is not valid UTF-8".to_string(),
                });
                continue;
            }
        };
        let file: TemplateFile = match toml::from_str(text) {
            Ok(f) => f,
            Err(e) => {
                report.findings.push(LintFinding {
                    severity: LintSeverity::Error,
                    location: rel.clone(),
                    message: format!("failed to parse: {e}"),
                });
                continue;
            }
        };

        if file.template.is_empty() {
            report.findings.push(LintFinding {
                severity: LintSeverity::Warning,
                location: rel.clone(),
                message: "declares no [[template]] blocks; the file loads but adds nothing"
                    .to_string(),
            });
        }

        for (i, def) in file.template.iter().enumerate() {
            let location = format!("{rel}: [[template]] #{i} (name={:?})", def.name);
            let op = match compile(def) {
                Ok(op) => op,
                Err(e) => {
                    report.findings.push(LintFinding {
                        severity: LintSeverity::Error,
                        location,
                        message: e.to_string(),
                    });
                    continue;
                }
            };
            if REGISTRY.iter().any(|entry| entry.name == op.name()) {
                report.findings.push(LintFinding {
                    severity: LintSeverity::Error,
                    location,
                    message: format!(
                        "shadows the Native Operation {:?}; the native vocabulary is frozen \
                         and always resolves first (ADR-0021)",
                        op.name()
                    ),
                });
                continue;
            }
            if let Some(other) = seen.get(op.name()) {
                report.findings.push(LintFinding {
                    severity: LintSeverity::Error,
                    location,
                    message: format!(
                        "duplicate template name {:?} (already declared in {other}); \
                         the whole set would fail to load",
                        op.name()
                    ),
                });
                continue;
            }
            if !op.path_slot_positions().is_empty() {
                report.path_slot_names.push(op.name().to_string());
            }
            seen.insert(op.name().to_string(), rel.clone());
        }
    }

    if seen.len() > MAX_TEMPLATES {
        report.findings.push(LintFinding {
            severity: LintSeverity::Error,
            location: root.display().to_string(),
            message: format!(
                "declares {} Template Operations; the maximum is {MAX_TEMPLATES}",
                seen.len()
            ),
        });
    }

    report.names = seen.into_keys().collect();
    report
}

// ---------------------------------------------------------------------------
// Directory walk — two levels, symlink-refusing, deterministic order
// ---------------------------------------------------------------------------

/// Collect `(relative path, absolute path)` for every template file under
/// `root`, in sorted relative-path order (the fingerprint's canonical order).
///
/// Returns `Ok(None)` when `root` does not exist.
fn collect_files(root: &Path) -> Result<Option<Vec<(String, PathBuf)>>, TemplateLoadError> {
    // symlink_metadata: never follow the root itself. A symlinked template root
    // would let anyone who controls the link target choose the vocabulary.
    let meta = match fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(TemplateLoadError::Io {
                path: root.to_path_buf(),
                source,
            })
        }
    };
    if meta.file_type().is_symlink() {
        return Err(TemplateLoadError::SymlinkRoot {
            path: root.to_path_buf(),
        });
    }
    if !meta.is_dir() {
        return Err(TemplateLoadError::RootNotDirectory {
            path: root.to_path_buf(),
        });
    }

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for entry in read_dir_sorted(root)? {
        let (name, file_type, path) = entry;
        if file_type.is_symlink() {
            return Err(TemplateLoadError::SymlinkEntry { path });
        }
        if file_type.is_dir() {
            // One level of packs; a directory inside a pack is skipped, loudly.
            for (pack_name, pack_type, pack_path) in read_dir_sorted(&path)? {
                if pack_type.is_symlink() {
                    return Err(TemplateLoadError::SymlinkEntry { path: pack_path });
                }
                if pack_type.is_dir() {
                    tracing::warn!(
                        path = %pack_path.display(),
                        "template pack contains a nested directory; not traversed (packs are one level deep)"
                    );
                    continue;
                }
                if is_template_file(&pack_name) {
                    files.push((format!("{name}/{pack_name}"), pack_path));
                }
            }
            continue;
        }
        if is_template_file(&name) {
            files.push((name, path));
        }
    }

    if files.len() > MAX_FILES {
        return Err(TemplateLoadError::TooManyFiles { max: MAX_FILES });
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Some(files))
}

/// `read_dir` yielding `(file name, file type, path)` sorted by name, with
/// non-UTF-8 names skipped (a template file needs a nameable path).
fn read_dir_sorted(dir: &Path) -> Result<Vec<(String, fs::FileType, PathBuf)>, TemplateLoadError> {
    let rd = fs::read_dir(dir).map_err(|source| TemplateLoadError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|source| TemplateLoadError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        // DirEntry::file_type is an lstat — it never follows a symlink, so a
        // symlinked entry is classified as a symlink and refused by the caller.
        let file_type = entry.file_type().map_err(|source| TemplateLoadError::Io {
            path: entry.path(),
            source,
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            tracing::warn!(
                path = %entry.path().display(),
                "template path is not valid UTF-8; skipped"
            );
            continue;
        };
        out.push((name, file_type, entry.path()));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Only `*.toml` files are templates; a pack may ship a README or a LICENSE
/// beside them without failing the load.
fn is_template_file(name: &str) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "toml")
}

// ---------------------------------------------------------------------------
// Hardened read (the `policy::load_policy` checks, per file)
// ---------------------------------------------------------------------------

/// Open once with `O_NOFOLLOW | O_NONBLOCK` and validate the descriptor
/// (regular file, not group/world-writable, owned by root or the daemon euid)
/// through the shared [`open_hardened`] — the same open `policy::load_policy`
/// uses — then apply this loader's own size cap and read the bytes from that
/// same descriptor.
fn read_hardened(path: &Path) -> Result<Vec<u8>, TemplateLoadError> {
    let (mut file, meta) = open_hardened(path).map_err(|rejection| {
        let path = path.to_path_buf();
        match rejection {
            HardenedRejection::Symlink => TemplateLoadError::SymlinkEntry { path },
            HardenedRejection::NotRegularFile => TemplateLoadError::NotRegularFile { path },
            HardenedRejection::InsecurePermissions { mode } => {
                TemplateLoadError::InsecurePermissions { path, mode }
            }
            HardenedRejection::InsecureOwner { uid } => {
                TemplateLoadError::InsecureOwner { path, uid }
            }
            HardenedRejection::Io(source) => TemplateLoadError::Io { path, source },
        }
    })?;

    if meta.len() > MAX_FILE_BYTES {
        return Err(TemplateLoadError::FileTooLarge {
            path: path.to_path_buf(),
            max: MAX_FILE_BYTES,
        });
    }

    // Read from the SAME descriptor that was validated above (closes the
    // metadata/read TOCTOU race), bounded by the cap regardless of what fstat
    // reported — a file that grows between fstat and read is truncated at the
    // cap and then fails the size check below rather than being read whole.
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| TemplateLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(TemplateLoadError::FileTooLarge {
            path: path.to_path_buf(),
            max: MAX_FILE_BYTES,
        });
    }

    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// SHA-256 over a canonical, unambiguous stream of the set's files:
///
/// ```text
/// "relay-template-set-v1\n" then, per file in sorted relative-path order:
///   <relative path> "\0" <byte length in decimal> "\n" <raw bytes>
/// ```
///
/// Length-prefixing the bytes and NUL-terminating the path make the encoding
/// injective: no rename or content edit can produce another set's stream.
/// Like the Policy fingerprint, this is over raw bytes — a cosmetic edit
/// changes it, which is exactly the drift signal policy-as-code needs.
fn fingerprint_files(files: &[(String, PathBuf, Vec<u8>)]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(FINGERPRINT_DOMAIN);
    for (rel, _, bytes) in files {
        ctx.update(rel.as_bytes());
        ctx.update(b"\0");
        ctx.update(bytes.len().to_string().as_bytes());
        ctx.update(b"\n");
        ctx.update(bytes);
    }
    let digest = ctx.finish();
    let mut s = String::with_capacity(64);
    for b in digest.as_ref() {
        write!(&mut s, "{b:02x}").expect("write to String is infallible");
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test fixtures build template trees; spawn calls are refused by clippy_write_ban.rs's spawn-site census"
)]
mod tests {
    use super::*;
    use crate::gen::RiskClass;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A self-cleaning temp directory (the daemon crate has no dev-dep on
    /// tempfile). Kept local rather than `crate::test_support::TempDir`: it is
    /// counter-named, clears any stale path first, and exposes `path` as a field.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("relay-templates-{tag}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }

        fn write(&self, rel: &str, contents: &str) -> PathBuf {
            let path = self.path.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(&path, contents).expect("write template file");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("set template file mode");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    const DISK: &str = r#"
[[template]]
name = "disk.usage"
risk_class = "read"
body = "df -PT"
"#;

    const LOG_TAIL: &str = r#"
[[template]]
name = "log.tail"
risk_class = "read"
body = "tail -n {{lines}} -- {{path}}"

[[template.slots]]
name = "lines"
type = "integer"

[[template.slots]]
name = "path"
type = "path"
"#;

    #[test]
    fn missing_root_is_an_empty_set_not_an_error() {
        let dir = TempDir::new("missing");
        let root = dir.path.join("does-not-exist");
        let set = TemplateSet::load(&root).expect("a missing root is not an error");
        assert_eq!(set.len(), 0);
        assert_eq!(set.fingerprint(), "", "no templates → empty fingerprint");
    }

    #[test]
    fn loads_loose_files_and_packs() {
        let dir = TempDir::new("load");
        dir.write("local.toml", DISK);
        dir.write("relay-read/catalog.toml", LOG_TAIL);

        let set = TemplateSet::load(&dir.path).expect("load");
        assert_eq!(set.len(), 2);
        assert!(set.lookup("disk.usage").is_some());
        assert!(set.lookup("log.tail").is_some());
        assert!(set.lookup("nope").is_none());
        assert_eq!(set.fingerprint().len(), 64, "loaded set → 64-hex digest");
    }

    #[test]
    fn non_toml_files_are_ignored() {
        let dir = TempDir::new("nontoml");
        dir.write("local.toml", DISK);
        dir.write("relay-read/README.md", "not a template");
        let set = TemplateSet::load(&dir.path).expect("load");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn invalid_utf8_fails_the_whole_set_closed() {
        let dir = TempDir::new("nonutf8");
        dir.write("good.toml", DISK);
        // A .toml file with an invalid UTF-8 byte (0xFF) inside a string value.
        // `from_utf8_lossy` would substitute U+FFFD and load it; the loader must
        // instead fail the whole set closed so the fingerprinted bytes always
        // equal the parsed bytes.
        let bad = dir.path.join("bad.toml");
        let mut bytes =
            b"[[template]]\nname = \"x\"\nrisk_class = \"read\"\nbody = \"echo ".to_vec();
        bytes.push(0xFF);
        bytes.extend_from_slice(b"\"\n");
        fs::write(&bad, &bytes).expect("write bad file");
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).expect("mode");

        let err = TemplateSet::load(&dir.path).expect_err("invalid UTF-8 must fail the set");
        assert!(
            matches!(err, TemplateLoadError::NotUtf8 { .. }),
            "expected NotUtf8, got {err:?}"
        );
    }

    #[test]
    fn snapshot_reports_names_risk_and_slots_in_name_order() {
        let dir = TempDir::new("snapshot");
        dir.write("a.toml", LOG_TAIL);
        dir.write("b.toml", DISK);

        let snap = TemplateSet::load(&dir.path).expect("load").snapshot();
        let names: Vec<&str> = snap.templates.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["disk.usage", "log.tail"], "name-sorted");
        assert_eq!(snap.templates[0].risk_class, RiskClass::Read as i32);
        assert!(snap.templates[0].slots.is_empty());

        let slots = &snap.templates[1].slots;
        assert_eq!(slots.len(), 2, "slots in declaration order");
        assert_eq!(slots[0].name, "lines");
        assert_eq!(slots[0].r#type, "integer");
        assert_eq!(slots[1].name, "path");
        assert_eq!(slots[1].r#type, "path");
        assert!(slots[0].enum_values.is_empty());
        assert_eq!(snap.template_set_fingerprint, {
            TemplateSet::load(&dir.path).expect("load").fingerprint
        });
    }

    #[test]
    fn enum_slot_values_reach_the_snapshot() {
        let dir = TempDir::new("enum");
        dir.write(
            "e.toml",
            r#"
[[template]]
name = "svc.status"
risk_class = "read"
body = "systemctl is-active {{unit}}"

[[template.slots]]
name = "unit"
type = "enum"
values = ["nginx", "sshd"]
"#,
        );
        let snap = TemplateSet::load(&dir.path).expect("load").snapshot();
        let slot = &snap.templates[0].slots[0];
        assert_eq!(slot.r#type, "enum");
        assert_eq!(slot.enum_values, ["nginx", "sshd"]);
    }

    #[test]
    fn fingerprint_is_deterministic_and_content_sensitive() {
        let a = TempDir::new("fp-a");
        a.write("x.toml", DISK);
        let first = TemplateSet::load(&a.path).expect("load").fingerprint;
        let second = TemplateSet::load(&a.path).expect("load").fingerprint;
        assert_eq!(first, second, "same bytes → same fingerprint");

        let b = TempDir::new("fp-b");
        b.write("x.toml", &format!("{DISK}\n# a comment\n"));
        let edited = TemplateSet::load(&b.path).expect("load").fingerprint;
        assert_ne!(first, edited, "edited bytes → different fingerprint");

        // Same bytes under a different file name is a different set: the path
        // is part of the canonical stream.
        let c = TempDir::new("fp-c");
        c.write("y.toml", DISK);
        assert_ne!(
            first,
            TemplateSet::load(&c.path).expect("load").fingerprint,
            "renaming a template file must change the fingerprint"
        );
    }

    #[test]
    fn fingerprint_is_domain_separated_from_the_policy_fingerprint() {
        // A template set whose single file's bytes are also a valid Policy must
        // not fingerprint like that Policy.
        let dir = TempDir::new("domain");
        dir.write("x.toml", DISK);
        let set_fp = TemplateSet::load(&dir.path).expect("load").fingerprint;
        let policy_like = crate::policy::from_toml_str("").expect("empty policy");
        assert_ne!(set_fp, policy_like.fingerprint());
    }

    #[test]
    fn a_template_may_not_shadow_a_native_operation() {
        let dir = TempDir::new("shadow");
        dir.write(
            "x.toml",
            r#"
[[template]]
name = "file.read"
risk_class = "read"
body = "cat /etc/hostname"
"#,
        );
        let err = TemplateSet::load(&dir.path).expect_err("must fail closed");
        assert!(
            matches!(err, TemplateLoadError::ShadowsNativeOperation { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn duplicate_names_fail_the_whole_set() {
        let dir = TempDir::new("dup");
        dir.write("a.toml", DISK);
        dir.write("b.toml", DISK);
        let err = TemplateSet::load(&dir.path).expect_err("must fail closed");
        assert!(
            matches!(err, TemplateLoadError::DuplicateName { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn one_bad_file_fails_the_whole_set() {
        let dir = TempDir::new("partial");
        dir.write("good.toml", DISK);
        dir.write(
            "bad.toml",
            r#"
[[template]]
name = "bad.template"
risk_class = "read"
body = "echo {{missing}}"
"#,
        );
        let err = TemplateSet::load(&dir.path).expect_err("must fail closed");
        assert!(
            matches!(err, TemplateLoadError::Invalid { .. }),
            "got {err:?}"
        );

        // ...and the daemon-facing fallback yields NO vocabulary, loudly.
        let set = TemplateSet::load_or_fail_closed(&dir.path);
        assert_eq!(set.len(), 0, "a partial vocabulary is never served");
        assert_eq!(set.fingerprint(), UNLOADABLE_FINGERPRINT);
    }

    #[test]
    fn missing_risk_class_fails_to_load() {
        let dir = TempDir::new("norisk");
        dir.write(
            "x.toml",
            r#"
[[template]]
name = "no.class"
body = "df -PT"
"#,
        );
        let err = TemplateSet::load(&dir.path).expect_err("risk_class is mandatory (ADR-0012)");
        assert!(
            matches!(err, TemplateLoadError::Parse { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_top_level_key_fails_to_load() {
        let dir = TempDir::new("typo");
        dir.write(
            "x.toml",
            r#"
[[templates]]
name = "typo.section"
risk_class = "read"
body = "df -PT"
"#,
        );
        let err =
            TemplateSet::load(&dir.path).expect_err("a typo'd section must not load silently");
        assert!(
            matches!(err, TemplateLoadError::Parse { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn symlinked_template_file_is_refused() {
        let dir = TempDir::new("symlink");
        let target = dir.write("real.txt", DISK);
        std::os::unix::fs::symlink(&target, dir.path.join("link.toml")).expect("symlink");
        let err = TemplateSet::load(&dir.path).expect_err("must refuse a symlink");
        assert!(
            matches!(err, TemplateLoadError::SymlinkEntry { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn symlinked_pack_directory_is_refused() {
        let dir = TempDir::new("symlink-pack");
        let real = TempDir::new("symlink-pack-target");
        real.write("catalog.toml", DISK);
        std::os::unix::fs::symlink(&real.path, dir.path.join("pack")).expect("symlink");
        let err = TemplateSet::load(&dir.path).expect_err("must refuse a symlinked pack");
        assert!(
            matches!(err, TemplateLoadError::SymlinkEntry { .. }),
            "got {err:?}"
        );
    }

    /// The open-time half of symlink refusal. `collect_files` refuses a
    /// symlinked entry by its `lstat` type before it is ever opened, so
    /// `TemplateSet::load` never reaches this path on a static tree; it exists
    /// for a file swapped for a symlink between the directory walk and the
    /// open, and `O_NOFOLLOW` must still refuse it there, as `SymlinkEntry`.
    #[test]
    fn read_hardened_refuses_a_symlink_at_open() {
        let dir = TempDir::new("symlink-open");
        let target = dir.write("real.toml", DISK);
        assert!(read_hardened(&target).is_ok(), "target alone must read");
        let link = dir.path.join("link.toml");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = read_hardened(&link).expect_err("must refuse a symlink at open");
        assert!(
            matches!(&err, TemplateLoadError::SymlinkEntry { path } if *path == link),
            "got {err:?}"
        );
    }

    #[test]
    fn third_party_owned_template_file_is_refused() {
        // Only root can hand a file to a uid that is neither 0 nor its own
        // euid; a non-root runner cannot build this fixture at all.
        if !rustix::process::geteuid().is_root() {
            eprintln!("skipped: needs root to chown a fixture to a third-party uid");
            return;
        }
        let dir = TempDir::new("owner");
        let path = dir.write("x.toml", DISK);
        assert!(
            TemplateSet::load(&dir.path).is_ok(),
            "root-owned fixture must load"
        );
        std::os::unix::fs::chown(&path, Some(65534), None).expect("chown");
        let err = TemplateSet::load(&dir.path).expect_err("must refuse a third-party owner");
        assert!(
            matches!(&err, TemplateLoadError::InsecureOwner { path: p, uid: 65534 } if *p == path),
            "got {err:?}"
        );
    }

    /// The gate is `mode & 0o022`: two independent bits, group-write (`0o020`)
    /// and other-write (`0o002`). Either one alone re-admits a template file
    /// that an unprivileged local user can rewrite, which is exactly what the
    /// filesystem trust root has to hold against (ADR-0021 on ADR-0002). So
    /// each case here trips **one** named bit; a mode that trips both at once
    /// (`0o666` on its own, as this test once was) proves nothing about either,
    /// and a mask narrowed to `0o002` or `0o020` would still pass it.
    #[test]
    fn group_or_world_writable_file_is_refused() {
        for (mode, bit) in [
            (0o664_u32, "group-writable, other-write clear"),
            (0o646_u32, "world-writable, group-write clear"),
            (0o666_u32, "both write bits"),
        ] {
            let dir = TempDir::new("perms");
            let path = dir.write("x.toml", DISK);
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
            let err = match TemplateSet::load(&dir.path) {
                Err(err) => err,
                Ok(_) => panic!("mode {mode:#o} ({bit}) must be refused"),
            };
            assert!(
                matches!(
                    err,
                    TemplateLoadError::InsecurePermissions { mode: reported, .. }
                        if reported == mode
                ),
                "mode {mode:#o} ({bit}); got {err:?}"
            );
        }
    }

    /// The accept side of the same gate, and the mirror of
    /// `group_or_world_writable_file_is_refused`: that test pins each *refused*
    /// bit, so the mask cannot be silently loosened; this one pins the
    /// *accepted* modes, so it cannot be silently tightened into refusing files
    /// the daemon must load (`0o022` widened to `0o023` or `0o222` fails closed
    /// — loud in operation, but invisible in a suite that only tests refusal).
    /// Shaped after `policy.rs`'s `loader_accepts_secure_modes`, and like it,
    /// the fixture is owned by the test runner rather than root, so it also
    /// exercises the loader's `uid == geteuid()` ownership branch.
    ///
    /// The two groups of modes make different claims. `0o600` and `0o644` are
    /// what a real template file carries — the shipped read catalog and every
    /// documented install line use `0644` (`docs/operations/template-packs.md`).
    /// The execute-bit cases claim nothing about shipping: templates are TOML
    /// data the daemon reads, never runs, and nothing here establishes that one
    /// is ever legitimately executable. They pin the *shape* of the mask — it
    /// gates write bits and only write bits, so an execute bit must never on
    /// its own refuse a file.
    #[test]
    fn secure_modes_are_accepted() {
        for (mode, why) in [
            (0o600_u32, "owner-only, as `TempDir::write` forces"),
            (0o644_u32, "what a shipped template file actually carries"),
            (0o645_u32, "other-execute set, no write bit"),
            (
                0o755_u32,
                "execute throughout, no group- or world-write bit",
            ),
        ] {
            let dir = TempDir::new("accept-perms");
            let path = dir.write("x.toml", DISK);
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");

            // Observe the fixture rather than assume it: `chmod(2)` is not
            // umask-masked, but this whole family of tests exists because a
            // fixture once carried different bits than its test claimed (#481).
            let landed = fs::metadata(&path).expect("stat").mode() & 0o777;
            assert_eq!(
                landed, mode,
                "fixture must land at {mode:#o} ({why}); got {landed:#o}"
            );

            let set = match TemplateSet::load(&dir.path) {
                Ok(set) => set,
                Err(err) => panic!("mode {mode:#o} ({why}) must be accepted; got {err:?}"),
            };
            assert_eq!(
                set.len(),
                1,
                "mode {mode:#o} ({why}) must load its template"
            );
        }
    }

    #[test]
    fn non_regular_template_file_is_refused() {
        let dir = TempDir::new("fifo");
        let fifo = dir.path.join("x.toml");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("cstring");
        // SAFETY: plain libc call with a valid NUL-terminated path.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

        let err = TemplateSet::load(&dir.path).expect_err("must refuse a FIFO");
        assert!(
            matches!(err, TemplateLoadError::NotRegularFile { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn root_that_is_not_a_directory_is_refused() {
        let dir = TempDir::new("notdir");
        let file = dir.write("root.toml", DISK);
        let err = TemplateSet::load(&file).expect_err("must refuse a non-directory root");
        assert!(
            matches!(err, TemplateLoadError::RootNotDirectory { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn nested_pack_directories_are_not_traversed() {
        let dir = TempDir::new("nested");
        dir.write("pack/catalog.toml", DISK);
        dir.write("pack/deeper/hidden.toml", LOG_TAIL);
        let set = TemplateSet::load(&dir.path).expect("load");
        assert_eq!(set.len(), 1, "only the pack's own files load");
        assert!(set.lookup("log.tail").is_none());
    }

    #[test]
    fn unloadable_and_empty_are_distinguishable() {
        assert_eq!(TemplateSet::empty().fingerprint(), "");
        assert_eq!(
            TemplateSet::unloadable().fingerprint(),
            UNLOADABLE_FINGERPRINT
        );
        assert_ne!(
            TemplateSet::unloadable().fingerprint().len(),
            64,
            "the sentinel must never look like a digest"
        );
    }
}
