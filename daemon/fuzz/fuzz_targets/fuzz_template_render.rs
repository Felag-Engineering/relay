//! Fuzzes Template render through `ResolvedOp::invoke` with a recording Runner
//! that never spawns a process.
//!
//! The render contract under test (EX-18, ADR-0021, invariant 1): the argv is
//! `["/bin/sh", "-c", <script fixed at compile>, "relay-template", v1..vN]`, so
//! no slot value is ever part of the text the shell parses. The oracles:
//!
//! * (a) `argv[4..]` is the values, verbatim and in slot order.
//! * (b) `argv[0..4]` does not depend on the values, and the script equals
//!   `expected_script`, a model independent of the relay-ops lexer.
//! * (c) Compile is deterministic. Valid values always render. A refused render
//!   spawns nothing and does not echo the value.
//! * (d) A value its slot type's validator refuses never renders. For a Path
//!   slot the code's verdict equals the model's in both directions.
//!
//! Limits. The script model has no lexer: it reads a body as plain text with
//! placeholders in it, so it gives no independent evidence about which shell
//! contexts compile refuses (arithmetic, `eval`, `sh -c`, here-documents). Bodies
//! in those contexts stay in the seeds so the refusals stay exercised. Oracle (a)
//! sees a Path position only as this binary's own path: a fuzzer-chosen path is
//! judged by the validator model and never rendered.
//!
//! Input: byte 0 is `sel`; the rest is UTF-8, split on U+001F. With bit 7 of
//! `sel` set, field 0 is a template file parsed through the loader's own serde
//! (`TemplateFileMirror`); otherwise it is the body of `render_def(sel, ..)`.
//! The remaining fields are the slot values, the same list for every definition.
//! U+001F is the one character that cannot occur in a body or a value; NUL, C1
//! and bidi controls stay reachable.
//!
//! A crash here is a Template structure or validator finding. File it, never
//! weaken the oracle. A path the fuzzer chose is never opened.
#![no_main]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use relay_daemon_fuzz::pb::{Operation, Outcome, TaskResult};
use relay_daemon_fuzz::policy_oracle::{deny_all, fields};
use relay_daemon_fuzz::render_oracle::{
    allow_any, canonical_values, expected_script, refusal_message_ok, render_def, value_ok,
};
use relay_daemon_fuzz::template_oracle::TemplateFileMirror;
use relay_exec::executor::ExecRequest;
use relay_ops::operations::registry::{OpCtx, OpFuture, ResolvedOp, Runner};
use relay_ops::operations::template::{
    compile, RiskClassDef, SlotDef, SlotType, TemplateDef, TemplateOp,
};
use relay_policy::Policy;

/// The most definitions one file-mode input checks.
const MAX_DEFS: usize = 16;

/// The runtime `invoke` runs on. One kept-alive blocking thread, so a path-slot
/// resolution never creates a thread per input.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(1)
            .thread_keep_alive(Duration::from_secs(3600))
            .build()
            .expect("build the harness runtime")
    })
}

/// A Template with a Path slot followed by an Integer slot that an empty value
/// always refuses. `invoke` validates every value before it opens anything, so
/// passing `[v, ""]` yields a verdict on `v` alone and opens no file.
fn probe() -> &'static TemplateOp {
    static PROBE: OnceLock<TemplateOp> = OnceLock::new();
    PROBE.get_or_init(|| {
        compile(&TemplateDef {
            name: "fuzz.probe".to_string(),
            risk_class: RiskClassDef::Read,
            body: "cat {{p}} {{z}}".to_string(),
            slots: vec![
                SlotDef {
                    name: "p".to_string(),
                    ty: SlotType::Path,
                },
                SlotDef {
                    name: "z".to_string(),
                    ty: SlotType::Integer,
                },
            ],
        })
        .expect("the probe template compiles")
    })
}

/// This binary's canonical path: the only Path value ever opened. Fixture checks
/// fail loudly and are not findings.
fn exe() -> &'static str {
    static EXE: OnceLock<String> = OnceLock::new();
    EXE.get_or_init(|| {
        let exe = std::fs::canonicalize(std::env::current_exe().expect("current_exe"))
            .expect("canonicalize the fuzz binary")
            .into_os_string()
            .into_string()
            .expect("the fuzz binary's path is UTF-8");
        assert!(
            value_ok(&SlotType::Path, &exe),
            "the fuzz binary's path is not a valid path-slot value; build from a directory the Path type accepts"
        );
        let (result, recorded) = invoke(
            probe(),
            vec![exe.clone(), "1".to_string()],
            &allow_any("fuzz.probe", 2),
        );
        assert_eq!(
            result.outcome,
            Outcome::Success as i32,
            "the probe refused the fuzz binary's own path: a harness fixture failure, not a finding"
        );
        assert_eq!(
            recorded.first().and_then(|argv| argv.get(4)),
            Some(&exe),
            "the fuzz binary's canonical path does not read back unchanged from its descriptor"
        );
        exe
    })
}

/// Records every request and reports success without spawning. It never calls
/// `relay_exec::executor::execute`.
#[derive(Default)]
struct Recording(Mutex<Vec<Vec<String>>>);

impl Runner for Recording {
    fn run(&self, req: ExecRequest) -> OpFuture<'static> {
        self.0.lock().unwrap().push(req.argv.clone());
        let task_id = req.task_id;
        Box::pin(async move {
            TaskResult {
                task_id,
                outcome: Outcome::Success as i32,
                ..Default::default()
            }
        })
    }
}

fn invoke(
    op: &TemplateOp,
    positional: Vec<String>,
    policy: &Policy,
) -> (TaskResult, Vec<Vec<String>>) {
    let recording = Recording::default();
    let result = runtime().block_on(ResolvedOp::invoke(
        op,
        OpCtx {
            task_id: "fuzz".to_string(),
            positional,
            timeout: Duration::from_secs(10),
            max_output_bytes: 4096,
            policy,
            cancel: None,
            runner: &recording,
        },
    ));
    let recorded = recording.0.into_inner().unwrap();
    (result, recorded)
}

/// Whether the code refuses `v` as a Path value, judged on the probe so that
/// nothing is opened: this relies on `invoke` validating every value before it
/// resolves any path, and the always-invalid second slot then stops it.
fn path_refused(v: &str) -> bool {
    let (result, recorded) = invoke(probe(), vec![v.to_string(), String::new()], deny_all());
    assert!(recorded.is_empty(), "the probe spawned for {v:?}");
    assert_eq!(result.outcome, Outcome::Failure as i32, "probe on {v:?}");
    assert!(result.stdout.is_empty(), "probe on {v:?}");
    if refusal_message_ok(&result.stderr, "p", &SlotType::Path, v.len()) {
        return true;
    }
    assert!(
        refusal_message_ok(&result.stderr, "z", &SlotType::Integer, 0),
        "unrecognised probe refusal for {v:?}: {:?}",
        String::from_utf8_lossy(&result.stderr)
    );
    false
}

fn check(def: &TemplateDef, values: &[String]) {
    // A refusal belongs to fuzz_template_compile.
    let Ok(op) = compile(def) else {
        return;
    };
    // (c) Compile is deterministic.
    let again = compile(def).expect("the same definition compiles twice");
    assert_eq!(op.script(), again.script(), "compile is not deterministic");
    assert_eq!(op.slot_specs(), again.slot_specs());

    // (b) The script is what the model says.
    let expected = expected_script(&def.body, &def.slots).unwrap_or_else(|why| {
        panic!(
            "compile accepted {:?} but the model refuses it ({why}); script {:?}",
            def.body,
            op.script()
        )
    });
    assert_eq!(expected, op.script(), "body {:?}", def.body);

    // (a) The mapping from named arguments to positional values.
    let operation = Operation {
        name: def.name.clone(),
        args: def
            .slots
            .iter()
            .zip(values)
            .map(|(s, v)| (s.name.clone(), v.clone()))
            .collect::<HashMap<_, _>>(),
    };
    let requested = ResolvedOp::positional_args(&op, &operation);
    let want: Vec<String> = (0..def.slots.len())
        .map(|i| values.get(i).cloned().unwrap_or_default())
        .collect();
    assert_eq!(requested, want, "positional_args");

    // (d) Validator conformance. A Path verdict comes from the probe.
    let ok: Vec<bool> = def
        .slots
        .iter()
        .zip(&requested)
        .map(|(s, v)| value_ok(&s.ty, v))
        .collect();
    for ((s, v), ok) in def.slots.iter().zip(&requested).zip(&ok) {
        if matches!(s.ty, SlotType::Path) {
            assert_eq!(
                path_refused(v),
                !ok,
                "Path validator and model disagree on {v:?}"
            );
        }
    }
    // The only fuzzer-chosen paths that reach `invoke` are ones just refused.
    let effective: Vec<String> = def
        .slots
        .iter()
        .zip(&requested)
        .zip(&ok)
        .map(|((s, v), ok)| match (&s.ty, ok) {
            (SlotType::Path, true) => exe().to_string(),
            _ => v.clone(),
        })
        .collect();

    let policy = allow_any(&def.name, def.slots.len());
    let head = ["/bin/sh", "-c", expected.as_str(), "relay-template"];
    let (result, recorded) = invoke(&op, effective.clone(), &policy);
    match ok.iter().position(|ok| !ok) {
        None => {
            // Valid values always render, with the values verbatim.
            assert_eq!(recorded.len(), 1, "valid values did not render once");
            assert_eq!(result.outcome, Outcome::Success as i32);
            let want: Vec<&str> = head
                .iter()
                .copied()
                .chain(effective.iter().map(String::as_str))
                .collect();
            assert_eq!(recorded[0], want);
        }
        Some(k) => {
            // A refused render never spawns and never echoes the value.
            assert!(recorded.is_empty(), "a refused value spawned");
            assert_eq!(result.outcome, Outcome::Failure as i32);
            assert!(result.stdout.is_empty());
            assert!(
                refusal_message_ok(
                    &result.stderr,
                    &def.slots[k].name,
                    &def.slots[k].ty,
                    effective[k].len()
                ),
                "unexpected refusal text {:?} for slot {:?}",
                String::from_utf8_lossy(&result.stderr),
                def.slots[k].name
            );
        }
    }

    // (b) and (c): the same head whatever the values, and a valid value in every
    // slot renders, even when the fuzzed values were refused.
    for set in canonical_values(&def.slots, exe()) {
        let (result, recorded) = invoke(&op, set.clone(), &policy);
        assert_eq!(recorded.len(), 1, "canonical values did not render once");
        assert_eq!(result.outcome, Outcome::Success as i32);
        assert_eq!(recorded[0][..4], head);
        assert_eq!(recorded[0][4..], set[..]);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Ok(rest) = std::str::from_utf8(rest) else {
        return;
    };
    let f = fields(rest);
    let values = &f[1..];
    if sel & 0x80 != 0 {
        let Ok(file) = toml::from_str::<TemplateFileMirror>(&f[0]) else {
            return;
        };
        if file.template.len() > MAX_DEFS {
            return;
        }
        for def in &file.template {
            check(def, values);
        }
    } else {
        check(&render_def(sel, &f[0]), values);
    }
});
