//! Code-position classifier for Template bodies (ADR-0021 amendments of
//! 2026-10-14 decision 2 and 2026-10-15 decision 3).
//!
//! A slot value is never shell text, but the command the author wrote can still
//! turn its argument back into code. This module reads the body lexer's
//! top-level word stream (it never re-lexes) and reports where a placeholder
//! stands:
//!
//! - **Errors** ([`CodePosition`]): positions decidable from the body alone and
//!   guaranteed to execute their value. The body does not compile, so the
//!   Node's template set is `unloadable`.
//! - **Warnings** ([`BodyWarning`]): positions that cannot be decided reliably,
//!   and bodies whose own text routes slot values into code. They load, and
//!   `policy check` reports them (`--strict` fails).
//!
//! Only a body that holds a placeholder is classified. The command tables below
//! are the whole vocabulary: a command not named in them is an ordinary command,
//! and a placeholder among its arguments is data.

use std::fmt;

/// One word of the body's top-level command list.
#[derive(Debug, Clone)]
pub(super) struct Word {
    pub at: usize,
    /// The literal text with quotes and backslashes removed; text from an
    /// expansion is not included.
    pub lit: String,
    /// The word holds an expansion, so `lit` is only part of it.
    pub dynamic: bool,
    /// Any part of the word was quoted or escaped.
    pub quoted: bool,
    /// The word is a `{{slot}}` placeholder.
    pub slot: bool,
}

impl Word {
    pub(super) fn slot(at: usize) -> Word {
        Word {
            at,
            lit: String::new(),
            dynamic: false,
            quoted: false,
            slot: true,
        }
    }

    fn is(&self, text: &str) -> bool {
        !self.slot && !self.dynamic && self.lit == text
    }

    fn is_any(&self, texts: &[&str]) -> bool {
        texts.iter().any(|t| self.is(t))
    }

    fn is_option(&self) -> bool {
        !self.slot && !self.dynamic && self.lit.len() > 1 && self.lit.starts_with('-')
    }
}

/// A token of the top-level command list.
#[derive(Debug, Clone)]
pub(super) enum Tok {
    Word(Word),
    /// A command boundary: newline, `;`, `&`, `|`, `&&`, `||`.
    Sep,
    /// A redirection operator; the word after it is a file or descriptor.
    Redir,
    /// A `(` at the top level and the matching `)`.
    Open,
    Close,
}

/// A placeholder position whose value is executed, decidable from the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodePosition {
    CommandName,
    CommandOperand,
    EvalOperand,
    SourceOperand,
    LetOperand,
    ShellProgram,
    InterpreterProgram,
}

impl CodePosition {
    pub fn why(self) -> &'static str {
        match self {
            CodePosition::CommandName => {
                "the command-name position of a simple command, where its value would be run as a command"
            }
            CodePosition::CommandOperand => {
                "the operand of exec, command or builtin, where its value would be run as a command"
            }
            CodePosition::EvalOperand => "an operand of eval, which runs its operands as shell code",
            CodePosition::SourceOperand => {
                "the file operand of . or source, which runs the file its value names"
            }
            CodePosition::LetOperand => {
                "an operand of let, an arithmetic context some shells re-evaluate"
            }
            CodePosition::ShellProgram => {
                "the program argument of a shell's -c, which runs its value as shell code"
            }
            CodePosition::InterpreterProgram => {
                "the program argument of an interpreter's -c/-e/-r flag, which runs its value as code"
            }
        }
    }
}

impl fmt::Display for CodePosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.why())
    }
}

/// Why a body draws a `policy check` warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningKind {
    UndecidableProgram,
    FindExec,
    Xargs,
    Wrapper,
    OptionCommand,
    RemoteCommand,
    InterpreterScript,
    ComputedCommand,
    OwnPositional,
    FunctionBody,
    Alias,
    Trap,
    SourcedFile,
    WordList,
}

impl WarningKind {
    pub fn why(self) -> &'static str {
        match self {
            WarningKind::UndecidableProgram => {
                "a placeholder is the program text of awk or sed, which may run commands"
            }
            WarningKind::FindExec => {
                "a placeholder follows find -exec/-execdir/-ok/-okdir, where it may be the command run"
            }
            WarningKind::Xargs => "a placeholder follows xargs, which runs its operands as a command",
            WarningKind::Wrapper => {
                "a placeholder is an argument of a wrapper that runs a command (env, sudo, timeout, ...)"
            }
            WarningKind::OptionCommand => {
                "a placeholder is the value of an option that takes a command to run"
            }
            WarningKind::RemoteCommand => "a placeholder is part of the command ssh runs remotely",
            WarningKind::InterpreterScript => {
                "a placeholder is the script operand of a shell or interpreter, which runs the file its value names"
            }
            WarningKind::ComputedCommand => {
                "a placeholder is an argument of a command whose name is computed at run time"
            }
            WarningKind::OwnPositional => {
                "the body reads or changes the positional parameters ($1.. $@ $* shift set -- getopts), which carry the slot values"
            }
            WarningKind::FunctionBody => {
                "a placeholder is inside a function body, where its argument is re-expanded on each call"
            }
            WarningKind::Alias => "the body defines an alias, which can turn a later word into code",
            WarningKind::Trap => "a placeholder is an operand of trap, whose action is run as shell code",
            WarningKind::SourcedFile => {
                "the body sources a file, which receives the slot values as its positional parameters"
            }
            WarningKind::WordList => {
                "a placeholder is in a compgen/complete -W word list, which the shell expands again"
            }
        }
    }
}

/// A `policy check` warning about a body: it loads, and `--strict` fails it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyWarning {
    pub at: usize,
    pub kind: WarningKind,
}

impl fmt::Display for BodyWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "near byte {} of the body: {} ({:?})",
            self.at,
            self.kind.why(),
            self.kind
        )
    }
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Reserved words after which a command name follows.
const COMMAND_STARTERS: &[&str] = &[
    "!", "if", "then", "else", "elif", "while", "until", "do", "time", "{",
];

/// Commands that run another command, whose options are not modelled: a
/// placeholder among their arguments may be the command.
const WRAPPERS: &[&str] = &[
    "env",
    "sudo",
    "doas",
    "nice",
    "ionice",
    "timeout",
    "nohup",
    "setsid",
    "stdbuf",
    "chroot",
    "unshare",
    "nsenter",
    "flock",
    "watch",
    "strace",
    "ltrace",
    "taskset",
    "chrt",
    "runuser",
    "systemd-run",
];

/// Commands with an option whose value is a command to run.
const OPTION_COMMANDS: &[(&str, &[&str])] = &[
    (
        "tar",
        &[
            "-I",
            "--use-compress-program",
            "--to-command",
            "--rsh-command",
        ],
    ),
    ("rsync", &["-e", "--rsh"]),
    ("git", &["-c"]),
    ("su", &["-c", "--command"]),
    ("script", &["-c", "--command"]),
];

/// ssh options that take a value, so the value is not mistaken for the host.
const SSH_VALUE_OPTIONS: &[&str] = &[
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q",
    "-R", "-S", "-W", "-w",
];

struct Interpreter {
    names: &'static [&'static str],
    shell: bool,
    /// Single-letter flags whose next argument is the program.
    program: &'static str,
    /// Letters that may share a cluster with the program flag (`-ec`).
    bundle: &'static str,
    /// Long flags whose next argument is the program.
    long: &'static [&'static str],
}

const SHELL_BUNDLE: &str = "abefhilmnuvxCHP";

const INTERPRETERS: &[Interpreter] = &[
    Interpreter {
        names: &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "rbash"],
        shell: true,
        program: "c",
        bundle: SHELL_BUNDLE,
        long: &[],
    },
    Interpreter {
        names: &["python", "python2", "python3"],
        shell: false,
        program: "c",
        bundle: "bBdEiIOqsSuvx",
        long: &[],
    },
    Interpreter {
        names: &["perl"],
        shell: false,
        program: "eE",
        bundle: "lnpawsSTtuUWxc",
        long: &[],
    },
    Interpreter {
        names: &["ruby"],
        shell: false,
        program: "e",
        bundle: "lnpasdvwxc",
        long: &[],
    },
    Interpreter {
        names: &["node", "nodejs"],
        shell: false,
        program: "ep",
        bundle: "",
        long: &["--eval", "--print"],
    },
    Interpreter {
        names: &["php"],
        shell: false,
        program: "r",
        bundle: "",
        long: &[],
    },
    Interpreter {
        names: &["lua", "luajit"],
        shell: false,
        program: "e",
        bundle: "",
        long: &[],
    },
];

struct ProgramTool {
    names: &'static [&'static str],
    /// Flags whose next argument is program text or a program file.
    flags: &'static [&'static str],
    /// Other options that take a value.
    value_options: &'static [&'static str],
}

const PROGRAM_TOOLS: &[ProgramTool] = &[
    ProgramTool {
        names: &["awk", "gawk", "mawk", "nawk"],
        flags: &["-f", "--file", "-e", "--source"],
        value_options: &["-F", "-v", "-W"],
    },
    ProgramTool {
        names: &["sed", "gsed"],
        flags: &["-e", "--expression", "-f", "--file"],
        value_options: &[],
    },
];

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

pub(super) struct Findings {
    /// The first (lowest-offset) error, if any.
    pub error: Option<(usize, CodePosition)>,
    pub warnings: Vec<BodyWarning>,
}

pub(super) fn classify(toks: &[Tok]) -> Findings {
    let mut c = Classifier {
        errors: Vec::new(),
        warnings: Vec::new(),
        groups: Vec::new(),
        pending_function: false,
    };
    c.run(toks);
    c.errors.sort_by_key(|(at, _)| *at);
    c.warnings.sort_by_key(|w| w.at);
    c.warnings.dedup();
    Findings {
        error: c.errors.first().copied(),
        warnings: c.warnings,
    }
}

struct Classifier {
    errors: Vec<(usize, CodePosition)>,
    warnings: Vec<BodyWarning>,
    /// Open `{ }` groups; `true` for a function body.
    groups: Vec<bool>,
    /// A function header was read; the next `{` opens its body.
    pending_function: bool,
}

impl Classifier {
    fn run(&mut self, toks: &[Tok]) {
        let mut words: Vec<&Word> = Vec::new();
        let mut redirect_target = false;
        for (k, tok) in toks.iter().enumerate() {
            match tok {
                Tok::Word(w) if redirect_target => {
                    let _ = w;
                    redirect_target = false;
                }
                Tok::Word(w) => words.push(w),
                Tok::Redir => redirect_target = true,
                Tok::Open if words.len() == 1 && matches!(toks.get(k + 1), Some(Tok::Close)) => {
                    // `name ( )` defines a function.
                    words.clear();
                    self.pending_function = true;
                }
                Tok::Sep | Tok::Open | Tok::Close => {
                    redirect_target = false;
                    self.command(&std::mem::take(&mut words));
                }
            }
        }
        self.command(&words);
    }

    fn command(&mut self, words: &[&Word]) {
        let mut words = words;
        if words.first().is_some_and(|w| w.is("function")) && !words[0].quoted {
            // `function name { … }`: the header is two words.
            self.pending_function = true;
            words = &words[words.len().min(2)..];
        }
        let mut k = 0;
        while let Some(w) = words.get(k) {
            if w.is("}") && k == 0 {
                self.groups.pop();
                return;
            }
            if w.is_any(COMMAND_STARTERS) && !w.quoted {
                if w.is("{") {
                    let function = std::mem::take(&mut self.pending_function);
                    self.groups.push(function);
                }
                k += 1;
            } else if is_assignment(&w.lit) && !w.slot {
                if w.lit.starts_with("BASH_ALIASES") {
                    self.warn(w.at, WarningKind::Alias);
                }
                k += 1;
            } else {
                break;
            }
        }
        let words = &words[k..];
        if words.is_empty() {
            return;
        }
        self.pending_function = false;
        if self.groups.contains(&true) {
            for w in words.iter().filter(|w| w.slot) {
                self.warn(w.at, WarningKind::FunctionBody);
            }
        }
        self.command_word(words[0], &words[1..]);
    }

    fn warn(&mut self, at: usize, kind: WarningKind) {
        self.warnings.push(BodyWarning { at, kind });
    }

    fn error(&mut self, at: usize, kind: CodePosition) {
        self.errors.push((at, kind));
    }

    fn first_slot<'w>(args: &[&'w Word]) -> Option<&'w Word> {
        args.iter().copied().find(|w| w.slot)
    }

    /// `name` is in command-name position and `args` follow it.
    fn command_word(&mut self, name: &Word, args: &[&Word]) {
        if name.slot {
            self.error(name.at, CodePosition::CommandName);
            return;
        }
        if name.dynamic {
            if Self::first_slot(args).is_some() {
                self.warn(name.at, WarningKind::ComputedCommand);
            }
            return;
        }
        let base = name.lit.rsplit('/').next().unwrap_or("");
        self.known_command(name, base, args);
    }

    fn known_command(&mut self, name: &Word, base: &str, args: &[&Word]) {
        let first_slot = Self::first_slot(args);
        match base {
            "exec" | "command" | "builtin" => self.exec_like(base, args),
            "eval" => {
                if let Some(s) = first_slot {
                    self.error(s.at, CodePosition::EvalOperand);
                }
            }
            "." | "source" => {
                self.warn(name.at, WarningKind::SourcedFile);
                let operand = args.iter().find(|w| !w.is("--"));
                if let Some(w) = operand.filter(|w| w.slot) {
                    self.error(w.at, CodePosition::SourceOperand);
                }
            }
            "let" => {
                if let Some(s) = first_slot {
                    self.error(s.at, CodePosition::LetOperand);
                }
            }
            "shift" | "getopts" => self.warn(name.at, WarningKind::OwnPositional),
            "set" => {
                if args.iter().any(|w| w.is("--")) {
                    self.warn(name.at, WarningKind::OwnPositional);
                }
            }
            "alias" => self.warn(name.at, WarningKind::Alias),
            "trap" => {
                if let Some(s) = first_slot {
                    self.warn(s.at, WarningKind::Trap);
                }
            }
            "compgen" | "complete" => {
                let word_list = args
                    .iter()
                    .any(|w| w.is_option() && w.lit.starts_with("-W"));
                if let (true, Some(s)) = (word_list, first_slot) {
                    self.warn(s.at, WarningKind::WordList);
                }
            }
            "xargs" => {
                if let Some(s) = first_slot {
                    self.warn(s.at, WarningKind::Xargs);
                }
            }
            "find" => self.find(args),
            "ssh" => self.ssh(args),
            "busybox" => {
                if let Some((applet, rest)) = args.split_first() {
                    if applet.slot {
                        self.warn(applet.at, WarningKind::Wrapper);
                    } else {
                        self.command_word_unchecked(applet, rest);
                    }
                }
            }
            _ => self.table_command(base, args),
        }
    }

    /// A word that follows a command-name-like word but is itself only
    /// dispatched by name (a `busybox` applet): a dynamic word is not run.
    fn command_word_unchecked(&mut self, word: &Word, rest: &[&Word]) {
        if !word.dynamic {
            let base = word.lit.rsplit('/').next().unwrap_or("");
            self.known_command(word, base, rest);
        }
    }

    fn table_command(&mut self, base: &str, args: &[&Word]) {
        let stem = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
        if let Some(i) = INTERPRETERS
            .iter()
            .find(|i| i.names.contains(&base) || i.names.contains(&stem))
        {
            return self.interpreter(i, args);
        }
        if let Some(t) = PROGRAM_TOOLS.iter().find(|t| t.names.contains(&base)) {
            return self.program_tool(t, args);
        }
        if let Some((_, flags)) = OPTION_COMMANDS.iter().find(|(n, _)| *n == base) {
            for pair in args.windows(2) {
                if pair[0].is_any(flags) && pair[1].slot {
                    self.warn(pair[1].at, WarningKind::OptionCommand);
                }
            }
            return;
        }
        if WRAPPERS.contains(&base) {
            if let Some(s) = Self::first_slot(args) {
                self.warn(s.at, WarningKind::Wrapper);
            }
        }
    }

    /// `exec`, `command` and `builtin` run their operand as a command, so the
    /// operand is a command-name position. `command -v` and `-V` only look a
    /// name up and run nothing.
    fn exec_like(&mut self, base: &str, args: &[&Word]) {
        let mut rest = args;
        while let Some(w) = rest.first() {
            if w.is("--") {
                rest = &rest[1..];
                break;
            }
            if !w.is_option() {
                break;
            }
            if base == "command" && w.lit[1..].chars().any(|c| c == 'v' || c == 'V') {
                return;
            }
            // `exec -a NAME` takes a value.
            let skip = if base == "exec" && w.is("-a") { 2 } else { 1 };
            rest = &rest[skip.min(rest.len())..];
        }
        let Some((operand, tail)) = rest.split_first() else {
            return;
        };
        if operand.slot {
            self.error(operand.at, CodePosition::CommandOperand);
            return;
        }
        self.command_word(operand, tail);
    }

    fn interpreter(&mut self, i: &Interpreter, args: &[&Word]) {
        let kind = if i.shell {
            CodePosition::ShellProgram
        } else {
            CodePosition::InterpreterProgram
        };
        let mut has_program = false;
        for (k, w) in args.iter().enumerate() {
            if !is_program_flag(w, i) {
                continue;
            }
            has_program = true;
            if let Some(next) = args.get(k + 1).filter(|n| n.slot) {
                self.error(next.at, kind);
            }
        }
        if has_program {
            return;
        }
        // No program flag: the first operand is the script file it runs.
        if let Some(script) = args.iter().find(|w| !w.is_option()).filter(|w| w.slot) {
            self.warn(script.at, WarningKind::InterpreterScript);
        }
    }

    fn program_tool(&mut self, t: &ProgramTool, args: &[&Word]) {
        let mut has_flag = false;
        for pair in args.windows(2) {
            if pair[0].is_any(t.flags) {
                has_flag = true;
                if pair[1].slot {
                    self.warn(pair[1].at, WarningKind::UndecidableProgram);
                }
            }
        }
        if has_flag || args.iter().any(|w| w.is_any(t.flags)) {
            return;
        }
        let mut skip = false;
        for w in args {
            if std::mem::take(&mut skip) {
                continue;
            }
            if w.is_any(t.value_options) {
                skip = true;
            } else if !w.is_option() {
                if w.slot {
                    self.warn(w.at, WarningKind::UndecidableProgram);
                }
                return;
            }
        }
    }

    fn find(&mut self, args: &[&Word]) {
        let mut in_exec = false;
        for w in args {
            if w.is_any(&["-exec", "-execdir", "-ok", "-okdir"]) {
                in_exec = true;
            } else if in_exec && w.is_any(&[";", "+"]) {
                in_exec = false;
            } else if in_exec && w.slot {
                self.warn(w.at, WarningKind::FindExec);
            }
        }
    }

    /// The first operand is the host; a placeholder after it is part of the
    /// command ssh runs remotely.
    fn ssh(&mut self, args: &[&Word]) {
        let mut skip = false;
        let mut seen_host = false;
        for w in args {
            if std::mem::take(&mut skip) {
                continue;
            }
            if w.is_any(SSH_VALUE_OPTIONS) {
                skip = true;
            } else if w.is_option() {
                continue;
            } else if !seen_host {
                seen_host = true;
            } else if w.slot {
                self.warn(w.at, WarningKind::RemoteCommand);
            }
        }
    }
}

fn is_program_flag(w: &Word, i: &Interpreter) -> bool {
    if w.slot || w.dynamic {
        return false;
    }
    if i.long.contains(&w.lit.as_str()) {
        return true;
    }
    let Some(cluster) = w.lit.strip_prefix('-').filter(|c| !c.starts_with('-')) else {
        return false;
    };
    !cluster.is_empty()
        && cluster
            .chars()
            .all(|c| i.program.contains(c) || i.bundle.contains(c))
        && cluster.chars().any(|c| i.program.contains(c))
}

/// `NAME=`, `NAME+=` or `NAME[…]=`: a prefix assignment, not a command name.
fn is_assignment(lit: &str) -> bool {
    let Some((lhs, _)) = lit.split_once('=') else {
        return false;
    };
    let lhs = lhs.strip_suffix('+').unwrap_or(lhs);
    let name = match lhs.find('[') {
        Some(open) if lhs.ends_with(']') => &lhs[..open],
        Some(_) => return false,
        None => lhs,
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::template::{Slot, SlotType, TemplateError};
    use crate::operations::template_body::analyse;

    fn slots() -> Vec<Slot> {
        vec![Slot {
            name: "p".into(),
            ty: SlotType::Path,
        }]
    }

    /// The error kind, or the warning kinds, of a body that holds `{{p}}`.
    fn outcome(body: &str) -> Result<Vec<WarningKind>, CodePosition> {
        match analyse(body, &slots()) {
            Ok(a) => Ok(a.warnings.iter().map(|w| w.kind).collect()),
            Err(TemplateError::PlaceholderInCodePosition { kind, .. }) => Err(kind),
            Err(e) => panic!("{body:?} should reach the classifier: {e}"),
        }
    }

    fn assert_error(kind: CodePosition, bodies: &[&str]) {
        for body in bodies {
            assert_eq!(outcome(body), Err(kind), "{body:?}");
        }
    }

    fn assert_warning(kind: WarningKind, bodies: &[&str]) {
        for body in bodies {
            let warnings = outcome(body).unwrap_or_else(|e| panic!("{body:?} is an error: {e}"));
            assert!(warnings.contains(&kind), "{body:?}: {warnings:?}");
        }
    }

    fn assert_clean(bodies: &[&str]) {
        for body in bodies {
            assert_eq!(outcome(body), Ok(vec![]), "{body:?}");
        }
    }

    #[test]
    fn a_placeholder_in_command_name_position_is_an_error() {
        assert_error(
            CodePosition::CommandName,
            &[
                "{{p}}",
                "{{p}} x",
                "echo a ; {{p}}",
                "echo a\n{{p}}",
                "true && {{p}}",
                "false || {{p}}",
                "echo a | {{p}}",
                "echo a & {{p}}",
                "{ {{p}} ; }",
                "! {{p}}",
                "if {{p}} ; then :; fi",
                "if true; then {{p}} ; fi",
                "if false; then :; elif {{p}} ; then :; fi",
                "if false; then :; else {{p}} ; fi",
                "while {{p}} ; do :; done",
                "until {{p}} ; do :; done",
                "while true; do {{p}} ; done",
                "time {{p}}",
                "A=1 {{p}}",
                "A=1 B+=2 C[1]=3 {{p}}",
                "> /dev/null {{p}}",
                "2>&1 {{p}}",
            ],
        );
    }

    #[test]
    fn the_operand_of_exec_command_and_builtin_is_an_error() {
        assert_error(
            CodePosition::CommandOperand,
            &[
                "exec {{p}}",
                "exec -c {{p}}",
                "exec -a name {{p}}",
                "exec -- {{p}}",
                "command {{p}}",
                "command -p {{p}}",
                "command -- {{p}}",
                "builtin {{p}}",
                "exec > /dev/null {{p}}",
            ],
        );
    }

    #[test]
    fn exec_with_only_redirections_and_lookups_are_not_command_positions() {
        assert_clean(&[
            "exec > {{p}}",
            "exec 3< {{p}}",
            "exec 2>> {{p}}",
            "exec -a {{p}} true",
            "command -v {{p}}",
            "command -V {{p}}",
            "command -pv {{p}}",
            "command -v true > {{p}}",
        ]);
    }

    #[test]
    fn eval_operands_are_an_error() {
        assert_error(
            CodePosition::EvalOperand,
            &["eval {{p}}", "eval echo {{p}}", "eval x y {{p}}"],
        );
    }

    #[test]
    fn the_file_operand_of_dot_and_source_is_an_error() {
        assert_error(
            CodePosition::SourceOperand,
            &[". {{p}}", "source {{p}}", ". -- {{p}}"],
        );
    }

    #[test]
    fn let_operands_are_an_error() {
        assert_error(CodePosition::LetOperand, &["let {{p}}", "let x=1 {{p}}"]);
    }

    #[test]
    fn the_program_after_a_shells_dash_c_is_an_error() {
        assert_error(
            CodePosition::ShellProgram,
            &[
                "sh -c {{p}}",
                "bash -c {{p}}",
                "dash -c {{p}}",
                "zsh -c {{p}}",
                "ksh -c {{p}}",
                "mksh -c {{p}}",
                "ash -c {{p}}",
                "/bin/sh -c {{p}}",
                "bash -ec {{p}}",
                "bash -lc {{p}}",
                "sh -x -c {{p}}",
                "exec sh -c {{p}}",
                "command bash -c {{p}}",
                "busybox sh -c {{p}}",
                "echo a | sh -c {{p}}",
            ],
        );
    }

    #[test]
    fn the_program_after_an_interpreters_program_flag_is_an_error() {
        assert_error(
            CodePosition::InterpreterProgram,
            &[
                "python -c {{p}}",
                "python3 -c {{p}}",
                "python3.11 -c {{p}}",
                "python3 -Bc {{p}}",
                "perl -e {{p}}",
                "perl -E {{p}}",
                "perl -ne {{p}}",
                "ruby -e {{p}}",
                "node -e {{p}}",
                "node -p {{p}}",
                "node --eval {{p}}",
                "nodejs --print {{p}}",
                "php -r {{p}}",
                "lua -e {{p}}",
            ],
        );
    }

    #[test]
    fn a_value_beside_a_program_the_author_wrote_is_data() {
        assert_clean(&[
            "sh -c 'echo \"$1\"' x {{p}}",
            "bash -c 'cat' x {{p}}",
            "python3 -c 'import sys' {{p}}",
            "perl -Mstrict -e 1 {{p}}",
            "sh -c true > {{p}}",
        ]);
    }

    #[test]
    fn undecidable_programs_warn() {
        assert_warning(
            WarningKind::UndecidableProgram,
            &[
                "awk {{p}}",
                "awk -f {{p}}",
                "gawk -e {{p}}",
                "awk -v x=1 {{p}}",
                "sed {{p}}",
                "sed -e {{p}}",
                "sed -n -f {{p}}",
            ],
        );
        assert_clean(&[
            "awk '{print}' {{p}}",
            "awk -F : '{print}' {{p}}",
            "sed -n p {{p}}",
            "sed -i s/a/b/ {{p}}",
        ]);
    }

    #[test]
    fn find_exec_and_xargs_warn() {
        assert_warning(
            WarningKind::FindExec,
            &[
                "find . -exec {{p}} \\;",
                "find . -execdir echo {{p}} {} +",
                "find . -ok {{p}} \\;",
            ],
        );
        assert_warning(
            WarningKind::Xargs,
            &[
                "xargs {{p}}",
                "xargs -n1 {{p}}",
                "echo x | xargs sh -c {{p}}",
            ],
        );
        assert_clean(&[
            "find {{p}} -name x",
            "find . -exec ls {} \\; -name {{p}}",
            "find . -type f -newer {{p}}",
        ]);
    }

    #[test]
    fn wrappers_warn() {
        for wrapper in WRAPPERS {
            assert_warning(WarningKind::Wrapper, &[&format!("{wrapper} {{{{p}}}}")]);
        }
        assert_warning(WarningKind::Wrapper, &["busybox {{p}}"]);
        assert_clean(&["nice -n 5 ls", "timeout 5 true > {{p}}"]);
    }

    #[test]
    fn options_that_take_a_command_warn() {
        assert_warning(
            WarningKind::OptionCommand,
            &[
                "tar -I {{p}} -cf x",
                "tar --use-compress-program {{p}} -cf x",
                "rsync -e {{p}} a b",
                "git -c {{p}} status",
                "su -c {{p}}",
                "script -c {{p}}",
            ],
        );
        assert_clean(&["tar -tf {{p}}", "git -C {{p}} status", "rsync -a {{p}} dst"]);
    }

    #[test]
    fn ssh_warns_only_after_the_host() {
        assert_warning(
            WarningKind::RemoteCommand,
            &["ssh host {{p}}", "ssh -p 22 host {{p}}"],
        );
        assert_clean(&[
            "ssh {{p}} uptime",
            "ssh -p {{p}} host uptime",
            "ssh -i {{p}} host uptime",
        ]);
    }

    #[test]
    fn a_script_operand_of_a_shell_or_interpreter_warns() {
        assert_warning(
            WarningKind::InterpreterScript,
            &[
                "sh {{p}}",
                "python3 {{p}}",
                "bash -x {{p}}",
                "python3 -m {{p}}",
            ],
        );
        assert_clean(&["python3 script.py {{p}}", "sh script.sh {{p}}"]);
    }

    #[test]
    fn a_computed_command_name_warns_only_beside_a_placeholder() {
        assert_warning(
            WarningKind::ComputedCommand,
            &["$cmd {{p}}", "\"$cmd\" {{p}}", "$(echo x) {{p}}"],
        );
        assert_clean(&["$cmd x ; echo {{p}}"]);
    }

    #[test]
    fn the_bodys_own_positional_parameters_warn() {
        assert_warning(
            WarningKind::OwnPositional,
            &[
                "echo \"$1\" {{p}}",
                "echo $@ {{p}}",
                "echo ${1} {{p}}",
                "echo \"$*\" {{p}}",
                "echo ${@:2} {{p}}",
                "shift ; echo {{p}}",
                "set -- x ; echo {{p}}",
                "getopts a o ; echo {{p}}",
            ],
        );
        assert_clean(&[
            "set -e ; echo {{p}}",
            "echo '$1' {{p}}",
            "echo $HOME $0 $# {{p}}",
            "cat <<'EOF' > /dev/null\n$1\nEOF\necho {{p}}",
        ]);
    }

    #[test]
    fn a_body_without_a_placeholder_is_not_classified() {
        let a = analyse("shift ; echo \"$1\" ; alias x=y ; eval $z", &[]).expect("loads");
        assert!(a.warnings.is_empty());
    }

    #[test]
    fn a_placeholder_inside_a_function_body_warns() {
        assert_warning(
            WarningKind::FunctionBody,
            &[
                "f() { echo {{p}} ; }",
                "function f { echo {{p}} ; }",
                "f()\n{\n echo {{p}}\n}",
            ],
        );
        assert_clean(&["f() { echo hi ; }\necho {{p}}", "{ echo {{p}} ; }"]);
    }

    #[test]
    fn alias_trap_source_and_word_lists_warn() {
        assert_warning(
            WarningKind::Alias,
            &["alias x=y ; echo {{p}}", "BASH_ALIASES[x]=y ; echo {{p}}"],
        );
        assert_warning(
            WarningKind::Trap,
            &["trap {{p}} EXIT", "trap -- {{p}} EXIT"],
        );
        assert_clean(&["trap 'echo x' EXIT ; echo {{p}}"]);
        assert_warning(
            WarningKind::SourcedFile,
            &[". /etc/profile ; echo {{p}}", "source ./x ; echo {{p}}"],
        );
        assert_warning(
            WarningKind::WordList,
            &["compgen -W {{p}} x", "complete -W {{p}} x"],
        );
        assert_clean(&["compgen -W 'a b' ; echo {{p}}"]);
    }

    #[test]
    fn a_placeholder_as_an_ordinary_argument_is_never_flagged() {
        assert_clean(&[
            "echo {{p}}",
            "echo {{p}} | cat -n {{p}}",
            "ls -l {{p}}",
            "grep -r x {{p}}",
            "cat < {{p}}",
            "echo hi > {{p}}",
            "echo hi 2> {{p}}",
            "echo hi >> {{p}}",
            "cmd > {{p}} 2>&1",
            "echo hi >&2 ; echo {{p}}",
            "true && echo {{p}} || echo {{p}} ; echo",
            "{ echo {{p}} ; }",
            "if test -f {{p}} ; then echo ok ; fi",
            "for f in {{p}} ; do echo $f ; done",
            "while read x ; do echo {{p}} ; done < /dev/null",
            "A=1 echo {{p}}",
            "cat <<EOF > /dev/null\nx\nEOF\necho {{p}}",
            "echo \"a b\" 'c' {{p}}",
            "echo $(date) {{p}}",
            "systemctl show --no-pager -- {{p}}",
            "if command -v dpkg-query > /dev/null 2>&1; then echo {{p}} ; fi",
        ]);
    }

    #[test]
    fn the_first_error_by_offset_is_reported() {
        let Err(TemplateError::PlaceholderInCodePosition { at, kind }) =
            analyse("eval {{p}} ; {{p}}", &slots()).map(|_| ())
        else {
            panic!("expected an error");
        };
        assert_eq!((at, kind), (5, CodePosition::EvalOperand));
    }

    #[test]
    fn findings_name_the_offset_and_the_reason() {
        let e = analyse("echo hi\n{{p}}", &slots()).map(|_| ()).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("byte 8") && msg.contains("command-name"),
            "{msg}"
        );
        let a = analyse("alias x=y ; echo {{p}}", &slots()).expect("loads");
        let msg = a.warnings[0].to_string();
        assert!(msg.contains("byte 0") && msg.contains("alias"), "{msg}");
    }
}
