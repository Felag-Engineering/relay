//! The one lexer for Template bodies (ADR-0021, invariant 1).
//!
//! It finds every `{{slot}}` placeholder, decides whether it is a **standalone
//! word outside any quotes**, and emits the script with each placeholder replaced
//! by the slot's quoted positional parameter (`"$1"`, `"$2"`, …). The values
//! themselves never enter the script: they travel as `argv[4..]` of the
//! `/bin/sh -c` invocation, so a lexer miss can never make a value part of the
//! text the shell parses. What a miss can do is leave a parameter in a context
//! where it is split or globbed, so the lexer still has to read quoting,
//! comments, here-documents and nested substitutions the way a shell does.
//!
//! Word boundaries are exactly space, tab and newline, plus the operator
//! characters `; & | < > ( )`. Form feed, carriage return and an escaped space
//! are word characters, as they are to dash and bash, so they never count as a
//! blank before or after a placeholder.
//!
//! Known limits: the lexer models POSIX `sh` plus the bash forms that change
//! where quotes end (`$'…'`, `$(( ))`, `$[ ]`, `${ }`). It does not model `case`
//! patterns, `[[ ]]`, `&>`, aliases or functions. Where it cannot tell how a
//! shell would read a body that holds a placeholder, it refuses the body rather
//! than guess: an unterminated construct, a backquote substitution (its own
//! backslash removal is not modelled; use `$( )`), a `case` inside a `$( )` or
//! `( )` (its pattern `)` would end the frame early), a `$((` that is not
//! arithmetic, and a backslash-newline inside a nested construct or a word
//! (the shell joins it before reading keywords and operators). A placeholder
//! inside arithmetic is refused outright.
//!
//! A slot is accepted only as a plain word of the top-level command list (a
//! simple command, pipeline or `;`/`&&`/`||`/newline list, including a `{ …; }`
//! group or a function body). Every other place a shell reads text is refused:
//! `$( )`, `( )`, quotes, `${ }`, arithmetic, here-documents, here-strings,
//! `[[ ]]` and `case`.

use std::collections::HashSet;

use super::template::{is_valid_slot_name, positional_ref, Slot, TemplateError};
use super::template_code::{classify, BodyWarning, Tok, WarningKind, Word};

/// The result of lexing a body: the script to hand to `/bin/sh -c`, the slots
/// it references and the `policy check` warnings.
pub(super) struct BodyAnalysis {
    pub script: String,
    pub referenced: HashSet<usize>,
    pub warnings: Vec<BodyWarning>,
}

pub(super) fn analyse(body: &str, slots: &[Slot]) -> Result<BodyAnalysis, TemplateError> {
    let mut lx = Lexer::new(body, slots);
    while lx.i < lx.chars.len() {
        lx.step()?;
    }
    lx.finish()
}

/// What the previous token was, which decides both "is this a word start" and
/// "may a placeholder stand here".
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prev {
    /// Start of body, space, tab or newline.
    Blank,
    /// Immediately inside the opening of `$(`, a backquote or `(`.
    Open,
    /// An operator character (or an arithmetic opener): a new word starts, but a
    /// placeholder glued to it is not standalone.
    Operator,
    /// Part of a word.
    Other,
}

#[derive(Clone)]
struct Heredoc {
    delim: Vec<char>,
    strip_tabs: bool,
    quoted: bool,
    /// The next char starts a body line, where the delimiter may appear.
    bol: bool,
}

enum Frame {
    Top,
    CmdSubst,
    Subshell,
    Backquote,
    DoubleQuote,
    SingleQuote,
    AnsiC,
    ParamExp {
        in_double: bool,
    },
    /// `$((`, `((` (closed by `))`) or the legacy `$[` (closed by `]`).
    Arith {
        depth: u32,
        bracket: bool,
    },
    Heredoc(Heredoc),
}

struct Lexer<'a> {
    chars: Vec<char>,
    /// Byte offset of each char index, plus the total length, for error positions.
    off: Vec<usize>,
    slots: &'a [Slot],
    i: usize,
    out: String,
    referenced: HashSet<usize>,
    stack: Vec<Frame>,
    prev: Prev,
    /// The body holds at least one `{{`: constructs the lexer cannot read are
    /// refused only then, so slot-free bodies keep loading.
    has_placeholder: bool,
    /// Here-documents whose operator was read; their bodies start after the
    /// next newline.
    pending: Vec<Heredoc>,
    /// The top-level word stream, kept only for a body with a placeholder; the
    /// code-position classifier reads it.
    toks: Vec<Tok>,
    /// The top-level word being read.
    word: Option<Word>,
    warnings: Vec<BodyWarning>,
}

impl<'a> Lexer<'a> {
    fn new(body: &str, slots: &'a [Slot]) -> Self {
        let chars: Vec<char> = body.chars().collect();
        let mut off = Vec::with_capacity(chars.len() + 1);
        let mut at = 0;
        for c in &chars {
            off.push(at);
            at += c.len_utf8();
        }
        off.push(at);
        Lexer {
            chars,
            off,
            slots,
            i: 0,
            out: String::with_capacity(body.len()),
            referenced: HashSet::new(),
            stack: vec![Frame::Top],
            prev: Prev::Blank,
            has_placeholder: body.contains("{{"),
            pending: Vec::new(),
            toks: Vec::new(),
            word: None,
            warnings: Vec::new(),
        }
    }

    fn finish(mut self) -> Result<BodyAnalysis, TemplateError> {
        let open_quote = self
            .stack
            .iter()
            .any(|f| matches!(f, Frame::SingleQuote | Frame::DoubleQuote | Frame::AnsiC));
        if open_quote {
            return Err(TemplateError::UnbalancedQuotes);
        }
        if self.has_placeholder && (self.stack.len() > 1 || !self.pending.is_empty()) {
            return Err(TemplateError::BodyNotAnalysable {
                at: self.off[self.chars.len()],
                reason: "an unterminated construct",
            });
        }
        let mut warnings = std::mem::take(&mut self.warnings);
        if self.has_placeholder {
            self.end_word();
            let found = classify(&self.toks);
            if let Some((at, kind)) = found.error {
                return Err(TemplateError::PlaceholderInCodePosition { at, kind });
            }
            warnings.extend(found.warnings);
            warnings.sort_by_key(|w| w.at);
            warnings.dedup();
        }
        Ok(BodyAnalysis {
            script: self.out,
            referenced: self.referenced,
            warnings,
        })
    }

    // -- top-level word stream --------------------------------------------------

    /// The cursor is in the top-level list, or in quotes directly inside it, so
    /// what it reads belongs to the current top-level word.
    fn in_word_frame(&self) -> bool {
        self.has_placeholder
            && (self.stack.len() == 1
                || (self.stack.len() == 2
                    && matches!(self.stack[1], Frame::SingleQuote | Frame::DoubleQuote)))
    }

    fn at_top(&self) -> bool {
        self.has_placeholder && self.stack.len() == 1
    }

    fn word_mut(&mut self) -> &mut Word {
        let at = self.here();
        self.word.get_or_insert_with(|| Word {
            at,
            lit: String::new(),
            dynamic: false,
            quoted: false,
            plain: usize::MAX,
            slot: false,
        })
    }

    /// A literal char of the current word; `quoted` if a quote or backslash made it so.
    fn word_char(&mut self, c: char, quoted: bool) {
        let w = self.word_mut();
        if quoted {
            w.plain = w.plain.min(w.lit.len());
        }
        w.lit.push(c);
        w.quoted |= quoted;
    }

    fn word_quote(&mut self) {
        let w = self.word_mut();
        w.quoted = true;
        w.plain = w.plain.min(w.lit.len());
    }

    fn word_dynamic(&mut self) {
        let w = self.word_mut();
        w.dynamic = true;
        w.plain = w.plain.min(w.lit.len());
    }

    fn end_word(&mut self) {
        if let Some(w) = self.word.take() {
            self.toks.push(Tok::Word(w));
        }
    }

    /// A redirection operator ends the word before it; a word of only digits,
    /// or bash's `{NAME}`, is the descriptor and not a word of the command.
    fn end_word_before_redirect(&mut self) {
        if let Some(w) = self.word.take() {
            let fd_name = w
                .lit
                .strip_prefix('{')
                .and_then(|l| l.strip_suffix('}'))
                .is_some_and(|name| {
                    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                });
            let io_number = !w.dynamic
                && !w.quoted
                && !w.lit.is_empty()
                && (fd_name || w.lit.chars().all(|c| c.is_ascii_digit()));
            if !io_number {
                self.toks.push(Tok::Word(w));
            }
        }
    }

    /// `&` or `|` right after `>` or `<` belongs to the redirection (`>&2`, `>|`).
    fn glued_to_redirect(&self) -> bool {
        matches!(self.toks.last(), Some(Tok::Redir))
            && self.i > 0
            && matches!(self.chars[self.i - 1], '<' | '>')
    }

    /// A `$` that expands makes the current word dynamic, and `$1`.. `$@` `$*`
    /// are the body's own reference to the slot values.
    fn note_dollar(&mut self) {
        if !self.has_placeholder {
            return;
        }
        if self.in_word_frame() {
            self.word_dynamic();
        }
        let positional = matches!(
            (self.at(1), self.at(2)),
            (Some('1'..='9' | '@' | '*'), _) | (Some('{'), Some('1'..='9' | '@' | '*'))
        );
        if positional {
            let at = self.here();
            self.warnings.push(BodyWarning {
                at,
                kind: WarningKind::OwnPositional,
            });
        }
    }

    // -- cursor helpers -------------------------------------------------------

    fn at(&self, k: usize) -> Option<char> {
        self.chars.get(self.i + k).copied()
    }

    fn at_placeholder(&self) -> bool {
        self.at(0) == Some('{') && self.at(1) == Some('{')
    }

    fn here(&self) -> usize {
        self.off[self.i]
    }

    /// Copy the next `k` chars to the script verbatim.
    fn copy(&mut self, k: usize) {
        for c in &self.chars[self.i..self.i + k] {
            self.out.push(*c);
        }
        self.i += k;
    }

    /// Copy one char and record what it was.
    fn copy_as(&mut self, prev: Prev) {
        self.copy(1);
        self.prev = prev;
    }

    fn push(&mut self, frame: Frame, prev: Prev) {
        self.stack.push(frame);
        self.prev = prev;
    }

    fn pop(&mut self) {
        self.stack.pop();
        self.prev = Prev::Other;
    }

    // -- fail-closed refusals -------------------------------------------------

    /// The shell joins `\`+newline before it reads keywords and operators, so
    /// inside any nested frame a continuation can split `case`, `$(` or `<<`
    /// where this lexer sees two tokens. A body with a placeholder may not hold
    /// one there. Single quotes, ANSI-C strings and quoted here-documents take
    /// the backslash literally and are exempt.
    fn refuse_nested_continuation(&self) -> Result<(), TemplateError> {
        if !self.has_placeholder
            || self.stack.len() == 1
            || self.at(0) != Some('\\')
            || self.at(1) != Some('\n')
        {
            return Ok(());
        }
        match self.stack.last() {
            Some(Frame::SingleQuote | Frame::AnsiC) => Ok(()),
            Some(Frame::Heredoc(h)) if h.quoted => Ok(()),
            _ => Err(self.not_analysable("a line continuation inside a nested construct")),
        }
    }

    /// Backquote substitutions apply their own backslash removal before the
    /// shell re-reads the text, which this lexer does not model: authors use
    /// `$( )` in a body that holds a placeholder.
    fn open_backquote(&mut self) -> Result<(), TemplateError> {
        if self.has_placeholder {
            return Err(self.not_analysable("a backquote command substitution; use $( )"));
        }
        self.copy(1);
        self.push(Frame::Backquote, Prev::Open);
        Ok(())
    }

    // -- dispatch -------------------------------------------------------------

    fn step(&mut self) -> Result<(), TemplateError> {
        self.refuse_nested_continuation()?;
        match self.stack.last() {
            Some(Frame::SingleQuote) => self.single_quote(),
            Some(Frame::DoubleQuote) => self.double_quote(),
            Some(Frame::AnsiC) => self.ansi_c(),
            Some(Frame::ParamExp { in_double }) => {
                let in_double = *in_double;
                self.param_exp(in_double)
            }
            Some(Frame::Arith { .. }) => self.arith(),
            Some(Frame::Heredoc(_)) => self.heredoc(),
            _ => self.list(),
        }
    }

    // -- quoted contexts ------------------------------------------------------

    fn single_quote(&mut self) -> Result<(), TemplateError> {
        if self.at_placeholder() {
            return Err(TemplateError::PlaceholderInQuotedContext { at: self.here() });
        }
        let closes = self.at(0) == Some('\'');
        if !closes && self.in_word_frame() {
            self.word_char(self.chars[self.i], true);
        }
        self.copy(1);
        if closes {
            self.pop();
        }
        Ok(())
    }

    fn double_quote(&mut self) -> Result<(), TemplateError> {
        if self.at_placeholder() {
            return Err(TemplateError::PlaceholderInQuotedContext { at: self.here() });
        }
        match self.at(0) {
            Some('\\') => {
                if self.in_word_frame() {
                    // Approximation: the escaped char is literal.
                    if let Some(c) = self.at(1).filter(|c| *c != '\n') {
                        self.word_char(c, true);
                    }
                }
                self.copy(if self.at(1).is_some() { 2 } else { 1 })
            }
            Some('"') => {
                self.copy(1);
                self.pop();
            }
            Some('`') => {
                self.open_backquote()?;
            }
            Some('$') => self.dollar(true)?,
            Some(c) => {
                if self.in_word_frame() {
                    self.word_char(c, true);
                }
                self.copy(1);
            }
            None => self.copy(1),
        }
        Ok(())
    }

    fn ansi_c(&mut self) -> Result<(), TemplateError> {
        if self.at_placeholder() {
            return Err(self.not_expanded("ANSI-C quoting"));
        }
        match self.at(0) {
            Some('\\') => self.copy(if self.at(1).is_some() { 2 } else { 1 }),
            Some('\'') => {
                self.copy(1);
                self.pop();
            }
            _ => self.copy(1),
        }
        Ok(())
    }

    fn param_exp(&mut self, in_double: bool) -> Result<(), TemplateError> {
        if self.at_placeholder() {
            return Err(self.not_expanded("a parameter expansion"));
        }
        match self.at(0) {
            Some('\\') => self.copy(if self.at(1).is_some() { 2 } else { 1 }),
            Some('}') => {
                self.copy(1);
                self.pop();
            }
            // Inside a double-quoted expansion a single quote is a plain char.
            Some('\'') if !in_double => {
                self.copy(1);
                self.push(Frame::SingleQuote, Prev::Other);
            }
            Some('"') => {
                self.copy(1);
                self.push(Frame::DoubleQuote, Prev::Other);
            }
            Some('`') => {
                self.open_backquote()?;
            }
            Some('$') => self.dollar(in_double)?,
            _ => self.copy(1),
        }
        Ok(())
    }

    fn not_analysable(&self, reason: &'static str) -> TemplateError {
        TemplateError::BodyNotAnalysable {
            at: self.here(),
            reason,
        }
    }

    /// A `$` in any context that expands: opens `$(`, `$((`, `${` or (outside
    /// double quotes) `$'`.
    fn dollar(&mut self, quoted: bool) -> Result<(), TemplateError> {
        self.note_dollar();
        match (self.at(1), self.at(2)) {
            (Some('('), Some('(')) => {
                self.copy(3);
                self.push(
                    Frame::Arith {
                        depth: 0,
                        bracket: false,
                    },
                    Prev::Operator,
                );
            }
            (Some('('), _) => {
                self.copy(2);
                self.push(Frame::CmdSubst, Prev::Open);
            }
            (Some('['), _) => {
                self.copy(2);
                self.push(
                    Frame::Arith {
                        depth: 0,
                        bracket: true,
                    },
                    Prev::Operator,
                );
            }
            (Some('{'), Some('{')) => return Err(self.not_expanded("a parameter expansion")),
            (Some('{'), _) => {
                self.copy(2);
                self.push(Frame::ParamExp { in_double: quoted }, Prev::Other);
            }
            (Some('\''), _) if !quoted => {
                self.copy(2);
                self.push(Frame::AnsiC, Prev::Other);
            }
            _ => self.copy_as(Prev::Other),
        }
        Ok(())
    }

    fn set_arith_depth(&mut self, new: u32) {
        if let Some(Frame::Arith { depth, .. }) = self.stack.last_mut() {
            *depth = new;
        }
    }

    fn arith(&mut self) -> Result<(), TemplateError> {
        if self.at_placeholder() {
            return Err(TemplateError::PlaceholderInArithmetic { at: self.here() });
        }
        let Some(&Frame::Arith { depth, bracket }) = self.stack.last() else {
            unreachable!("arith() runs only with an Arith frame on top");
        };
        let open = if bracket { '[' } else { '(' };
        let close = if bracket { ']' } else { ')' };
        match self.at(0) {
            Some(c) if c == open => {
                self.set_arith_depth(depth + 1);
                self.copy_as(Prev::Operator);
            }
            Some(c) if c == close => {
                if depth > 0 {
                    self.set_arith_depth(depth - 1);
                    self.copy_as(Prev::Operator);
                } else if bracket {
                    self.copy(1);
                    self.pop();
                } else {
                    // A lone `)` means bash read `$((` as a command substitution
                    // wrapping a subshell, not as arithmetic.
                    if self.at(1) != Some(')') && self.has_placeholder {
                        return Err(self.not_analysable("a `$((` that is not arithmetic"));
                    }
                    self.copy(if self.at(1) == Some(')') { 2 } else { 1 });
                    self.pop();
                }
            }
            Some('\\') => {
                self.copy(if self.at(1).is_some() { 2 } else { 1 });
                self.prev = Prev::Other;
            }
            Some('\'') => {
                self.copy(1);
                self.push(Frame::SingleQuote, Prev::Other);
            }
            Some('"') => {
                self.copy(1);
                self.push(Frame::DoubleQuote, Prev::Other);
            }
            Some('`') => {
                self.open_backquote()?;
            }
            Some('$') => self.dollar(false)?,
            Some(' ' | '\t' | '\n') => self.copy_as(Prev::Blank),
            _ => self.copy_as(Prev::Other),
        }
        Ok(())
    }

    // -- command lists --------------------------------------------------------

    fn list(&mut self) -> Result<(), TemplateError> {
        if self.at_placeholder() {
            return self.placeholder();
        }
        let c = self.chars[self.i];
        let top = self.at_top();
        match c {
            '\\' => match self.at(1) {
                None => return Err(TemplateError::UnbalancedQuotes),
                // A line continuation joins the lines without creating a boundary.
                Some('\n') => {
                    // Mid-word or after an operator the join can fuse tokens
                    // (`$\⏎(`, `<\⏎<`); only a join after a blank is inert.
                    if self.has_placeholder && self.prev != Prev::Blank {
                        return Err(self.not_analysable("a line continuation inside a word"));
                    }
                    self.copy(2);
                }
                Some(escaped) => {
                    if top {
                        self.word_char(escaped, true);
                    }
                    self.copy(2);
                    self.prev = Prev::Other;
                }
            },
            '\'' | '"' => {
                if top {
                    self.word_quote();
                }
                self.copy(1);
                let frame = if c == '"' {
                    Frame::DoubleQuote
                } else {
                    Frame::SingleQuote
                };
                self.push(frame, Prev::Other);
            }
            '`' => {
                if matches!(self.stack.last(), Some(Frame::Backquote)) {
                    self.copy(1);
                    self.pop();
                } else {
                    self.open_backquote()?;
                }
            }
            '$' => self.dollar(false)?,
            '(' => {
                if top {
                    self.end_word();
                    self.toks.push(if self.at(1) == Some('(') {
                        Tok::Sep
                    } else {
                        Tok::Open
                    });
                }
                if self.at(1) == Some('(') {
                    self.copy(2);
                    self.push(
                        Frame::Arith {
                            depth: 0,
                            bracket: false,
                        },
                        Prev::Operator,
                    );
                } else {
                    self.copy(1);
                    self.push(Frame::Subshell, Prev::Open);
                }
            }
            ')' => {
                let closes = matches!(self.stack.last(), Some(Frame::CmdSubst | Frame::Subshell));
                if top {
                    self.end_word();
                    self.toks.push(Tok::Sep);
                } else if self.has_placeholder
                    && self.stack.len() == 2
                    && matches!(self.stack.last(), Some(Frame::Subshell))
                {
                    self.toks.push(Tok::Close);
                }
                self.copy(1);
                if closes {
                    self.pop();
                } else {
                    self.prev = Prev::Operator;
                }
            }
            '#' if self.prev != Prev::Other => self.comment()?,
            '\n' => {
                if top {
                    self.end_word();
                    self.toks.push(Tok::Sep);
                }
                self.copy_as(Prev::Blank);
                if !self.pending.is_empty() {
                    let docs: Vec<Heredoc> = std::mem::take(&mut self.pending);
                    // The first operator's body comes first, so it goes on top.
                    for doc in docs.into_iter().rev() {
                        self.stack.push(Frame::Heredoc(doc));
                    }
                }
            }
            ' ' | '\t' => {
                if top {
                    self.end_word();
                }
                self.copy_as(Prev::Blank);
            }
            ';' | '&' | '|' | '>' => {
                if top {
                    if c == '>' {
                        self.end_word_before_redirect();
                        self.toks.push(Tok::Redir);
                    } else if !(c != ';' && self.glued_to_redirect()) {
                        self.end_word();
                        self.toks.push(Tok::Sep);
                    }
                }
                self.copy_as(Prev::Operator);
            }
            '<' => self.less_than()?,
            'c' if self.prev != Prev::Other && self.at_word("case") => {
                // A pattern `)` ends a `$(` or `(` frame early, and a pattern is
                // not a plain word: no `case` beside a placeholder.
                if self.has_placeholder {
                    return Err(self.not_analysable("a `case` command"));
                }
                self.copy_as(Prev::Other);
            }
            '[' if self.prev != Prev::Other && self.at_word("[[") => {
                if self.has_placeholder {
                    return Err(self.not_top_level_here("a `[[ ]]` test"));
                }
                self.copy_as(Prev::Other);
            }
            _ => {
                if top {
                    self.word_char(c, false);
                }
                self.copy_as(Prev::Other);
            }
        }
        Ok(())
    }

    /// The cursor is on the whole blank-delimited word `word`.
    fn at_word(&self, word: &str) -> bool {
        let n = word.chars().count();
        word.chars().enumerate().all(|(k, c)| self.at(k) == Some(c))
            && matches!(self.at(n), None | Some(' ' | '\t' | '\n'))
    }

    fn not_top_level_here(&self, context: &'static str) -> TemplateError {
        TemplateError::PlaceholderNotTopLevel {
            at: self.here(),
            context,
        }
    }

    /// A comment runs to the end of the line; the newline is left to the caller.
    fn comment(&mut self) -> Result<(), TemplateError> {
        while let Some(c) = self.at(0) {
            if c == '\n' || (c == '`' && matches!(self.stack.last(), Some(Frame::Backquote))) {
                break;
            }
            if self.at_placeholder() {
                return Err(self.not_expanded("a comment"));
            }
            self.copy(1);
        }
        Ok(())
    }

    fn less_than(&mut self) -> Result<(), TemplateError> {
        if self.at_top() {
            self.end_word_before_redirect();
            // A here-document delimiter is read by this lexer, so only the
            // other forms leave a target word.
            if self.at(1) != Some('<') {
                self.toks.push(Tok::Redir);
            }
        }
        if self.at(1) != Some('<') {
            self.copy_as(Prev::Operator);
            return Ok(());
        }
        // `<<<` is a here-string, not a here-document.
        if self.at(2) == Some('<') {
            if self.has_placeholder {
                return Err(self.not_top_level_here("a here-string"));
            }
            self.copy(3);
            self.prev = Prev::Operator;
            return Ok(());
        }
        self.copy(2);
        let strip_tabs = self.at(0) == Some('-');
        if strip_tabs {
            self.copy(1);
        }
        while matches!(self.at(0), Some(' ' | '\t')) {
            self.copy(1);
        }
        let (delim, quoted) = self.heredoc_delimiter()?;
        if !delim.is_empty() {
            self.pending.push(Heredoc {
                delim,
                strip_tabs,
                quoted,
                bol: true,
            });
        }
        self.prev = Prev::Other;
        Ok(())
    }

    /// Read the here-document delimiter word, quote-removed. It is quoted if any
    /// part of the word was quoted or escaped.
    fn heredoc_delimiter(&mut self) -> Result<(Vec<char>, bool), TemplateError> {
        let mut delim = Vec::new();
        let mut quoted = false;
        while let Some(c) = self.at(0) {
            if self.at_placeholder() {
                return Err(self.not_expanded("a here-document delimiter"));
            }
            match c {
                ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')' => break,
                '\\' => {
                    quoted = true;
                    self.copy(1);
                    if let Some(next) = self.at(0) {
                        delim.push(next);
                        self.copy(1);
                    }
                }
                '\'' | '"' => {
                    quoted = true;
                    self.copy(1);
                    while let Some(inner) = self.at(0) {
                        if self.at_placeholder() {
                            return Err(self.not_expanded("a here-document delimiter"));
                        }
                        self.copy(1);
                        if inner == c {
                            break;
                        }
                        if inner == '\\' && c == '"' {
                            if let Some(next) = self.at(0) {
                                delim.push(next);
                                self.copy(1);
                                continue;
                            }
                        }
                        delim.push(inner);
                    }
                }
                _ => {
                    delim.push(c);
                    self.copy(1);
                }
            }
        }
        Ok((delim, quoted))
    }

    // -- here-document bodies -------------------------------------------------

    fn heredoc(&mut self) -> Result<(), TemplateError> {
        if self.heredoc_mut().bol {
            self.heredoc_mut().bol = false;
            if let Some(end) = self.delimiter_line_end() {
                let upto = if self.chars.get(end) == Some(&'\n') {
                    end + 1
                } else {
                    end
                };
                self.copy(upto - self.i);
                self.stack.pop();
                self.prev = Prev::Blank;
                return Ok(());
            }
        }
        if self.heredoc_mut().quoted {
            if self.at_placeholder() {
                return Err(self.not_expanded("a quoted here-document"));
            }
            self.heredoc_mut().bol = self.at(0) == Some('\n');
            self.copy(1);
            return Ok(());
        }
        if self.at_placeholder() {
            return self.placeholder();
        }
        match self.at(0) {
            Some('\\') => {
                let continuation = self.at(1) == Some('\n');
                self.copy(if self.at(1).is_some() { 2 } else { 1 });
                if !continuation {
                    self.prev = Prev::Other;
                }
            }
            Some('`') => {
                self.open_backquote()?;
            }
            Some('$') => self.dollar(true)?,
            Some('\n') => {
                self.copy_as(Prev::Blank);
                self.heredoc_mut().bol = true;
            }
            Some(' ' | '\t') => self.copy_as(Prev::Blank),
            _ => self.copy_as(Prev::Other),
        }
        Ok(())
    }

    /// The here-document frame on top of the stack; only called from `heredoc`.
    fn heredoc_mut(&mut self) -> &mut Heredoc {
        match self.stack.last_mut() {
            Some(Frame::Heredoc(h)) => h,
            _ => unreachable!("heredoc() runs only with a Heredoc frame on top"),
        }
    }

    /// If the line starting at the cursor is the current here-document's
    /// delimiter, the char index where that line ends.
    fn delimiter_line_end(&self) -> Option<usize> {
        let Some(Frame::Heredoc(h)) = self.stack.last() else {
            return None;
        };
        let mut start = self.i;
        if h.strip_tabs {
            while self.chars.get(start) == Some(&'\t') {
                start += 1;
            }
        }
        let mut end = start;
        while end < self.chars.len() && self.chars[end] != '\n' {
            end += 1;
        }
        (self.chars[start..end] == h.delim[..]).then_some(end)
    }

    // -- placeholders ---------------------------------------------------------

    fn not_expanded(&self, context: &'static str) -> TemplateError {
        TemplateError::PlaceholderNotExpanded {
            at: self.here(),
            context,
        }
    }

    /// Consume a `{{slot}}` at the cursor, or refuse it. A placeholder is
    /// accepted only as a whole word in an expanding, unquoted context.
    fn placeholder(&mut self) -> Result<(), TemplateError> {
        let at = self.here();

        // A slot is a plain word of the top-level command list and nowhere else.
        match self.stack.last() {
            Some(Frame::SingleQuote | Frame::DoubleQuote) => {
                return Err(TemplateError::PlaceholderInQuotedContext { at });
            }
            Some(Frame::AnsiC) => return Err(self.not_expanded("ANSI-C quoting")),
            Some(Frame::ParamExp { .. }) => {
                return Err(self.not_expanded("a parameter expansion"));
            }
            Some(Frame::Arith { .. }) => {
                return Err(TemplateError::PlaceholderInArithmetic { at });
            }
            Some(Frame::Heredoc(_)) => return Err(self.not_top_level_here("a here-document")),
            Some(Frame::CmdSubst) => {
                return Err(self.not_top_level_here("a command substitution"));
            }
            Some(Frame::Subshell) => return Err(self.not_top_level_here("a subshell")),
            Some(Frame::Backquote) => {
                return Err(self.not_top_level_here("a backquote substitution"));
            }
            Some(Frame::Top) | None => {}
        }
        if self.prev != Prev::Blank {
            return Err(TemplateError::PlaceholderNotStandalone { at });
        }

        let n = self.chars.len();
        let mut j = self.i + 2;
        let mut close = None;
        while j + 1 < n {
            if self.chars[j] == '}' && self.chars[j + 1] == '}' {
                close = Some(j);
                break;
            }
            if self.chars[j] == '{' && self.chars[j + 1] == '{' {
                return Err(TemplateError::MalformedPlaceholder {
                    at,
                    detail: "nested '{{' before a closing '}}'",
                });
            }
            j += 1;
        }
        let Some(j) = close else {
            return Err(TemplateError::MalformedPlaceholder {
                at,
                detail: "unterminated placeholder (no closing '}}')",
            });
        };

        let right_ok = match self.chars.get(j + 2) {
            None | Some(' ' | '\t' | '\n') => true,
            Some(_) => false,
        };
        if !right_ok {
            return Err(TemplateError::PlaceholderNotStandalone { at });
        }

        let inner: String = self.chars[self.i + 2..j].iter().collect();
        let name = inner.trim();
        if !is_valid_slot_name(name) {
            return Err(TemplateError::MalformedPlaceholder {
                at,
                detail: "placeholder name must match ^[a-z][a-z0-9_]*$",
            });
        }
        let Some(idx) = self.slots.iter().position(|s| s.name == name) else {
            return Err(TemplateError::UnknownSlot {
                name: name.to_string(),
            });
        };

        self.toks.push(Tok::Word(Word::slot(at)));
        self.out.push_str(&positional_ref(idx));
        self.referenced.insert(idx);
        self.i = j + 2;
        self.prev = Prev::Other;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::template::SlotType;

    fn slots(names: &[&str]) -> Vec<Slot> {
        names
            .iter()
            .map(|n| Slot {
                name: n.to_string(),
                ty: SlotType::Path,
            })
            .collect()
    }

    fn script(body: &str) -> String {
        analyse(body, &slots(&["p"]))
            .unwrap_or_else(|e| panic!("{body:?} should lex: {e}"))
            .script
    }

    fn error(body: &str) -> TemplateError {
        match analyse(body, &slots(&["p"])) {
            Ok(a) => panic!("{body:?} should be refused, got {:?}", a.script),
            Err(e) => e,
        }
    }

    fn not_standalone(body: &str) {
        assert!(
            matches!(error(body), TemplateError::PlaceholderNotStandalone { .. }),
            "{body:?}"
        );
    }

    #[test]
    fn standalone_placeholders_become_quoted_parameters() {
        for (body, want) in [
            ("echo {{p}}", "echo \"$1\""),
            ("echo x {{p}}", "echo x \"$1\""),
            ("echo {{ p }}", "echo \"$1\""),
            ("echo\t{{p}}\ttail", "echo\t\"$1\"\ttail"),
            ("a\necho {{p}}\nb", "a\necho \"$1\"\nb"),
            ("echo a \\\n{{p}}", "echo a \\\n\"$1\""),
            ("echo {{p}} | cat -n {{p}}", "echo \"$1\" | cat -n \"$1\""),
            (
                "true && echo {{p}} || echo {{p}} ; echo",
                "true && echo \"$1\" || echo \"$1\" ; echo",
            ),
            ("{ echo {{p}} ; }", "{ echo \"$1\" ; }"),
            ("f() { echo {{p}} ; }", "f() { echo \"$1\" ; }"),
            (
                "echo $(echo x) {{p}} \"$(echo y)\"",
                "echo $(echo x) \"$1\" \"$(echo y)\"",
            ),
        ] {
            assert_eq!(script(body), want, "{body:?}");
        }
    }

    #[test]
    fn a_placeholder_must_be_a_whole_word() {
        for body in [
            "echo x{{p}}",
            "echo {{p}}x",
            "echo >{{p}}",
            "echo <{{p}}",
            "echo ;{{p}}",
            "echo |{{p}}",
            "echo &{{p}}",
            "echo {{p}};",
            "echo {{p}})",
            "echo {{p}}{{p}}",
            "echo -n={{p}}",
            "echo a\\ {{p}}",
            "echo {{p}}\\ x",
            // Form feed, carriage return and vertical tab are word characters.
            "echo a\u{c}{{p}}",
            "echo {{p}}\u{c}",
            "echo a\r{{p}}",
            "echo {{p}}\r",
            "echo {{p}}\r\n",
            "echo a\u{b}{{p}}",
            "echo\u{a0}{{p}}",
        ] {
            not_standalone(body);
        }
    }

    #[test]
    fn a_placeholder_in_quotes_is_refused() {
        for body in [
            "echo \"{{p}}\"",
            "echo '{{p}}'",
            "echo \"a {{p}} b\"",
            "echo \"$(echo \"{{p}}\")\"",
            "echo 'a'\"{{p}}\"",
        ] {
            assert!(
                matches!(
                    error(body),
                    TemplateError::PlaceholderInQuotedContext { .. }
                ),
                "{body:?}"
            );
        }
    }

    #[test]
    fn a_placeholder_the_shell_never_expands_is_refused() {
        for body in [
            "true # {{p}}",
            "true\n# {{p}}\necho",
            "echo $'x {{p}}'",
            "echo ${x:- {{p}} }",
            "echo ${{p}}",
            "cat <<'EOF'\n{{p}}\nEOF",
            "cat <<\\EOF\n{{p}}\nEOF",
            "cat << {{p}}\nx\n{{p}}",
            "cat <<'{{p}}'\n",
        ] {
            assert!(
                matches!(error(body), TemplateError::PlaceholderNotExpanded { .. }),
                "{body:?}"
            );
        }
    }

    #[test]
    fn unbalanced_quotes_are_refused_for_every_body() {
        for body in [
            "echo 'x",
            "echo \"x",
            "echo x\\",
            "echo $'x",
            "echo \"$(echo 'x)\"",
        ] {
            assert_eq!(
                analyse(body, &[]).err(),
                Some(TemplateError::UnbalancedQuotes),
                "{body:?}"
            );
        }
    }

    #[test]
    fn here_documents_hold_no_placeholder() {
        for body in [
            "cat <<EOF\n{{p}}\nEOF",
            "cat <<-EOF\n\t{{p}}\n\tEOF",
            "cat <<A <<B\n{{p}}\nA\n{{p}}\nB",
            "cat <<EOF\n$(echo {{p}})\nEOF",
            "sh <<EOF\necho {{p}}\nEOF",
            "cat <<EOF\n$(( 1 $(echo {{p}}) ))\nEOF",
            "cat <<< {{p}}",
        ] {
            assert!(
                matches!(error(body), TemplateError::PlaceholderNotTopLevel { .. }),
                "{body:?}"
            );
        }
        // After the delimiter line the body is over; the top level is back.
        assert_eq!(
            script("cat <<A <<B\nx\nA\ny\nB\necho {{p}}"),
            "cat <<A <<B\nx\nA\ny\nB\necho \"$1\""
        );
        not_standalone("cat <<EOF\nx\nEOF\necho x{{p}}");
        // Slot-free here-documents and here-strings still load.
        assert!(analyse("cat <<EOF\nhi\nEOF\ncat <<< x", &slots(&[])).is_ok());
    }

    #[test]
    fn a_placeholder_is_accepted_only_at_the_top_level() {
        for body in [
            "echo $(echo {{p}})",
            "echo $({{p}} x)",
            "(echo {{p}})",
            "echo ( {{p}} )",
            "echo \"a $(echo {{p}}) b\"",
            "echo \"$(echo \")\" {{p}} \")\")\"",
            "echo $(( 1 $(echo {{p}}) ))",
            "echo $[ 1 $(echo {{p}}) ]",
            "(( 1 $(echo {{p}}) ))",
            "for (( i=1$(echo {{p}}); i<0; )); do :; done",
            "echo $(( $(echo 1 {{p}}) ))",
            "x=abc; echo ${x:1$(echo {{p}})}",
            "x=(a b); echo ${x[1$(echo {{p}})]}",
            "find $(dirname {{p}}) -maxdepth 0 -print",
            "ls -ld $(dirname {{p}})",
            "cat <( echo {{p}} )",
            "x=( {{p}} )",
            "[[ 1 -eq {{p}} ]]",
            "cat <<< {{p}}",
        ] {
            error(body);
        }
        assert!(matches!(
            error("echo $(echo {{p}})"),
            TemplateError::PlaceholderNotTopLevel { .. }
        ));
        assert!(matches!(
            error("(echo {{p}})"),
            TemplateError::PlaceholderNotTopLevel { .. }
        ));
    }

    #[test]
    fn comments_and_ansi_c_quotes_do_not_unbalance_other_quotes() {
        // Slot-free bodies the shell parses are accepted whatever quote chars
        // sit in a comment, an ANSI-C string or a here-document.
        for body in [
            "true # it's",
            "echo $'it\\'s' ok",
            "cat <<EOF\nit's\nEOF",
            "case x in a) echo hi;; esac",
        ] {
            assert!(analyse(body, &slots(&[])).is_ok(), "{body:?}");
        }
        assert_eq!(
            script("true #'\necho {{p}} \\'"),
            "true #'\necho \"$1\" \\'"
        );
        // `#` inside a word is not a comment.
        assert_eq!(script("echo a#b {{p}}"), "echo a#b \"$1\"");
        assert_eq!(script("echo $# {{p}}"), "echo $# \"$1\"");
    }

    #[test]
    fn unknown_and_malformed_placeholders_are_refused() {
        assert!(matches!(
            analyse("echo {{q}}", &slots(&["p"])).err(),
            Some(TemplateError::UnknownSlot { .. })
        ));
        assert!(matches!(
            error("echo {{p"),
            TemplateError::MalformedPlaceholder { .. }
        ));
        assert!(matches!(
            error("echo {{P}}"),
            TemplateError::MalformedPlaceholder { .. }
        ));
    }

    #[test]
    fn a_placeholder_in_arithmetic_is_refused() {
        for body in [
            "echo $(( {{p}} + 1 ))",
            "(( {{p}} ))",
            "for (( i = {{p}} ; ; )) ; do :; done",
            "echo \"$(( {{p}} ))\"",
        ] {
            assert!(
                matches!(error(body), TemplateError::PlaceholderInArithmetic { .. }),
                "{body:?}"
            );
        }
        // So is a command substitution inside arithmetic.
        assert!(matches!(
            error("echo $(( $(echo {{p}}) + 1 ))"),
            TemplateError::PlaceholderNotTopLevel { .. }
        ));
    }

    fn not_analysable(body: &str) {
        assert!(
            matches!(error(body), TemplateError::BodyNotAnalysable { .. }),
            "{body:?}"
        );
    }

    #[test]
    fn unterminated_constructs_are_refused_only_with_a_placeholder() {
        for open in [
            "echo {{p}} $(echo",
            "echo {{p}} `echo",
            "echo {{p}} ${x:-a",
            "echo {{p}} $((1",
            "echo {{p}} ; cat <<EOF\nx\n",
            "cat <<EOF {{p}}",
        ] {
            not_analysable(open);
        }
        for open in [
            "echo $(echo",
            "echo `echo",
            "echo ${x",
            "cat <<EOF\nx",
            "cat <<EOF",
        ] {
            assert!(analyse(open, &slots(&[])).is_ok(), "{open:?}");
        }
    }

    #[test]
    fn a_case_command_is_refused_beside_a_placeholder() {
        // The pattern's `)` would close a `$(` early, and a pattern is not a
        // plain word.
        not_analysable("echo \"$(case x in x) printf '<%s>' \" {{p}} \" ;; esac)\"");
        not_analysable("echo $(case x in x) echo hi ;; esac) {{p}}");
        not_analysable("(case x in x) :;; esac; echo {{p}})");
        not_analysable("echo `case x in x) :;; esac` {{p}}");
        not_analysable("case x in x) echo {{p}} ;; esac");
        not_analysable("case {{p}} in x) :;; esac");
        // `case` as part of a word is not the keyword; slot-free bodies load.
        assert_eq!(
            script("echo $(echo case) {{p}}"),
            "echo $(echo case) \"$1\""
        );
        assert_eq!(
            script("echo $(echo incase) {{p}}"),
            "echo $(echo incase) \"$1\""
        );
        assert!(analyse("echo $(case x in x) :;; esac)", &slots(&[])).is_ok());
        assert!(analyse("case x in x) :;; esac", &slots(&[])).is_ok());
    }

    #[test]
    fn a_double_paren_that_is_not_arithmetic_is_refused() {
        not_analysable("echo \"$((echo a) ; printf '<%s>' \" {{p}} \")\"");
        assert!(analyse("echo $((echo a) ; echo b)", &slots(&[])).is_ok());
        assert_eq!(
            script("echo $((1 + (2))) {{p}}"),
            "echo $((1 + (2))) \"$1\""
        );
    }

    #[test]
    fn a_comment_inside_backquotes_ends_at_the_closing_backquote() {
        // Backquotes are only lexed in a body without a placeholder.
        assert!(analyse("echo `true # note` x", &slots(&[])).is_ok());
    }

    #[test]
    fn a_legacy_arithmetic_bracket_is_arithmetic() {
        for body in [
            "echo $[ 1 {{p}} ]",
            "echo \"$[ 1 + {{p}} ]\"",
            "echo $[ a[1] + {{p}} ]",
        ] {
            assert!(
                matches!(error(body), TemplateError::PlaceholderInArithmetic { .. }),
                "{body:?}"
            );
        }
        // Unterminated, with a placeholder elsewhere.
        not_analysable("echo {{p}} $[ 1 + 2");
        // A closed one elsewhere in the body is fine.
        assert_eq!(
            script("echo $[ a[1] + 2 ] {{p}}"),
            "echo $[ a[1] + 2 ] \"$1\""
        );
        assert!(analyse("echo $[ 1", &slots(&[])).is_ok());
    }

    #[test]
    fn backquotes_are_refused_when_the_body_has_a_placeholder() {
        for body in [
            "printf '<%s>' \"`printf '[%s]' \\\" {{p}} \\\"`\"",
            "printf '<%s>' `printf '[%s]' \\\\\\\" {{p}} \\\\\\\"`",
            "printf '<%s>' \"${x:-`printf '[%s]' \\\" {{p}} \\\"`}\"",
            "cat <<EOF\n`printf '[%s]' \\\" {{p}} \\\"`\nEOF",
            "echo `echo {{p}}`",
            "echo {{p}} `true`",
        ] {
            not_analysable(body);
        }
        // Escaped, single-quoted or commented backquotes are not substitutions.
        assert_eq!(script("echo \\` '`' {{p}}"), "echo \\` '`' \"$1\"");
        assert_eq!(script("true # `x`\necho {{p}}"), "true # `x`\necho \"$1\"");
        assert!(analyse("echo `true` x", &slots(&[])).is_ok());
    }

    #[test]
    fn a_line_continuation_that_can_split_a_keyword_is_refused() {
        for body in [
            "printf '<%s>' \"$(ca\\\nse x in x) printf '[%s]' \" {{p}} \" ;; esac)\"",
            "printf '<%s>' \"$(case\\\n x in x) printf '[%s]' \" {{p}} \" ;; esac)\"",
            "echo $(echo \\\n) {{p}}",
            "echo (echo \\\n) {{p}}",
            "echo \"a\\\nb\" {{p}}",
            "echo ${x:-a\\\nb} {{p}}",
            "echo $(( 1 +\\\n 2 )) {{p}}",
            "cat <<EOF\na\\\nb\nEOF\necho {{p}}",
            // Mid-word or after an operator at the top level: the join can fuse
            // `$` + `(` or `<` + `<` that the lexer reads as separate tokens.
            "echo $\\\n(echo) {{p}}",
            "cat <\\\n<EOF\nx\nEOF\necho {{p}}",
            "echo a\\\n{{p}}",
            "echo x;\\\n{{p}}",
        ] {
            not_analysable(body);
        }
        // Between words, after a blank, a continuation is inert; single quotes
        // and quoted here-documents take the backslash literally.
        assert_eq!(script("echo a \\\n{{p}}"), "echo a \\\n\"$1\"");
        assert_eq!(script("echo 'a\\\nb' {{p}}"), "echo 'a\\\nb' \"$1\"");
        assert_eq!(
            script("cat <<'E'\na\\\nb\nE\necho {{p}}"),
            "cat <<'E'\na\\\nb\nE\necho \"$1\""
        );
        assert!(analyse("echo $(echo \\\n) x", &slots(&[])).is_ok());
    }

    #[test]
    fn stacked_here_documents_each_check_their_own_delimiter() {
        assert_eq!(
            script("cat <<A <<B\nA-ish\nA\nB-ish\nB\necho {{p}}"),
            "cat <<A <<B\nA-ish\nA\nB-ish\nB\necho \"$1\""
        );
    }

    mod never_panics {
        use super::*;
        use proptest::prelude::*;

        fn token() -> impl Strategy<Value = &'static str> {
            proptest::sample::select(vec![
                "{{p}}", "{{", "}}", "$(", ")", "`", "$[", "]", "\\\n", "'", "\"", "\\", "<<EOF\n",
                "<<-X\n", "EOF\n", "X\n", "#", "$((", "))", "((", "${", "}", " ", "\t", "\n", "\r",
                "x", ";", "|", "&", "<", "<<<", ">", "case ", "(", "$'", "$", "\u{c}", "é",
            ])
        }

        proptest! {
            // Arbitrary token soup, with and without placeholders, never panics.
            #[test]
            fn analyse_never_panics(tokens in proptest::collection::vec(token(), 0..40)) {
                let body: String = tokens.concat();
                let _ = analyse(&body, &slots(&["p"]));
                let _ = analyse(&body, &slots(&[]));
            }

            #[test]
            fn analyse_never_panics_on_arbitrary_text(body in ".{0,80}", at in 0usize..80) {
                let mut chars: Vec<char> = body.chars().collect();
                let at = at.min(chars.len());
                chars.splice(at..at, "{{p}}".chars());
                let _ = analyse(&chars.iter().collect::<String>(), &slots(&["p"]));
            }
        }
    }
}
