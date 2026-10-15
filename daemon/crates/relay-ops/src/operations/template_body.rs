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
//! where quotes end (`$'…'`, `$(( ))`, `${ }`). It does not model `case`
//! patterns, `[[ ]]`, `$[ ]`, `&>`, aliases or functions.

use std::collections::HashSet;

use super::template::{is_valid_slot_name, positional_ref, Slot, TemplateError};

/// The result of lexing a body: the script to hand to `/bin/sh -c` and the slots
/// it references.
pub(super) struct BodyAnalysis {
    pub script: String,
    pub referenced: HashSet<usize>,
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
}

enum Frame {
    Top,
    CmdSubst,
    Subshell,
    Backquote,
    DoubleQuote,
    SingleQuote,
    AnsiC,
    ParamExp { in_double: bool },
    Arith { depth: u32 },
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
    /// The next char starts a here-document line (only read by a `Heredoc` frame).
    bol: bool,
    /// Here-documents whose operator was read; their bodies start after the
    /// next newline.
    pending: Vec<Heredoc>,
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
            bol: false,
            pending: Vec::new(),
        }
    }

    fn finish(self) -> Result<BodyAnalysis, TemplateError> {
        let open_quote = self
            .stack
            .iter()
            .any(|f| matches!(f, Frame::SingleQuote | Frame::DoubleQuote | Frame::AnsiC));
        if open_quote {
            return Err(TemplateError::UnbalancedQuotes);
        }
        Ok(BodyAnalysis {
            script: self.out,
            referenced: self.referenced,
        })
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

    // -- dispatch -------------------------------------------------------------

    fn step(&mut self) -> Result<(), TemplateError> {
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
            Some('\\') => self.copy(if self.at(1).is_some() { 2 } else { 1 }),
            Some('"') => {
                self.copy(1);
                self.pop();
            }
            Some('`') => {
                self.copy(1);
                self.push(Frame::Backquote, Prev::Open);
            }
            Some('$') => self.dollar(true)?,
            _ => self.copy(1),
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
                self.copy(1);
                self.push(Frame::Backquote, Prev::Open);
            }
            Some('$') => self.dollar(true)?,
            _ => self.copy(1),
        }
        Ok(())
    }

    /// A `$` in any context that expands: opens `$(`, `$((`, `${` or (outside
    /// double quotes) `$'`.
    fn dollar(&mut self, quoted: bool) -> Result<(), TemplateError> {
        match (self.at(1), self.at(2)) {
            (Some('('), Some('(')) => {
                self.copy(3);
                self.push(Frame::Arith { depth: 0 }, Prev::Operator);
            }
            (Some('('), _) => {
                self.copy(2);
                self.push(Frame::CmdSubst, Prev::Open);
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

    fn arith(&mut self) -> Result<(), TemplateError> {
        if self.at_placeholder() {
            return self.placeholder();
        }
        match self.at(0) {
            Some('(') => {
                if let Some(Frame::Arith { depth }) = self.stack.last_mut() {
                    *depth += 1;
                }
                self.copy_as(Prev::Operator);
            }
            Some(')') => {
                let nested =
                    matches!(self.stack.last(), Some(Frame::Arith { depth }) if *depth > 0);
                if nested {
                    if let Some(Frame::Arith { depth }) = self.stack.last_mut() {
                        *depth -= 1;
                    }
                    self.copy_as(Prev::Operator);
                } else {
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
                self.copy(1);
                self.push(Frame::Backquote, Prev::Open);
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
        let Some(c) = self.at(0) else {
            return Ok(());
        };
        match c {
            '\\' => match self.at(1) {
                None => return Err(TemplateError::UnbalancedQuotes),
                // A line continuation joins the lines without creating a boundary.
                Some('\n') => self.copy(2),
                Some(_) => {
                    self.copy(2);
                    self.prev = Prev::Other;
                }
            },
            '\'' => {
                self.copy(1);
                self.push(Frame::SingleQuote, Prev::Other);
            }
            '"' => {
                self.copy(1);
                self.push(Frame::DoubleQuote, Prev::Other);
            }
            '`' => {
                self.copy(1);
                if matches!(self.stack.last(), Some(Frame::Backquote)) {
                    self.pop();
                } else {
                    self.push(Frame::Backquote, Prev::Open);
                }
            }
            '$' => self.dollar(false)?,
            '(' => {
                if self.at(1) == Some('(') {
                    self.copy(2);
                    self.push(Frame::Arith { depth: 0 }, Prev::Operator);
                } else {
                    self.copy(1);
                    self.push(Frame::Subshell, Prev::Open);
                }
            }
            ')' => {
                let closes = matches!(self.stack.last(), Some(Frame::CmdSubst | Frame::Subshell));
                self.copy(1);
                if closes {
                    self.pop();
                } else {
                    self.prev = Prev::Operator;
                }
            }
            '#' if self.prev != Prev::Other => self.comment()?,
            '\n' => {
                self.copy_as(Prev::Blank);
                if !self.pending.is_empty() {
                    let docs: Vec<Heredoc> = self.pending.drain(..).collect();
                    // The first operator's body comes first, so it goes on top.
                    for doc in docs.into_iter().rev() {
                        self.stack.push(Frame::Heredoc(doc));
                    }
                    self.bol = true;
                }
            }
            ' ' | '\t' => self.copy_as(Prev::Blank),
            ';' | '&' | '|' | '>' => self.copy_as(Prev::Operator),
            '<' => self.less_than()?,
            _ => self.copy_as(Prev::Other),
        }
        Ok(())
    }

    /// A comment runs to the end of the line; the newline is left to the caller.
    fn comment(&mut self) -> Result<(), TemplateError> {
        while let Some(c) = self.at(0) {
            if c == '\n' {
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
        if self.at(1) != Some('<') {
            self.copy_as(Prev::Operator);
            return Ok(());
        }
        // `<<<` is a here-string, not a here-document.
        if self.at(2) == Some('<') {
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
        if self.bol {
            self.bol = false;
            if let Some(end) = self.delimiter_line_end() {
                let upto = if self.chars.get(end) == Some(&'\n') {
                    end + 1
                } else {
                    end
                };
                self.copy(upto - self.i);
                self.stack.pop();
                self.prev = Prev::Blank;
                self.bol = true;
                return Ok(());
            }
        }
        let quoted = matches!(self.stack.last(), Some(Frame::Heredoc(h)) if h.quoted);
        if quoted {
            if self.at_placeholder() {
                return Err(self.not_expanded("a quoted here-document"));
            }
            self.bol = self.at(0) == Some('\n');
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
                self.copy(1);
                self.push(Frame::Backquote, Prev::Open);
            }
            Some('$') => self.dollar(true)?,
            Some('\n') => {
                self.copy_as(Prev::Blank);
                self.bol = true;
            }
            Some(' ' | '\t') => self.copy_as(Prev::Blank),
            _ => self.copy_as(Prev::Other),
        }
        Ok(())
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

        let left_ok = match self.stack.last() {
            Some(Frame::SingleQuote | Frame::DoubleQuote) => {
                return Err(TemplateError::PlaceholderInQuotedContext { at });
            }
            Some(Frame::AnsiC) => return Err(self.not_expanded("ANSI-C quoting")),
            Some(Frame::ParamExp { .. }) => {
                return Err(self.not_expanded("a parameter expansion"));
            }
            Some(Frame::Arith { .. } | Frame::Heredoc(_)) => self.prev == Prev::Blank,
            _ => matches!(self.prev, Prev::Blank | Prev::Open),
        };
        if !left_ok {
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
            Some(')') => matches!(self.stack.last(), Some(Frame::CmdSubst | Frame::Subshell)),
            Some('`') => matches!(self.stack.last(), Some(Frame::Backquote)),
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
            ("{{p}} x", "\"$1\" x"),
            ("echo {{ p }}", "echo \"$1\""),
            ("echo\t{{p}}\ttail", "echo\t\"$1\"\ttail"),
            ("a\n{{p}}\nb", "a\n\"$1\"\nb"),
            ("echo $(echo {{p}})", "echo $(echo \"$1\")"),
            ("echo $({{p}} x)", "echo $(\"$1\" x)"),
            ("echo `echo {{p}}`", "echo `echo \"$1\"`"),
            ("(echo {{p}})", "(echo \"$1\")"),
            ("echo \"a $(echo {{p}}) b\"", "echo \"a $(echo \"$1\") b\""),
            ("echo a \\\n{{p}}", "echo a \\\n\"$1\""),
            (
                "echo \"$(echo \")\" {{p}} \")\")\"",
                "echo \"$(echo \")\" \"$1\" \")\")\"",
            ),
            ("echo $(( {{p}} + 1 ))", "echo $(( \"$1\" + 1 ))"),
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
            "echo a\\\n{{p}}",
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
    fn here_documents_expand_placeholders_in_unquoted_bodies_only() {
        assert_eq!(script("cat <<EOF\n{{p}}\nEOF"), "cat <<EOF\n\"$1\"\nEOF");
        assert_eq!(
            script("cat <<-EOF\n\t{{p}}\n\tEOF\necho {{p}}"),
            "cat <<-EOF\n\t\"$1\"\n\tEOF\necho \"$1\""
        );
        // Two here-documents on one line; the second body follows the first.
        assert_eq!(
            script("cat <<A <<B\n{{p}}\nA\n{{p}}\nB\necho {{p}}"),
            "cat <<A <<B\n\"$1\"\nA\n\"$1\"\nB\necho \"$1\""
        );
        // After the delimiter line the body is over: glue is refused again.
        not_standalone("cat <<EOF\nx\nEOF\necho x{{p}}");
        // A command substitution inside the body is lexed as code.
        assert_eq!(
            script("cat <<EOF\n$(echo {{p}})\nEOF"),
            "cat <<EOF\n$(echo \"$1\")\nEOF"
        );
        // A here-string is not a here-document.
        assert_eq!(script("cat <<< {{p}}"), "cat <<< \"$1\"");
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
}
