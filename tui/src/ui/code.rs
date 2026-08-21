//! Fenced code blocks in agent responses: splitting, language detection, highlighting,
//! and whitespace-exact layout.
//!
//! The prose wrapper is the wrong tool for code twice over: it collapses runs of spaces,
//! which destroys indentation, and it knows nothing about languages, so a function and its
//! comment render in one undifferentiated colour. Messages are therefore split at ```
//! fences and each side takes its own path. The highlighter is deliberately not a parser —
//! per-language tables recognise comments, strings, numbers, keywords, call names, and
//! capitalized names, and exactly two pieces of state survive a line break (block comments
//! and triple-quoted strings). Anything it cannot model renders as ordinary text, which is
//! what the whole block used to get. An unterminated fence is a block still streaming, so
//! it is rendered as a block rather than abandoned to the prose path.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthChar;

/// One fenced region of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBlock<'a> {
    /// First word of the fence info string, lowercased (`rust`, `sh`, `py`…).
    pub lang: Option<&'a str>,
    pub code: &'a str,
    /// False while the closing fence has not arrived yet.
    pub closed: bool,
}

/// A message split at fences: prose keeps the word-wrapping path, code does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment<'a> {
    Prose(&'a str),
    Code(CodeBlock<'a>),
}

/// Splits message text into prose and fenced-code segments, in order.
pub fn split_fences(text: &str) -> Vec<Segment<'_>> {
    let mut segments = Vec::new();
    let mut prose_start = 0;
    let mut cursor = 0;

    while let Some((open_at, content_start, info)) = find_fence(text, cursor) {
        if !at_line_start(text, open_at) {
            cursor = content_start;
            continue;
        }

        match find_closing_fence(text, content_start) {
            Some((close_at, resume)) => {
                push_prose(&mut segments, &text[prose_start..open_at]);
                segments.push(Segment::Code(CodeBlock {
                    lang: info,
                    code: &text[content_start..close_at],
                    closed: true,
                }));
                cursor = resume;
                prose_start = cursor;
            }
            None => {
                push_prose(&mut segments, &text[prose_start..open_at]);
                segments.push(Segment::Code(CodeBlock {
                    lang: info,
                    code: &text[content_start..],
                    closed: false,
                }));
                return segments;
            }
        }
    }

    push_prose(&mut segments, &text[prose_start..]);
    segments
}

fn push_prose<'a>(segments: &mut Vec<Segment<'a>>, text: &'a str) {
    if !text.is_empty() {
        segments.push(Segment::Prose(text));
    }
}

/// Whether everything between the previous newline and `at` is indentation.
fn at_line_start(text: &str, at: usize) -> bool {
    let line_begin = text[..at].rfind('\n').map(|found| found + 1).unwrap_or(0);
    text[line_begin..at]
        .chars()
        .all(|character| character == ' ' || character == '\t')
}

/// Finds the next fence opener: (line-start byte, content byte, info string).
fn find_fence(text: &str, from: usize) -> Option<(usize, usize, Option<&str>)> {
    let mut index = from;

    while index < text.len() {
        let line_start = index;
        let line_end = text[index..]
            .find('\n')
            .map(|offset| index + offset)
            .unwrap_or(text.len());

        let trimmed = text[line_start..line_end].trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            // The language is the first whitespace-delimited word; the remainder of an
            // info line is metadata (`{highlightLines}` and friends) that is not a name.
            let info = trimmed[3..].split_whitespace().next().filter(|word| {
                !word.is_empty()
                    && word
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "+#.-_".contains(c))
            });
            let content = (line_end + 1).min(text.len());
            return Some((line_start, content, info));
        }

        index = line_end + 1;
    }

    None
}

/// Finds the closer for a block opened at `from`: (closer line start, byte after it).
fn find_closing_fence(text: &str, from: usize) -> Option<(usize, usize)> {
    let mut index = from;

    while index < text.len() {
        let line_start = index;
        let line_end = text[index..]
            .find('\n')
            .map(|offset| index + offset)
            .unwrap_or(text.len());

        let trimmed = text[line_start..line_end].trim();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            return Some((line_start, (line_end + 1).min(text.len())));
        }

        index = line_end + 1;
    }

    None
}

/// Languages the highlighter names. Unknown fences fall back to [`Language::Plain`],
/// which still colours strings and numbers by generic rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
    C,
    Cpp,
    Java,
    Go,
    Js,
    Python,
    Ruby,
    Shell,
    Elixir,
    Erlang,
    Sql,
    Json,
    Yaml,
    Toml,
    Html,
    Css,
    Lua,
    Haskell,
    Diff,
    Plain,
}

impl Language {
    /// The label shown on a block's frame; aliases collapse to the canonical name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::C => "c",
            Self::Cpp => "c++",
            Self::Java => "java",
            Self::Go => "go",
            Self::Js => "javascript",
            Self::Python => "python",
            Self::Ruby => "ruby",
            Self::Shell => "shell",
            Self::Elixir => "elixir",
            Self::Erlang => "erlang",
            Self::Sql => "sql",
            Self::Json => "json",
            Self::Yaml => "yaml",
            Self::Toml => "toml",
            Self::Html => "html",
            Self::Css => "css",
            Self::Lua => "lua",
            Self::Haskell => "haskell",
            Self::Diff => "diff",
            Self::Plain => "text",
        }
    }
}

/// Maps a fence info string to a language.
pub fn detect(info: Option<&str>) -> Language {
    let Some(info) = info else {
        return Language::Plain;
    };

    match info.trim().to_ascii_lowercase().as_str() {
        "rust" | "rs" => Language::Rust,
        "c" | "h" => Language::C,
        "cpp" | "c++" | "cc" | "cxx" | "hpp" | "hh" => Language::Cpp,
        "java" | "kt" | "kotlin" | "swift" | "cs" | "c#" | "csharp" | "scala" | "dart"
        | "groovy" | "php" => Language::Java,
        "go" | "golang" => Language::Go,
        "js" | "jsx" | "javascript" | "mjs" | "cjs" | "ts" | "tsx" | "typescript" | "node" => {
            Language::Js
        }
        "python" | "py" | "python3" | "py3" | "ipython" => Language::Python,
        "ruby" | "rb" => Language::Ruby,
        "sh" | "bash" | "zsh" | "shell" | "shell-session" | "console" | "fish" | "ksh" => {
            Language::Shell
        }
        "elixir" | "ex" | "exs" | "heex" | "leex" => Language::Elixir,
        "erlang" | "erl" | "escript" => Language::Erlang,
        "sql" | "psql" | "mysql" | "postgres" | "postgresql" | "sqlite" => Language::Sql,
        "json" | "json5" | "jsonc" => Language::Json,
        "yaml" | "yml" => Language::Yaml,
        "toml" | "ini" | "cfg" | "conf" => Language::Toml,
        "html" | "xml" | "svg" | "xhtml" | "vue" | "svelte" => Language::Html,
        "css" | "scss" | "sass" | "less" => Language::Css,
        "lua" => Language::Lua,
        "haskell" | "hs" | "purs" | "elm" => Language::Haskell,
        "diff" | "patch" => Language::Diff,
        _ => Language::Plain,
    }
}

/// Token classes, mapped to colours once in [`token_style`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Text,
    Keyword,
    String,
    Comment,
    Number,
    Function,
    Type,
    Key,
}

fn token_style(token: Token) -> Style {
    match token {
        // The terminal's own palette, like the rest of this client: magenta keywords,
        // green strings, gray comments, yellow numbers, blue calls and keys, cyan types.
        Token::Text => Style::default(),
        Token::Keyword => Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
        Token::String => Style::default().fg(Color::Green),
        Token::Comment => Style::default()
            .fg(super::theme::MUTED)
            .add_modifier(Modifier::DIM | Modifier::ITALIC),
        Token::Number => Style::default().fg(Color::Yellow),
        Token::Function => Style::default().fg(Color::Blue),
        Token::Type => Style::default().fg(super::theme::SYSTEM),
        Token::Key => Style::default().fg(Color::Blue),
    }
}

/// Everything the tokenizer needs to know about one language.
struct Grammar {
    /// `//`, `#`, `--`, `%`. Starts a comment anywhere on a line.
    line_comment: Option<&'static str>,
    /// `/* */`, `<!-- -->`, `{- -}`. May span lines; openness carries across them.
    block_comment: Option<(&'static str, &'static str)>,
    /// `"""…"""` / `'''…'''` also open strings.
    triple_quotes: bool,
    keywords: &'static [&'static str],
    case_insensitive_keywords: bool,
    /// Words directly followed by `!(` are calls (Rust macros).
    bang_calls: bool,
    /// `:atoms` and `$variables` get their own colour.
    atoms: bool,
    dollar_vars: bool,
    /// Bare words followed by `:` or `=` are keys, not calls.
    keys: bool,
    /// `<tag` names are coloured.
    markup: bool,
}

impl Grammar {
    fn is_keyword(&self, word: &str) -> bool {
        if self.case_insensitive_keywords {
            self.keywords
                .iter()
                .any(|keyword| keyword.eq_ignore_ascii_case(word))
        } else {
            self.keywords.contains(&word)
        }
    }
}

const KEYWORDS_C: &[&str] = &[
    "abstract",
    "as",
    "async",
    "await",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "constexpr",
    "continue",
    "crate",
    "debugger",
    "default",
    "defer",
    "delete",
    "do",
    "double",
    "dyn",
    "else",
    "enum",
    "export",
    "extends",
    "extern",
    "false",
    "final",
    "finally",
    "float",
    "fn",
    "for",
    "foreach",
    "friend",
    "from",
    "func",
    "function",
    "go",
    "goto",
    "if",
    "impl",
    "implements",
    "import",
    "in",
    "inline",
    "instanceof",
    "int",
    "interface",
    "let",
    "long",
    "match",
    "mod",
    "module",
    "move",
    "mut",
    "namespace",
    "new",
    "null",
    "nullptr",
    "operator",
    "override",
    "package",
    "private",
    "protected",
    "pub",
    "public",
    "ref",
    "return",
    "self",
    "Self",
    "signed",
    "sizeof",
    "static",
    "struct",
    "super",
    "switch",
    "template",
    "this",
    "throw",
    "throws",
    "trait",
    "true",
    "try",
    "type",
    "typedef",
    "typeof",
    "union",
    "unsafe",
    "unsigned",
    "use",
    "using",
    "var",
    "virtual",
    "void",
    "volatile",
    "where",
    "while",
    "with",
    "yield",
];

const KEYWORDS_PYTHON: &[&str] = &[
    "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif",
    "else", "except", "False", "finally", "for", "from", "global", "if", "import", "in", "is",
    "lambda", "None", "nonlocal", "not", "or", "pass", "raise", "return", "True", "try", "while",
    "with", "yield", "self", "cls",
];

const KEYWORDS_RUBY: &[&str] = &[
    "BEGIN", "END", "alias", "and", "begin", "break", "case", "class", "def", "defined?", "do",
    "else", "elsif", "end", "ensure", "false", "for", "if", "in", "module", "next", "nil", "not",
    "or", "redo", "rescue", "retry", "return", "self", "super", "then", "true", "undef", "unless",
    "until", "when", "while", "yield",
];

const KEYWORDS_SHELL: &[&str] = &[
    "break", "case", "cd", "continue", "do", "done", "echo", "elif", "else", "esac", "exit",
    "export", "fi", "for", "function", "if", "in", "local", "read", "return", "set", "shift",
    "source", "then", "unset", "until", "while",
];

const KEYWORDS_ELIXIR: &[&str] = &[
    "after",
    "and",
    "case",
    "catch",
    "cond",
    "def",
    "defdelegate",
    "defexception",
    "defguard",
    "defimpl",
    "defmacro",
    "defmodule",
    "defoverridable",
    "defp",
    "defprotocol",
    "defstruct",
    "do",
    "else",
    "end",
    "false",
    "fn",
    "for",
    "if",
    "import",
    "in",
    "nil",
    "not",
    "or",
    "quote",
    "raise",
    "receive",
    "require",
    "rescue",
    "spawn",
    "spawn_link",
    "true",
    "try",
    "unless",
    "unquote",
    "unquote_splicing",
    "use",
    "when",
    "with",
];

const KEYWORDS_ERLANG: &[&str] = &[
    "after", "and", "andalso", "band", "begin", "bnot", "bor", "bsl", "bsr", "bxor", "case",
    "catch", "div", "end", "fun", "if", "let", "not", "of", "or", "orelse", "receive", "rem",
    "try", "when", "xor",
];

const KEYWORDS_SQL: &[&str] = &[
    "add",
    "all",
    "alter",
    "and",
    "any",
    "as",
    "asc",
    "begin",
    "between",
    "by",
    "case",
    "check",
    "column",
    "commit",
    "constraint",
    "create",
    "cross",
    "database",
    "default",
    "delete",
    "desc",
    "distinct",
    "drop",
    "else",
    "end",
    "exists",
    "foreign",
    "from",
    "full",
    "group",
    "having",
    "in",
    "index",
    "inner",
    "insert",
    "into",
    "is",
    "join",
    "key",
    "left",
    "like",
    "limit",
    "not",
    "null",
    "offset",
    "on",
    "or",
    "order",
    "outer",
    "primary",
    "references",
    "right",
    "rollback",
    "select",
    "set",
    "table",
    "then",
    "top",
    "transaction",
    "truncate",
    "union",
    "unique",
    "update",
    "values",
    "view",
    "when",
    "where",
    "with",
];

const KEYWORDS_LUA: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in",
    "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
];

const KEYWORDS_HASKELL: &[&str] = &[
    "case", "class", "data", "default", "deriving", "do", "else", "foreign", "if", "import", "in",
    "infix", "infixl", "infixr", "instance", "let", "module", "newtype", "of", "then", "type",
    "where",
];

fn grammar(lang: Language) -> Grammar {
    match lang {
        Language::Rust => Grammar {
            line_comment: Some("//"),
            block_comment: Some(("/*", "*/")),
            triple_quotes: false,
            keywords: KEYWORDS_C,
            case_insensitive_keywords: false,
            bang_calls: true,
            atoms: false,
            dollar_vars: false,
            keys: false,
            markup: false,
        },
        Language::C | Language::Cpp | Language::Java | Language::Go | Language::Js => Grammar {
            line_comment: Some("//"),
            block_comment: Some(("/*", "*/")),
            triple_quotes: false,
            keywords: KEYWORDS_C,
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: false,
            markup: false,
        },
        Language::Css => Grammar {
            line_comment: None,
            block_comment: Some(("/*", "*/")),
            triple_quotes: false,
            keywords: &[],
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: true,
            markup: false,
        },
        Language::Python => Grammar {
            line_comment: Some("#"),
            block_comment: None,
            triple_quotes: true,
            keywords: KEYWORDS_PYTHON,
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: false,
            markup: false,
        },
        Language::Ruby => Grammar {
            line_comment: Some("#"),
            block_comment: None,
            triple_quotes: false,
            keywords: KEYWORDS_RUBY,
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: true,
            dollar_vars: true,
            keys: false,
            markup: false,
        },
        Language::Shell => Grammar {
            line_comment: Some("#"),
            block_comment: None,
            triple_quotes: false,
            keywords: KEYWORDS_SHELL,
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: false,
            dollar_vars: true,
            keys: false,
            markup: false,
        },
        Language::Elixir => Grammar {
            line_comment: Some("#"),
            block_comment: None,
            triple_quotes: true,
            keywords: KEYWORDS_ELIXIR,
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: true,
            dollar_vars: false,
            keys: false,
            markup: false,
        },
        Language::Erlang => Grammar {
            line_comment: Some("%"),
            block_comment: None,
            triple_quotes: false,
            keywords: KEYWORDS_ERLANG,
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: true,
            dollar_vars: false,
            keys: false,
            markup: false,
        },
        Language::Sql => Grammar {
            line_comment: Some("--"),
            block_comment: Some(("/*", "*/")),
            triple_quotes: false,
            keywords: KEYWORDS_SQL,
            case_insensitive_keywords: true,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: false,
            markup: false,
        },
        Language::Json => Grammar {
            line_comment: None,
            block_comment: None,
            triple_quotes: false,
            keywords: &["true", "false", "null"],
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: true,
            markup: false,
        },
        Language::Yaml | Language::Toml => Grammar {
            line_comment: Some("#"),
            block_comment: None,
            triple_quotes: false,
            keywords: &["true", "false", "null", "yes", "no", "on", "off"],
            case_insensitive_keywords: true,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: true,
            markup: false,
        },
        Language::Html => Grammar {
            line_comment: None,
            block_comment: Some(("<!--", "-->")),
            triple_quotes: false,
            keywords: &[],
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: true,
            markup: true,
        },
        Language::Lua => Grammar {
            line_comment: Some("--"),
            block_comment: None,
            triple_quotes: false,
            keywords: KEYWORDS_LUA,
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: false,
            markup: false,
        },
        Language::Haskell => Grammar {
            line_comment: Some("--"),
            block_comment: Some(("{-", "-}")),
            triple_quotes: false,
            keywords: KEYWORDS_HASKELL,
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: false,
            markup: false,
        },
        Language::Diff | Language::Plain => Grammar {
            line_comment: None,
            block_comment: None,
            triple_quotes: false,
            keywords: &[],
            case_insensitive_keywords: false,
            bang_calls: false,
            atoms: false,
            dollar_vars: false,
            keys: false,
            markup: false,
        },
    }
}

/// State carried between lines of one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carry {
    Normal,
    BlockComment { closer: &'static str },
    String { quote: char, triple: bool },
}

/// Highlights a block into display lines, wrapping each source line to `width` cells
/// without disturbing its whitespace, and stopping before `max_lines` rows.
pub fn highlight(code: &str, lang: Language, width: usize, max_lines: usize) -> Vec<Line<'static>> {
    if lang == Language::Diff {
        return diff_lines(code, width, max_lines);
    }

    let grammar = grammar(lang);
    let mut carry = Carry::Normal;
    let mut lines: Vec<Line<'static>> = Vec::new();

    for source in code.lines() {
        if lines.len() >= max_lines {
            break;
        }

        let spans = highlight_line(source, &grammar, &mut carry);

        if spans.iter().all(|span| span.content.is_empty()) {
            lines.push(Line::from(String::new()));
            continue;
        }

        for row in wrap_spans(&spans, width.max(1)) {
            if lines.len() >= max_lines {
                return lines;
            }
            lines.push(Line::from(row));
        }
    }

    if lines.is_empty() && max_lines > 0 {
        lines.push(Line::from(String::new()));
    }

    lines
}

fn diff_lines(code: &str, width: usize, max_lines: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    for source in code.lines() {
        if lines.len() >= max_lines {
            break;
        }

        let style = if source.starts_with('+') && !source.starts_with("+++") {
            Style::default().fg(super::theme::GOOD)
        } else if source.starts_with('-') && !source.starts_with("---") {
            Style::default().fg(super::theme::BAD)
        } else if source.starts_with("@@") {
            Style::default().fg(super::theme::SYSTEM)
        } else {
            token_style(Token::Comment)
        };

        for row in wrap_spans(&[Span::styled(source.to_string(), style)], width.max(1)) {
            if lines.len() >= max_lines {
                return lines;
            }
            lines.push(Line::from(row));
        }
    }

    if lines.is_empty() && max_lines > 0 {
        lines.push(Line::from(String::new()));
    }

    lines
}

/// Tokenizes one line, updating cross-line state.
fn highlight_line(line: &str, grammar: &Grammar, carry: &mut Carry) -> Vec<Span<'static>> {
    let chars: Vec<char> = line.chars().collect();
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut plain = String::new();
    let mut index = 0;

    while index < chars.len() {
        match *carry {
            Carry::BlockComment { closer } => {
                let (next, closed) = consume_comment(chars.as_slice(), index, closer, &mut spans);
                index = next;
                if closed {
                    *carry = Carry::Normal;
                }
            }
            Carry::String { quote, triple } => {
                let (next, closed) =
                    continue_string(chars.as_slice(), index, quote, triple, &mut spans);
                index = next;
                if closed {
                    *carry = Carry::Normal;
                }
            }
            Carry::Normal => {
                if let Some(opener) = grammar.line_comment {
                    if starts_with(chars.as_slice(), index, opener) {
                        flush(&mut plain, &mut spans);
                        spans.push(Span::styled(
                            chars[index..].iter().collect::<String>(),
                            token_style(Token::Comment),
                        ));
                        break;
                    }
                }

                if let Some((opener, closer)) = grammar.block_comment {
                    if starts_with(chars.as_slice(), index, opener) {
                        flush(&mut plain, &mut spans);
                        spans.push(Span::styled(
                            opener.to_string(),
                            token_style(Token::Comment),
                        ));
                        *carry = Carry::BlockComment { closer };
                        index += opener.chars().count();
                        continue;
                    }
                }

                let character = chars[index];

                if matches!(character, '"' | '\'' | '`') {
                    let triple = grammar.triple_quotes
                        && chars.get(index + 1) == Some(&character)
                        && chars.get(index + 2) == Some(&character);
                    let delimiter = if triple { 3 } else { 1 };

                    // A quoted word followed by `:` is a key, not a string value.
                    if grammar.keys && character == '"' && !triple {
                        if let Some(close) =
                            find_string_end(chars.as_slice(), index + 1, '"', false)
                        {
                            let mut lookahead = close + 1;
                            while chars
                                .get(lookahead)
                                .is_some_and(|c: &char| c.is_whitespace())
                            {
                                lookahead += 1;
                            }
                            flush(&mut plain, &mut spans);
                            let token = if chars.get(lookahead) == Some(&':') {
                                Token::Key
                            } else {
                                Token::String
                            };
                            spans.push(Span::styled(
                                chars[index..=close].iter().collect::<String>(),
                                token_style(token),
                            ));
                            index = close + 1;
                            continue;
                        }
                    }

                    flush(&mut plain, &mut spans);
                    *carry = Carry::String {
                        quote: character,
                        triple,
                    };
                    let (next, closed) =
                        open_string(chars.as_slice(), index, character, delimiter, &mut spans);
                    index = next;
                    if closed {
                        *carry = Carry::Normal;
                    }
                    continue;
                }

                if grammar.markup && character == '<' {
                    flush(&mut plain, &mut spans);
                    if let Some(consumed) = consume_tag_name(chars.as_slice(), index, &mut spans) {
                        index = consumed;
                        continue;
                    }
                    plain.push('<');
                    index += 1;
                    continue;
                }

                if grammar.atoms
                    && character == ':'
                    && chars
                        .get(index + 1)
                        .is_some_and(|c| c.is_alphanumeric() || *c == '_')
                {
                    let end = ident_end(chars.as_slice(), index + 1);
                    flush(&mut plain, &mut spans);
                    spans.push(Span::styled(
                        chars[index..end].iter().collect::<String>(),
                        token_style(Token::Number),
                    ));
                    index = end;
                    continue;
                }

                if grammar.dollar_vars && character == '$' {
                    if let Some(next) = chars.get(index + 1) {
                        let braced = *next == '{';
                        if braced || next.is_alphanumeric() || *next == '_' {
                            let end = if braced {
                                chars[index + 2..]
                                    .iter()
                                    .position(|c| *c == '}')
                                    .map(|offset| index + 3 + offset)
                                    .unwrap_or(chars.len())
                            } else {
                                ident_end(chars.as_slice(), index + 1)
                            };
                            flush(&mut plain, &mut spans);
                            spans.push(Span::styled(
                                chars[index..end].iter().collect::<String>(),
                                token_style(Token::Type),
                            ));
                            index = end;
                            continue;
                        }
                    }
                }

                if character.is_ascii_digit()
                    || (character == '.'
                        && chars.get(index + 1).is_some_and(|c| c.is_ascii_digit()))
                {
                    let end = number_end(chars.as_slice(), index);
                    flush(&mut plain, &mut spans);
                    spans.push(Span::styled(
                        chars[index..end].iter().collect::<String>(),
                        token_style(Token::Number),
                    ));
                    index = end;
                    continue;
                }

                if is_ident_start(character) {
                    let end = ident_end(chars.as_slice(), index);
                    let word: String = chars[index..end].iter().collect();
                    let class = classify(chars.as_slice(), index, end, grammar);
                    flush(&mut plain, &mut spans);
                    spans.push(Span::styled(word, token_style(class)));
                    index = end;
                    continue;
                }

                plain.push(character);
                index += 1;
            }
        }
    }

    flush(&mut plain, &mut spans);
    spans
}

fn flush(plain: &mut String, spans: &mut Vec<Span<'static>>) {
    if !plain.is_empty() {
        spans.push(Span::raw(std::mem::take(plain)));
    }
}

fn classify(chars: &[char], start: usize, end: usize, grammar: &Grammar) -> Token {
    let word: String = chars[start..end].iter().collect();

    if grammar.is_keyword(&word) {
        return Token::Keyword;
    }

    let mut lookahead = end;
    while chars
        .get(lookahead)
        .is_some_and(|c| *c == ' ' || *c == '\t')
    {
        lookahead += 1;
    }

    if grammar.bang_calls && chars.get(end) == Some(&'!') {
        return Token::Function;
    }

    if grammar.keys && matches!(chars.get(lookahead), Some(':') | Some('=')) {
        // A URL scheme (`http://…`) is not a YAML key, even though a colon follows.
        if !(chars.get(lookahead) == Some(&':')
            && chars.get(lookahead + 1) == Some(&'/')
            && chars.get(lookahead + 2) == Some(&'/'))
        {
            return Token::Key;
        }
    }

    if chars.get(lookahead) == Some(&'(') {
        return Token::Function;
    }

    if word.chars().next().is_some_and(char::is_uppercase) {
        return Token::Type;
    }

    Token::Text
}

fn is_ident_start(character: char) -> bool {
    character.is_alphabetic() || character == '_' || character == '?' || character == '!'
}

fn ident_end(chars: &[char], start: usize) -> usize {
    let mut end = start;

    while end < chars.len() {
        let character = chars[end];
        if character.is_alphanumeric() || character == '_' || character == '?' || character == '!' {
            end += 1;
        } else {
            break;
        }
    }

    end
}

fn number_end(chars: &[char], start: usize) -> usize {
    let mut end = start;

    while end < chars.len() {
        let character = chars[end];
        if character.is_ascii_alphanumeric() || character == '.' || character == '_' {
            end += 1;
        } else {
            break;
        }
    }

    end
}

/// Consumes a tag name after `<` (or `</`), coloured as a call. Returns the new index,
/// or `None` when `<` did not begin a tag.
fn consume_tag_name(chars: &[char], start: usize, spans: &mut Vec<Span<'static>>) -> Option<usize> {
    let mut index = start + 1;
    let mut name = String::from("<");

    if chars.get(index) == Some(&'/') {
        name.push('/');
        index += 1;
    }

    let name_start = index;
    while index < chars.len()
        && (chars[index].is_alphanumeric() || matches!(chars[index], '-' | ':' | '_' | '.'))
    {
        index += 1;
    }

    if index == name_start {
        return None;
    }

    name.extend(chars[name_start..index].iter());
    spans.push(Span::styled(name, token_style(Token::Function)));
    Some(index)
}

/// Emits the opening delimiter and body of a string. Returns (next index, closed?).
fn open_string(
    chars: &[char],
    start: usize,
    quote: char,
    delimiter: usize,
    spans: &mut Vec<Span<'static>>,
) -> (usize, bool) {
    let body = start + delimiter;

    match find_string_end(chars, body, quote, delimiter == 3) {
        Some(close) => {
            spans.push(Span::styled(
                chars[start..=close].iter().collect::<String>(),
                token_style(Token::String),
            ));
            (close + 1, true)
        }
        None => {
            spans.push(Span::styled(
                chars[start..].iter().collect::<String>(),
                token_style(Token::String),
            ));
            (chars.len(), false)
        }
    }
}

/// Emits the remainder of a string opened on an earlier line.
fn continue_string(
    chars: &[char],
    start: usize,
    quote: char,
    triple: bool,
    spans: &mut Vec<Span<'static>>,
) -> (usize, bool) {
    match find_string_end(chars, start, quote, triple) {
        Some(close) => {
            spans.push(Span::styled(
                chars[start..=close].iter().collect::<String>(),
                token_style(Token::String),
            ));
            (close + 1, true)
        }
        None => {
            spans.push(Span::styled(
                chars[start..].iter().collect::<String>(),
                token_style(Token::String),
            ));
            (chars.len(), false)
        }
    }
}

/// Finds the inclusive index of a string's closing delimiter, if it closes here.
fn find_string_end(chars: &[char], mut index: usize, quote: char, triple: bool) -> Option<usize> {
    let mut escaped = false;

    while index < chars.len() {
        let character = chars[index];

        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == quote {
            if !triple {
                return Some(index);
            }
            if chars.get(index + 1) == Some(&quote) && chars.get(index + 2) == Some(&quote) {
                return Some(index + 2);
            }
        }

        index += 1;
    }

    None
}

/// Consumes up to and including `closer` when it appears on this line.
fn consume_comment(
    chars: &[char],
    start: usize,
    closer: &str,
    spans: &mut Vec<Span<'static>>,
) -> (usize, bool) {
    let mut index = start;

    while index < chars.len() {
        if starts_with(chars, index, closer) {
            let end = index + closer.chars().count();
            spans.push(Span::styled(
                chars[start..end].iter().collect::<String>(),
                token_style(Token::Comment),
            ));
            return (end, true);
        }

        index += 1;
    }

    spans.push(Span::styled(
        chars[start..].iter().collect::<String>(),
        token_style(Token::Comment),
    ));
    (chars.len(), false)
}

fn starts_with(chars: &[char], at: usize, pattern: &str) -> bool {
    pattern
        .chars()
        .enumerate()
        .all(|(offset, expected)| chars.get(at + offset) == Some(&expected))
}

/// Wraps styled spans to `width` cells, splitting spans when needed.
///
/// Nothing is normalized, unlike the prose wrapper: leading spaces are indentation, runs
/// of spaces are alignment, and both survive intact. A glyph wider than the whole pane
/// gets a row of its own rather than being dropped.
pub fn wrap_spans(spans: &[Span<'static>], width: usize) -> Vec<Vec<Span<'static>>> {
    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    let mut row: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;

    for span in spans {
        let mut pending = String::new();
        let mut pending_width = 0usize;

        for character in span.content.chars() {
            let cells = UnicodeWidthChar::width(character).unwrap_or(0);

            if cells > 0 && used + pending_width + cells > width {
                if !pending.is_empty() {
                    row.push(Span::styled(std::mem::take(&mut pending), span.style));
                }

                if row.iter().any(|part| !part.content.is_empty()) {
                    rows.push(std::mem::take(&mut row));
                }

                used = 0;
                pending_width = 0;
            }

            pending.push(character);
            pending_width += cells;
        }

        if !pending.is_empty() {
            row.push(Span::styled(pending, span.style));
            used += pending_width;
        }
    }

    if row.iter().any(|part| !part.content.is_empty()) || rows.is_empty() {
        rows.push(row);
    }

    rows
}

#[cfg(test)]
mod tests {
    use crate::ui::theme;
    use ratatui::style::{Color, Modifier};
    use unicode_width::UnicodeWidthStr;

    use super::*;

    fn text_of(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn styled<'a>(spans: &'a [Span<'a>], needle: &str) -> &'a Span<'a> {
        spans
            .iter()
            .find(|span| span.content.contains(needle))
            .expect("a matching span")
    }

    #[test]
    fn splits_prose_and_closed_blocks() {
        let segments = split_fences("before\n```rust\nfn main() {}\n```\nafter");

        assert_eq!(
            segments,
            vec![
                Segment::Prose("before\n"),
                Segment::Code(CodeBlock {
                    lang: Some("rust"),
                    code: "fn main() {}\n",
                    closed: true,
                }),
                Segment::Prose("after"),
            ]
        );
    }

    #[test]
    fn an_unterminated_fence_is_an_open_block_not_prose() {
        let segments = split_fences("look:\n```python\nprint('hi')\n");

        assert_eq!(
            segments,
            vec![
                Segment::Prose("look:\n"),
                Segment::Code(CodeBlock {
                    lang: Some("python"),
                    code: "print('hi')\n",
                    closed: false,
                }),
            ]
        );
    }

    #[test]
    fn inline_backticks_are_not_fences() {
        assert_eq!(
            split_fences("run `mix test` now"),
            vec![Segment::Prose("run `mix test` now")]
        );
    }

    #[test]
    fn indented_fences_still_open_blocks() {
        let segments = split_fences("text\n  ```js\nx()\n  ```");

        assert!(matches!(
            segments[1],
            Segment::Code(CodeBlock {
                lang: Some("js"),
                closed: true,
                ..
            })
        ));
    }

    #[test]
    fn fence_info_takes_the_first_word_only() {
        let segments = split_fences("```elixir mix format=true\nx\n```");

        assert_eq!(
            segments[0],
            Segment::Code(CodeBlock {
                lang: Some("elixir"),
                code: "x\n",
                closed: true,
            })
        );
    }

    #[test]
    fn tilde_fences_are_fences_too() {
        let segments = split_fences("~~~\nplain\n~~~");
        assert!(matches!(segments[0], Segment::Code(CodeBlock { .. })));
    }

    #[test]
    fn aliases_map_to_languages() {
        assert_eq!(detect(Some("rs")), Language::Rust);
        assert_eq!(detect(Some("golang")), Language::Go);
        assert_eq!(detect(Some("TS")), Language::Js);
        assert_eq!(detect(Some("zsh")), Language::Shell);
        assert_eq!(detect(Some("exs")), Language::Elixir);
        assert_eq!(detect(Some("yml")), Language::Yaml);
        assert_eq!(detect(None), Language::Plain);
        assert_eq!(detect(Some("cobol")), Language::Plain);
    }

    #[test]
    fn rust_code_gets_keyword_macro_and_comment_colours() {
        let lines = highlight(
            "// greet\nfn main() {\n    println!(\"hi\");\n}",
            Language::Rust,
            80,
            64,
        );

        let keyword = styled(&lines[1].spans, "fn");
        assert_eq!(keyword.style.fg, Some(Color::Magenta));
        assert!(keyword.style.add_modifier.contains(Modifier::BOLD));

        let call = styled(&lines[2].spans, "println!");
        assert_eq!(call.style.fg, Some(Color::Blue));

        let body = styled(&lines[2].spans, "\"hi\"");
        assert_eq!(body.style.fg, Some(Color::Green));

        let comment = styled(&lines[0].spans, "// greet");
        assert_eq!(comment.style.fg, Some(theme::MUTED));
    }

    #[test]
    fn elixir_module_atom_and_comment_colour_differently() {
        let lines = highlight(
            "# hi\ndefmodule Greeter do\n  def hello, do: :world\nend",
            Language::Elixir,
            80,
            64,
        );

        assert_eq!(
            styled(&lines[1].spans, "defmodule").style.fg,
            Some(Color::Magenta)
        );
        assert_eq!(
            styled(&lines[1].spans, "Greeter").style.fg,
            Some(theme::SYSTEM)
        );
        assert_eq!(
            styled(&lines[2].spans, ":world").style.fg,
            Some(Color::Yellow)
        );
        assert_eq!(styled(&lines[0].spans, "# hi").style.fg, Some(theme::MUTED));
    }

    #[test]
    fn python_triple_strings_survive_line_breaks() {
        let lines = highlight(
            "doc = \"\"\"first\nsecond\"\"\"\nx = 1",
            Language::Python,
            80,
            64,
        );

        assert_eq!(
            styled(&lines[0].spans, "\"\"\"first").style.fg,
            Some(Color::Green)
        );
        assert_eq!(
            styled(&lines[1].spans, "second\"\"\"").style.fg,
            Some(Color::Green)
        );
        assert_eq!(styled(&lines[2].spans, "x").style.fg, None);
    }

    #[test]
    fn c_block_comments_carry_across_lines() {
        let lines = highlight("/* one\ntwo */\nint x;", Language::C, 80, 64);

        assert_eq!(styled(&lines[0].spans, "/*").style.fg, Some(theme::MUTED));
        assert_eq!(styled(&lines[0].spans, "one").style.fg, Some(theme::MUTED));
        assert_eq!(
            styled(&lines[1].spans, "two */").style.fg,
            Some(theme::MUTED)
        );
        assert_eq!(
            styled(&lines[2].spans, "int").style.fg,
            Some(Color::Magenta)
        );
    }

    #[test]
    fn json_keys_numbers_and_literals_are_distinct() {
        let lines = highlight(
            "{\"name\": \"ouro\", \"count\": 3, \"ok\": true}",
            Language::Json,
            80,
            64,
        );

        assert_eq!(
            styled(&lines[0].spans, "\"name\"").style.fg,
            Some(Color::Blue)
        );
        assert_eq!(
            styled(&lines[0].spans, "\"ouro\"").style.fg,
            Some(Color::Green)
        );
        assert_eq!(styled(&lines[0].spans, "3").style.fg, Some(Color::Yellow));
        assert_eq!(
            styled(&lines[0].spans, "true").style.fg,
            Some(Color::Magenta)
        );
    }

    #[test]
    fn yaml_keys_exclude_url_schemes() {
        let lines = highlight(
            "name: ouro\nhome: http://example.com",
            Language::Yaml,
            80,
            64,
        );

        assert_eq!(styled(&lines[0].spans, "name").style.fg, Some(Color::Blue));
        assert_eq!(styled(&lines[1].spans, "home").style.fg, Some(Color::Blue));
        assert_eq!(styled(&lines[1].spans, "http").style.fg, None);
    }

    #[test]
    fn shell_variables_and_comments_colour() {
        let lines = highlight("# rebuild\nmake $TARGET", Language::Shell, 80, 64);

        assert_eq!(
            styled(&lines[0].spans, "# rebuild").style.fg,
            Some(theme::MUTED)
        );
        assert_eq!(
            styled(&lines[1].spans, "$TARGET").style.fg,
            Some(theme::SYSTEM)
        );
    }

    #[test]
    fn html_tags_and_attributes_colour() {
        let lines = highlight("<div class=\"box\">hi</div>", Language::Html, 80, 64);

        assert_eq!(styled(&lines[0].spans, "<div").style.fg, Some(Color::Blue));
        assert_eq!(styled(&lines[0].spans, "class").style.fg, Some(Color::Blue));
        assert_eq!(
            styled(&lines[0].spans, "\"box\"").style.fg,
            Some(Color::Green)
        );
        assert_eq!(styled(&lines[0].spans, "</div").style.fg, Some(Color::Blue));
    }

    #[test]
    fn sql_keywords_match_without_case() {
        let lines = highlight("select id from users;", Language::Sql, 80, 64);

        assert_eq!(
            styled(&lines[0].spans, "select").style.fg,
            Some(Color::Magenta)
        );
        assert_eq!(styled(&lines[0].spans, "users").style.fg, None);
    }

    #[test]
    fn diff_lines_take_add_remove_colours() {
        let lines = highlight("@@ -1 +1 @@\n-old\n+new", Language::Diff, 80, 64);

        assert_eq!(styled(&lines[1].spans, "-old").style.fg, Some(theme::BAD));
        assert_eq!(styled(&lines[2].spans, "+new").style.fg, Some(theme::GOOD));
    }

    #[test]
    fn unknown_languages_still_colour_strings_and_numbers() {
        let lines = highlight("value = \"x\" 42", Language::Plain, 80, 64);

        assert_eq!(
            styled(&lines[0].spans, "\"x\"").style.fg,
            Some(Color::Green)
        );
        assert_eq!(styled(&lines[0].spans, "42").style.fg, Some(Color::Yellow));
    }

    #[test]
    fn wrapping_preserves_indentation_exactly() {
        let lines = highlight("fn main() {\n    deep();\n}", Language::Rust, 80, 64);

        assert_eq!(text_of(&lines[1]), "    deep();");
    }

    #[test]
    fn long_code_lines_wrap_by_cells_keeping_style() {
        // Wrapping is lossless: a continuation row keeps the space it started with, so
        // concatenating the rows rebuilds the source exactly.
        let lines = highlight("alpha beta gamma delta", Language::Plain, 10, 64);
        let joined: String = lines.iter().map(|line| text_of(line)).collect();

        assert_eq!(joined, "alpha beta gamma delta");
        assert!(lines.iter().all(|line| line.width() <= 10));
        assert_eq!(styled(&lines[1].spans, "gamma").style.fg, None);
    }

    #[test]
    fn highlighting_stops_at_the_row_budget() {
        let lines = highlight("one\ntwo\nthree", Language::Plain, 40, 2);

        assert_eq!(lines.len(), 2);
        assert_eq!(text_of(&lines[0]), "one");
        assert_eq!(text_of(&lines[1]), "two");
    }

    #[test]
    fn a_wide_glyph_pair_fills_one_row_exactly() {
        let rows = wrap_spans(&[Span::raw("界界界")], 4);

        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|row| row.iter().map(|span| span.content.width()).sum::<usize>() <= 4));
    }

    #[test]
    fn empty_code_renders_one_blank_row() {
        let lines = highlight("", Language::Rust, 40, 64);

        assert_eq!(lines.len(), 1);
        assert_eq!(text_of(&lines[0]), "");
    }
}
