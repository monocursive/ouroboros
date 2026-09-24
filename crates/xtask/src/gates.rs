//! The acceptance map and the per-gate verdict (jail-v1 §15, §16; J5).
//!
//! §16's J5 exit is "all noncredential gates pass". Before this module the
//! gate-to-test map existed only in prose, so no run could say whether that
//! was true. `docs/specs/jail-v1/acceptance-map.toml` splits every §15 row
//! into its clauses and names, for each clause, the tests (or driver checks)
//! that assert it and how (`live-cli`, `live-lib`, `portable`, `simulated`,
//! `recorded-limit`, `credential`, `untested`). This module reads the map,
//! checks it against the §15 table of the spec at the same revision, parses
//! a `cargo test` log, and computes a verdict per clause and per gate. It is
//! pure: every input is a value, so every branch is unit-tested against real
//! logs.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

/// The map's own identifier.
pub const MAP_SCHEMA: &str = "ouro.jail.acceptance-map/1";
/// The verdict's identifier, in `gates.json`.
pub const VERDICT_SCHEMA: &str = "ouro.jail.gate-verdict/1";
/// Where the map lives, relative to the repository root.
pub const MAP_PATH: &str = "docs/specs/jail-v1/acceptance-map.toml";
/// Where the §15 table lives, relative to the repository root.
pub const SPEC_PATH: &str = "docs/specs/jail-v1.md";

/// How a clause is proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tag {
    LiveCli,
    LiveLib,
    Portable,
    Simulated,
    RecordedLimit,
    Credential,
    Untested,
}

/// Which test log evaluates a clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Lane {
    #[default]
    Linux,
    Macos,
}

/// A gate the suite proves, or the one that needs a real vendor agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Scripted,
    Credential,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub id: String,
    pub row: String,
    #[serde(default)]
    pub kind: Kind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Clause {
    pub id: String,
    pub gate: String,
    pub clause: String,
    pub tag: Tag,
    #[serde(default)]
    pub lane: Lane,
    #[serde(default)]
    pub tests: Vec<String>,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default)]
    pub limit: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ignored {
    pub test: String,
    pub reason: String,
    #[serde(default)]
    pub lane: Lane,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Map {
    pub schema: String,
    #[serde(default)]
    pub gate: Vec<Gate>,
    #[serde(default)]
    pub clause: Vec<Clause>,
    #[serde(default)]
    pub ignored: Vec<Ignored>,
}

/// The driver checks a clause may name.
pub const CHECKS: &[&str] = &[
    "i01_absent",
    "i01_scrubbed_path",
    "i02_scan",
    "contract_validation",
    "doctor_manifest",
    "plain_session_smoke",
    "suite_clean",
];

impl Map {
    /// Parse and validate. Every problem is reported, not only the first.
    pub fn parse(text: &str) -> Result<Map, String> {
        let map: Map = toml::from_str(text).map_err(|e| format!("the acceptance map: {e}"))?;
        let problems = map.problems();
        if problems.is_empty() {
            Ok(map)
        } else {
            Err(format!(
                "the acceptance map has {} problem(s):\n- {}",
                problems.len(),
                problems.join("\n- ")
            ))
        }
    }

    /// Everything wrong with the map on its own terms.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        if self.schema != MAP_SCHEMA {
            p.push(format!("schema is `{}`, not `{MAP_SCHEMA}`", self.schema));
        }
        let mut gates: BTreeMap<&str, Kind> = BTreeMap::new();
        for g in &self.gate {
            if gates.insert(g.id.as_str(), g.kind).is_some() {
                p.push(format!("gate {} has two [[gate]] tables", g.id));
            }
            if g.row.trim().is_empty() {
                p.push(format!("gate {} has an empty `row`", g.id));
            }
        }
        let ignored: BTreeSet<&str> = self.ignored.iter().map(|i| i.test.as_str()).collect();
        let mut clause_ids = BTreeSet::new();
        for c in &self.clause {
            if !clause_ids.insert(c.id.as_str()) {
                p.push(format!("clause id {} is used twice", c.id));
            }
            let well_named = c.id.split_once('.').is_some_and(|(g, n)| {
                g == c.gate && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
            });
            if !well_named {
                p.push(format!("clause id {} is not `{}.<n>`", c.id, c.gate));
            }
            match gates.get(c.gate.as_str()) {
                None => p.push(format!(
                    "clause {} names gate {}, which has no [[gate]]",
                    c.id, c.gate
                )),
                Some(kind) => {
                    if (c.tag == Tag::Credential) != (*kind == Kind::Credential) {
                        p.push(format!(
                            "{} is tagged {:?} but its gate {} is {:?}: credential clauses belong to credential gates, and only there",
                            c.id, c.tag, c.gate, kind
                        ).replace("Credential", "credential"));
                    }
                }
            }
            if c.clause.trim().is_empty() {
                p.push(format!("{} has an empty `clause`", c.id));
            }
            let has_limit = c.limit.as_deref().is_some_and(|l| !l.trim().is_empty());
            if c.tag == Tag::RecordedLimit && !has_limit {
                p.push(format!("{} is recorded-limit without a `limit`", c.id));
            }
            if c.tag != Tag::RecordedLimit && has_limit {
                p.push(format!("{} has a `limit` but is not recorded-limit", c.id));
            }
            let evidence = !c.tests.is_empty() || !c.checks.is_empty();
            if matches!(c.tag, Tag::Untested | Tag::Credential) && evidence {
                p.push(format!(
                    "{} is {} but lists evidence",
                    c.id,
                    if c.tag == Tag::Untested {
                        "untested"
                    } else {
                        "credential"
                    }
                ));
            }
            let mut seen = BTreeSet::new();
            for t in &c.tests {
                if !is_test_id(t) {
                    p.push(format!("{}: `{t}` is not a test id", c.id));
                }
                if !seen.insert(t.as_str()) {
                    p.push(format!("{}: `{t}` is listed twice", c.id));
                }
                if ignored.contains(t.as_str()) {
                    p.push(format!(
                        "{}: `{t}` is pinned as ignored and mapped as evidence",
                        c.id
                    ));
                }
            }
            for k in &c.checks {
                if !CHECKS.contains(&k.as_str()) {
                    p.push(format!(
                        "{}: `{k}` is not a driver check (one of {})",
                        c.id,
                        CHECKS.join(", ")
                    ));
                }
            }
        }
        for g in &self.gate {
            if !self.clause.iter().any(|c| c.gate == g.id) {
                p.push(format!("gate {} has no clause", g.id));
            }
        }
        let mut pinned = BTreeSet::new();
        for i in &self.ignored {
            if !is_test_id(&i.test) {
                p.push(format!("the ignored entry `{}` is not a test id", i.test));
            }
            if i.reason.trim().is_empty() {
                p.push(format!("the ignored test `{}` has no reason", i.test));
            }
            if !pinned.insert((i.lane, i.test.as_str())) {
                p.push(format!("the ignored test `{}` is pinned twice", i.test));
            }
        }
        p
    }
}

/// Is `id` a well-formed test id (`<crate>/<source>::<libtest name>`)?
#[must_use]
pub fn is_test_id(id: &str) -> bool {
    let Some((binary, name)) = id.split_once("::") else {
        return false;
    };
    let Some((krate, source)) = binary.split_once('/') else {
        return false;
    };
    let crate_ok = !krate.is_empty()
        && krate
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    let rs_file = |dir: &str| {
        source
            .strip_prefix(dir)
            .and_then(|f| f.strip_suffix(".rs"))
            .is_some_and(|stem| !stem.is_empty() && !stem.contains('/'))
    };
    let source_ok = source == "doc"
        || source == "src/lib.rs"
        || source == "src/main.rs"
        || rs_file("tests/")
        || rs_file("src/bin/");
    let name_ok = !name.is_empty()
        && !name.starts_with(' ')
        && !name.ends_with(' ')
        && (source == "doc" || !name.contains(char::is_whitespace));
    crate_ok && source_ok && name_ok
}

/// Is `id` a §15 gate id (`P01`, `A01`, ...)?
fn is_gate_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 3 && b[0].is_ascii_uppercase() && b[1].is_ascii_digit() && b[2].is_ascii_digit()
}

/// The §15 rows of the spec, `(id, row text)`, in order.
pub fn spec_rows(spec: &str) -> Result<Vec<(String, String)>, String> {
    let mut lines = spec.lines();
    if !lines.any(|l| l.starts_with("## 15. ")) {
        return Err(format!("{SPEC_PATH} has no `## 15.` section"));
    }
    let mut rows: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.starts_with("## ") {
            break;
        }
        let Some(rest) = line.strip_prefix("| ") else {
            continue;
        };
        let Some((id, text)) = rest.split_once(" | ") else {
            continue;
        };
        if !is_gate_id(id) {
            continue;
        }
        let Some(text) = text.strip_suffix(" |") else {
            return Err(format!("§15 row {id} does not end with ` |`"));
        };
        if rows.iter().any(|(seen, _)| seen == id) {
            return Err(format!("§15 lists {id} twice"));
        }
        rows.push((id.to_string(), text.to_string()));
    }
    if rows.is_empty() {
        return Err(format!("{SPEC_PATH} §15 has no gate rows"));
    }
    Ok(rows)
}

/// Where the map and §15 disagree.
#[must_use]
pub fn spec_problems(map: &Map, rows: &[(String, String)]) -> Vec<String> {
    let mut p = Vec::new();
    for (id, text) in rows {
        match map.gate.iter().find(|g| &g.id == id) {
            None => p.push(format!("§15 {id} has no [[gate]] in the acceptance map")),
            Some(g) if &g.row != text => p.push(format!(
                "the map's row for {id} differs from §15: re-review its clauses against the new text and copy it"
            )),
            Some(_) => {}
        }
    }
    for g in &map.gate {
        if !rows.iter().any(|(id, _)| id == &g.id) {
            p.push(format!("map gate {} is not a §15 row", g.id));
        }
    }
    p
}

// ------------------------------------------------------------------ the log

/// One test's reported result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Failed,
    Ignored,
}

impl Outcome {
    /// The result libtest printed after ` ... `, if that is what `text` is.
    fn read(text: &str) -> Option<Outcome> {
        let text = text.trim();
        if text == "ok" {
            Some(Outcome::Ok)
        } else if text == "FAILED" {
            Some(Outcome::Failed)
        } else if text == "ignored" || text.starts_with("ignored, ") {
            Some(Outcome::Ignored)
        } else {
            None
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Failed => "FAILED",
            Outcome::Ignored => "ignored",
        }
    }
}

/// Something in the log the parser could not attribute with certainty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// The test it concerns, when it concerns one.
    pub test: Option<String>,
    pub text: String,
}

/// A parsed `cargo test` log.
#[derive(Debug, Default, Clone)]
pub struct TestLog {
    /// Test id to every result the log reports for it, in order.
    pub results: BTreeMap<String, Vec<Outcome>>,
    pub anomalies: Vec<Anomaly>,
    /// `test result: FAILED` lines.
    pub failed_binaries: usize,
    /// `test result:` lines of any kind.
    pub summaries: usize,
    /// `skipped:` lines (a live test that did not run).
    pub skips: Vec<String>,
}

/// The test binary the log is in.
struct Binary {
    prefix: String,
    /// Results attributed to it, for the count check.
    attributed: usize,
    /// `passed + failed + ignored` from its last `test result:` line.
    counted: Option<usize>,
}

/// `(source, artifact stem)` of a `Running <source> (<artifact>)` line.
fn running(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim().strip_prefix("Running ")?;
    let rest = rest.strip_prefix("unittests ").unwrap_or(rest);
    let (source, artifact) = rest.split_once(" (")?;
    let artifact = artifact.strip_suffix(')')?;
    let file = artifact.rsplit('/').next()?;
    // `<stem>-<16 hex>`; on a platform with an extension, drop it first.
    let file = file.split_once('.').map_or(file, |(f, _)| f);
    let (stem, hash) = file.rsplit_once('-')?;
    if hash.is_empty() || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((source, stem))
}

/// `passed + failed + ignored` of a `test result:` line.
fn counted(line: &str) -> Option<usize> {
    let mut total = 0;
    for part in line.split([';', '.']) {
        let part = part.trim();
        for word in ["passed", "failed", "ignored"] {
            if let Some(n) = part.strip_suffix(word) {
                total += n.trim().parse::<usize>().ok()?;
            }
        }
    }
    Some(total)
}

/// A libtest name as the map spells it: ` - should panic` and a doc-test's
/// ` (line N)` are dropped, so neither a flag nor an edit above a doc-test
/// changes a test's id.
fn normalise(name: &str) -> String {
    let name = name.strip_suffix(" - should panic").unwrap_or(name);
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(at) = rest.find(" (line ") {
        let after = &rest[at + " (line ".len()..];
        match after.find(')') {
            Some(close) if after[..close].bytes().all(|b| b.is_ascii_digit()) && close > 0 => {
                out.push_str(&rest[..at]);
                rest = &after[close + 1..];
            }
            _ => break,
        }
    }
    out.push_str(rest);
    out
}

/// Parse a `cargo test` log (see the module doc and the format document).
///
/// The suite runs with one test thread, so libtest prints `test <name> ... `
/// and then that test's result before the next test starts. Output a test's
/// subprocesses write lands between the two; the result is then the next line
/// that is exactly a result. A `test <other> ... <result>` line while a test
/// is pending is a nested process's own libtest output, never a result of
/// this binary, and is reported rather than attributed.
#[must_use]
pub fn parse_log(text: &str) -> TestLog {
    let mut log = TestLog::default();
    let mut package: Option<String> = None;
    let mut binary: Option<Binary> = None;
    let mut pending: Option<String> = None;

    fn finish(log: &mut TestLog, binary: Option<Binary>, pending: &mut Option<String>) {
        if let Some(test) = pending.take() {
            log.anomalies.push(Anomaly {
                text: format!("`{test}` started but no result was printed for it"),
                test: Some(test),
            });
        }
        if let Some(b) = binary {
            match b.counted {
                None => log.anomalies.push(Anomaly {
                    test: None,
                    text: format!("{} has no `test result:` line (a truncated log?)", b.prefix),
                }),
                Some(n) if n != b.attributed => log.anomalies.push(Anomaly {
                    test: None,
                    text: format!(
                        "{}: libtest counted {n} result(s), the log attributes {}",
                        b.prefix, b.attributed
                    ),
                }),
                Some(_) => {}
            }
        }
    }

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((source, stem)) = running(line) {
            finish(&mut log, binary.take(), &mut pending);
            if source == "src/lib.rs" || source == "src/main.rs" {
                package = Some(stem.replace('_', "-"));
            }
            let krate = package.clone().unwrap_or_else(|| "?".to_string());
            binary = Some(Binary {
                prefix: format!("{krate}/{source}"),
                attributed: 0,
                counted: None,
            });
            continue;
        }
        if let Some(krate) = trimmed.strip_prefix("Doc-tests ") {
            finish(&mut log, binary.take(), &mut pending);
            binary = Some(Binary {
                prefix: format!("{}/doc", krate.replace('_', "-")),
                attributed: 0,
                counted: None,
            });
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("test result: ") {
            log.summaries += 1;
            if rest.starts_with("FAILED") {
                log.failed_binaries += 1;
            }
            if let Some(test) = pending.take() {
                log.anomalies.push(Anomaly {
                    text: format!("`{test}` started but its binary ended without a result for it"),
                    test: Some(test),
                });
            }
            if let Some(b) = binary.as_mut() {
                // The last one wins: a nested process may print its own first.
                b.counted = counted(rest);
            }
            continue;
        }
        if trimmed.starts_with("skipped:") {
            log.skips.push(trimmed.to_string());
            continue;
        }
        let prefix = binary.as_ref().map(|b| b.prefix.clone());
        if let Some(rest) = line.strip_prefix("test ")
            && let Some((name, result)) = rest.split_once(" ... ")
        {
            let Some(prefix) = prefix else {
                log.anomalies.push(Anomaly {
                    test: None,
                    text: format!("a result outside any test binary: {trimmed}"),
                });
                continue;
            };
            let id = format!("{prefix}::{}", normalise(name));
            if let Some(waiting) = &pending {
                log.anomalies.push(Anomaly {
                    test: Some(id.clone()),
                    text: format!(
                        "`{id}` reported while `{waiting}` was running: a nested process's line, not attributed"
                    ),
                });
                continue;
            }
            match Outcome::read(result) {
                Some(outcome) => {
                    log.results.entry(id).or_default().push(outcome);
                    if let Some(b) = binary.as_mut() {
                        b.attributed += 1;
                    }
                }
                None => pending = Some(id),
            }
            continue;
        }
        if let Some(test) = &pending
            && let Some(outcome) = Outcome::read(trimmed)
        {
            log.results.entry(test.clone()).or_default().push(outcome);
            pending = None;
            if let Some(b) = binary.as_mut() {
                b.attributed += 1;
            }
        }
    }
    finish(&mut log, binary.take(), &mut pending);
    log
}

impl TestLog {
    /// Every test the log reports `ignored` (and nothing else).
    #[must_use]
    pub fn ignored(&self) -> BTreeSet<String> {
        self.results
            .iter()
            .filter(|(_, v)| v.as_slice() == [Outcome::Ignored])
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Results exist, no binary failed, no test failed, nothing skipped.
    #[must_use]
    pub fn clean(&self) -> bool {
        self.summaries > 0
            && !self.results.is_empty()
            && self.failed_binaries == 0
            && self.skips.is_empty()
            && !self.results.values().any(|v| v.contains(&Outcome::Failed))
    }

    /// The anomalies that concern `test`.
    fn anomalies_of<'a>(&'a self, test: &'a str) -> impl Iterator<Item = &'a Anomaly> + 'a {
        self.anomalies
            .iter()
            .filter(move |a| a.test.as_deref() == Some(test))
    }
}

// -------------------------------------------------------------- the verdict

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClauseStatus {
    Pass,
    Limit,
    Credential,
    Elsewhere,
    Fail,
}

impl ClauseStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ClauseStatus::Pass => "pass",
            ClauseStatus::Limit => "limit",
            ClauseStatus::Credential => "credential",
            ClauseStatus::Elsewhere => "elsewhere",
            ClauseStatus::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClauseVerdict {
    pub id: String,
    pub tag: Tag,
    pub lane: Lane,
    pub status: ClauseStatus,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    Pass,
    PassWithLimits,
    Elsewhere,
    Credential,
    Fail,
}

impl GateStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GateStatus::Pass => "pass",
            GateStatus::PassWithLimits => "pass+limits",
            GateStatus::Elsewhere => "elsewhere",
            GateStatus::Credential => "credential",
            GateStatus::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GateVerdict {
    pub id: String,
    pub status: GateStatus,
    pub clauses: Vec<ClauseVerdict>,
    /// Why the gate fails when no clause says so (it has none).
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub lanes: Vec<Lane>,
    pub gates: Vec<GateVerdict>,
    /// Failures that are not one gate's: the map, the spec, the ignored set,
    /// an unattributable result of a mapped test.
    pub problems: Vec<String>,
    /// Reported, not failures: anomalies that touch no mapped or pinned test.
    pub warnings: Vec<String>,
}

impl Tag {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Tag::LiveCli => "live-cli",
            Tag::LiveLib => "live-lib",
            Tag::Portable => "portable",
            Tag::Simulated => "simulated",
            Tag::RecordedLimit => "recorded-limit",
            Tag::Credential => "credential",
            Tag::Untested => "untested",
        }
    }
}

impl Lane {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Lane::Linux => "linux",
            Lane::Macos => "macos",
        }
    }

    /// `linux` or `macos`.
    pub fn parse(text: &str) -> Option<Lane> {
        match text {
            "linux" => Some(Lane::Linux),
            "macos" => Some(Lane::Macos),
            _ => None,
        }
    }
}

fn clause_verdict(
    c: &Clause,
    logs: &BTreeMap<Lane, TestLog>,
    checks: &BTreeMap<String, bool>,
) -> ClauseVerdict {
    let mut reasons = Vec::new();
    let status = if c.tag == Tag::Credential {
        ClauseStatus::Credential
    } else if let Some(log) = logs.get(&c.lane) {
        let lane = c.lane.as_str();
        for t in &c.tests {
            match log.results.get(t).map(Vec::as_slice) {
                None => reasons.push(format!("`{t}` is absent from the {lane} log")),
                Some([Outcome::Ok]) => {}
                Some([one]) => reasons.push(format!(
                    "`{t}` {}",
                    match one {
                        Outcome::Failed => "FAILED",
                        _ => "was ignored",
                    }
                )),
                Some(many) => reasons.push(format!(
                    "`{t}` is reported {} times ({})",
                    many.len(),
                    many.iter()
                        .map(|o| o.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            }
            for a in log.anomalies_of(t) {
                reasons.push(a.text.clone());
            }
        }
        for k in &c.checks {
            let passed = if k == "suite_clean" {
                Some(log.clean())
            } else {
                checks.get(k).copied()
            };
            match passed {
                Some(true) => {}
                Some(false) => reasons.push(format!("check `{k}` failed")),
                None => reasons.push(format!("check `{k}` was not produced by this run")),
            }
        }
        if c.tests.is_empty() && c.checks.is_empty() && c.tag != Tag::RecordedLimit {
            reasons.push(if c.tag == Tag::Untested {
                "untested: no test asserts this clause yet".to_string()
            } else {
                "no test or check asserts this clause".to_string()
            });
        }
        if !reasons.is_empty() {
            ClauseStatus::Fail
        } else if c.tag == Tag::RecordedLimit {
            ClauseStatus::Limit
        } else {
            ClauseStatus::Pass
        }
    } else {
        ClauseStatus::Elsewhere
    };
    ClauseVerdict {
        id: c.id.clone(),
        tag: c.tag,
        lane: c.lane,
        status,
        reasons,
    }
}

/// Compute the verdict. `checks` holds the driver checks this run produced
/// (`true` = passed); `suite_clean` is computed from each lane's log.
#[must_use]
pub fn evaluate(
    map: &Map,
    rows: &[(String, String)],
    logs: &BTreeMap<Lane, TestLog>,
    checks: &BTreeMap<String, bool>,
) -> Verdict {
    let mut v = Verdict {
        lanes: logs.keys().copied().collect(),
        ..Verdict::default()
    };
    v.problems.extend(map.problems());
    v.problems.extend(spec_problems(map, rows));

    for (id, _) in rows {
        let clauses: Vec<ClauseVerdict> = map
            .clause
            .iter()
            .filter(|c| &c.gate == id)
            .map(|c| clause_verdict(c, logs, checks))
            .collect();
        let kind = map.gate.iter().find(|g| &g.id == id).map(|g| g.kind);
        let mut reasons = Vec::new();
        if kind.is_none() {
            reasons.push("the acceptance map has no [[gate]] for it".to_string());
        }
        if clauses.is_empty() {
            reasons.push("the acceptance map has no clause for it".to_string());
        }
        let any = |s: ClauseStatus| clauses.iter().any(|c| c.status == s);
        let status = if !reasons.is_empty() || any(ClauseStatus::Fail) {
            GateStatus::Fail
        } else if kind == Some(Kind::Credential) {
            GateStatus::Credential
        } else if any(ClauseStatus::Elsewhere) {
            GateStatus::Elsewhere
        } else if any(ClauseStatus::Limit) {
            GateStatus::PassWithLimits
        } else {
            GateStatus::Pass
        };
        v.gates.push(GateVerdict {
            id: id.clone(),
            status,
            clauses,
            reasons,
        });
    }

    // The ignored set, pinned exactly, per evaluated lane.
    for (lane, log) in logs {
        let expected: BTreeSet<&str> = map
            .ignored
            .iter()
            .filter(|i| i.lane == *lane)
            .map(|i| i.test.as_str())
            .collect();
        let found = log.ignored();
        for t in &found {
            if !expected.contains(t.as_str()) {
                v.problems.push(format!(
                    "`{t}` is ignored in the {} log but not pinned in the acceptance map: an #[ignore] on a gate test would pass silently",
                    lane.as_str()
                ));
            }
        }
        for t in &expected {
            if !found.contains(*t) {
                let now = match log.results.get(*t).map(Vec::as_slice) {
                    None => "is absent from the log".to_string(),
                    Some(results) => format!(
                        "reports {}",
                        results
                            .iter()
                            .map(|o| o.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                };
                v.problems.push(format!(
                    "`{t}` is pinned as ignored but the {} log {now}: update the pin",
                    lane.as_str()
                ));
            }
        }
        // Anomalies: a failure when they touch a pinned test (mapped tests
        // already fail their clause), otherwise a warning.
        for a in &log.anomalies {
            match &a.test {
                Some(t) if expected.contains(t.as_str()) => v.problems.push(a.text.clone()),
                Some(t)
                    if map
                        .clause
                        .iter()
                        .any(|c| c.lane == *lane && c.tests.contains(t)) => {}
                _ => v.warnings.push(a.text.clone()),
            }
        }
    }
    v
}

impl Verdict {
    /// One line per failing gate plus every problem. Empty means every gate
    /// in the evaluated lanes passed (with recorded limits at most).
    #[must_use]
    pub fn failures(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .problems
            .iter()
            .map(|p| format!("acceptance: {p}"))
            .collect();
        for g in self.gates.iter().filter(|g| g.status == GateStatus::Fail) {
            let mut why: Vec<String> = g.reasons.clone();
            for c in g.clauses.iter().filter(|c| c.status == ClauseStatus::Fail) {
                why.push(format!("{}: {}", c.id, c.reasons.join("; ")));
            }
            out.push(format!("gate {} fails: {}", g.id, why.join(" | ")));
        }
        out
    }

    /// How many gates have each status.
    #[must_use]
    pub fn counts(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for g in &self.gates {
            *m.entry(g.status.as_str()).or_insert(0) += 1;
        }
        m
    }

    /// True when every noncredential gate passed in the evaluated lanes and
    /// none was left to another lane: the §16 J5 exit, for these logs.
    #[must_use]
    pub fn all_noncredential_gates_pass(&self) -> bool {
        self.failures().is_empty()
            && self.gates.iter().all(|g| {
                matches!(
                    g.status,
                    GateStatus::Pass | GateStatus::PassWithLimits | GateStatus::Credential
                )
            })
    }

    /// The table `evidence/gates.txt` holds.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let lanes: Vec<&str> = self.lanes.iter().map(|l| l.as_str()).collect();
        let _ = writeln!(
            s,
            "{VERDICT_SCHEMA}: acceptance verdict over the {} log(s), map {MAP_PATH}",
            lanes.join(" and ")
        );
        let _ = writeln!(s);
        let _ = writeln!(s, "{:<5} {:<12} {:<9} detail", "gate", "status", "clauses");
        for g in &self.gates {
            let passed = g
                .clauses
                .iter()
                .filter(|c| matches!(c.status, ClauseStatus::Pass | ClauseStatus::Limit))
                .count();
            let mut detail: Vec<String> = g.reasons.clone();
            for c in &g.clauses {
                match c.status {
                    ClauseStatus::Fail => {
                        detail.push(format!(
                            "{} [{}]: {}",
                            c.id,
                            c.tag.as_str(),
                            c.reasons.join("; ")
                        ));
                    }
                    ClauseStatus::Limit => detail.push(format!("{} recorded limit", c.id)),
                    ClauseStatus::Elsewhere => {
                        detail.push(format!("{} in the {} lane", c.id, c.lane.as_str()));
                    }
                    ClauseStatus::Credential => detail.push(format!("{} needs a real agent", c.id)),
                    ClauseStatus::Pass => {}
                }
            }
            let _ = writeln!(
                s,
                "{:<5} {:<12} {:<9} {}",
                g.id,
                g.status.as_str(),
                format!("{passed}/{}", g.clauses.len()),
                detail.join(" | ")
            );
        }
        let _ = writeln!(s);
        let counts = self.counts();
        let _ = writeln!(
            s,
            "gates: {}",
            counts
                .iter()
                .map(|(k, n)| format!("{n} {k}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for p in &self.problems {
            let _ = writeln!(s, "problem: {p}");
        }
        for w in &self.warnings {
            let _ = writeln!(s, "warning: {w}");
        }
        let _ = writeln!(
            s,
            "every noncredential gate passes in these lanes: {}",
            if self.all_noncredential_gates_pass() {
                "yes"
            } else {
                "no"
            }
        );
        s
    }

    /// The same, as `gates.json`.
    #[must_use]
    pub fn to_json(&self, map: &Map) -> serde_json::Value {
        let gates: Vec<serde_json::Value> = self
            .gates
            .iter()
            .map(|g| {
                let clauses: Vec<serde_json::Value> = g
                    .clauses
                    .iter()
                    .map(|c| {
                        let mapped = map.clause.iter().find(|m| m.id == c.id);
                        serde_json::json!({
                            "id": c.id,
                            "clause": mapped.map(|m| m.clause.as_str()),
                            "tag": c.tag.as_str(),
                            "lane": c.lane.as_str(),
                            "status": c.status.as_str(),
                            "tests": mapped.map(|m| m.tests.as_slice()).unwrap_or_default(),
                            "checks": mapped.map(|m| m.checks.as_slice()).unwrap_or_default(),
                            "limit": mapped.and_then(|m| m.limit.as_deref()),
                            "note": mapped.and_then(|m| m.note.as_deref()),
                            "reasons": c.reasons,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "id": g.id,
                    "status": g.status.as_str(),
                    "reasons": g.reasons,
                    "clauses": clauses,
                })
            })
            .collect();
        serde_json::json!({
            "schema": VERDICT_SCHEMA,
            "map_schema": map.schema,
            "lanes": self.lanes.iter().map(|l| l.as_str()).collect::<Vec<_>>(),
            "all_noncredential_gates_pass": self.all_noncredential_gates_pass(),
            "counts": self.counts(),
            "gates": gates,
            "problems": self.problems,
            "warnings": self.warnings,
        })
    }
}

// ------------------------------------------------------ loading and the CLI

/// The map and the §15 rows it is checked against, loaded together.
#[derive(Debug, Clone)]
pub struct Acceptance {
    pub map: Map,
    pub rows: Vec<(String, String)>,
}

/// Load the map and the spec from a repository root.
pub fn load(root: &std::path::Path) -> Result<Acceptance, String> {
    load_from(&root.join(MAP_PATH), &root.join(SPEC_PATH))
}

/// Load the map and the spec from explicit paths.
pub fn load_from(map: &std::path::Path, spec: &std::path::Path) -> Result<Acceptance, String> {
    let map_text =
        std::fs::read_to_string(map).map_err(|e| format!("cannot read {}: {e}", map.display()))?;
    let spec_text = std::fs::read_to_string(spec)
        .map_err(|e| format!("cannot read {}: {e}", spec.display()))?;
    Ok(Acceptance {
        map: Map::parse(&map_text)?,
        rows: spec_rows(&spec_text)?,
    })
}

/// `cargo xtask gates`: the verdict over saved logs.
#[derive(Debug, clap::Args)]
pub struct GatesArgs {
    /// A test log and its lane, `linux=<file>` or `macos=<file>`; repeat
    /// for both lanes.
    #[arg(long = "log", value_name = "LANE=FILE", required = true)]
    pub logs: Vec<String>,
    /// A driver check that passed (`name`) or failed (`name=fail`), as the
    /// run's `gates.json` or summary recorded it.
    #[arg(long = "check", value_name = "NAME[=pass|fail]")]
    pub checks: Vec<String>,
    /// The acceptance map; defaults to the repository's.
    #[arg(long, value_name = "PATH")]
    pub map: Option<std::path::PathBuf>,
    /// The spec whose §15 the map is checked against; defaults to the
    /// repository's.
    #[arg(long, value_name = "PATH")]
    pub spec: Option<std::path::PathBuf>,
    /// Also write the verdict as JSON here.
    #[arg(long, value_name = "PATH")]
    pub json: Option<std::path::PathBuf>,
}

/// Parse `--check` values.
pub fn parse_checks(values: &[String]) -> Result<BTreeMap<String, bool>, String> {
    let mut out = BTreeMap::new();
    for v in values {
        let (name, passed) = match v.split_once('=') {
            None => (v.as_str(), true),
            Some((n, "pass")) => (n, true),
            Some((n, "fail")) => (n, false),
            Some((_, other)) => return Err(format!("--check {v}: `{other}` is not pass or fail")),
        };
        if !CHECKS.contains(&name) || name == "suite_clean" {
            return Err(format!(
                "--check {name}: not a driver check (suite_clean comes from the log)"
            ));
        }
        out.insert(name.to_string(), passed);
    }
    Ok(out)
}

/// Run `cargo xtask gates`. Exit 0 when nothing fails.
pub fn run_cli(args: &GatesArgs, root: &std::path::Path) -> std::process::ExitCode {
    let fail = |msg: String| {
        eprintln!("xtask gates: {msg}");
        std::process::ExitCode::FAILURE
    };
    let acceptance = match load_from(
        &args.map.clone().unwrap_or_else(|| root.join(MAP_PATH)),
        &args.spec.clone().unwrap_or_else(|| root.join(SPEC_PATH)),
    ) {
        Ok(a) => a,
        Err(e) => return fail(e),
    };
    let mut logs = BTreeMap::new();
    for spec in &args.logs {
        let Some((lane, file)) = spec.split_once('=') else {
            return fail(format!("--log {spec}: expected LANE=FILE"));
        };
        let Some(lane) = Lane::parse(lane) else {
            return fail(format!("--log {spec}: the lane is linux or macos"));
        };
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) => return fail(format!("cannot read {file}: {e}")),
        };
        if logs.insert(lane, parse_log(&text)).is_some() {
            return fail(format!("--log names the {} lane twice", lane.as_str()));
        }
    }
    let checks = match parse_checks(&args.checks) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let verdict = evaluate(&acceptance.map, &acceptance.rows, &logs, &checks);
    print!("{}", verdict.render());
    if let Some(path) = &args.json {
        let body =
            serde_json::to_string_pretty(&verdict.to_json(&acceptance.map)).unwrap_or_default();
        if let Err(e) = std::fs::write(path, body + "\n") {
            return fail(format!("cannot write {}: {e}", path.display()));
        }
    }
    let failures = verdict.failures();
    if failures.is_empty() {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("xtask gates: {} failure(s)", failures.len());
        for f in &failures {
            eprintln!("  - {f}");
        }
        std::process::ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The J4 evidence run (`8baec7d6`, 1299 passed, 0 failed, 13 ignored).
    const J4_LOG: &str =
        include_str!("../../../docs/specs/jail-v1/evidence/j4-test-log-2026-09-23-ouro-ci.txt");
    /// The checked-in map and spec at this revision.
    const MAP: &str = include_str!("../../../docs/specs/jail-v1/acceptance-map.toml");
    const SPEC: &str = include_str!("../../../docs/specs/jail-v1.md");

    fn linux(log: &str) -> BTreeMap<Lane, TestLog> {
        BTreeMap::from([(Lane::Linux, parse_log(log))])
    }

    fn no_checks() -> BTreeMap<String, bool> {
        BTreeMap::new()
    }

    /// A two-gate spec and a map over it, small enough to read.
    const MINI_SPEC: &str = "\
# spec

## 15. Acceptance matrix

| ID | Test and required result |
|---|---|
| X01 | Spaces reach the fixture literally. |
| A01 | A real batch agent run records a receipt. |

## 16. Next
";

    const MINI_MAP: &str = r#"
schema = "ouro.jail.acceptance-map/1"

[[gate]]
id = "X01"
row = "Spaces reach the fixture literally."

[[gate]]
id = "A01"
row = "A real batch agent run records a receipt."
kind = "credential"

[[clause]]
id = "X01.1"
gate = "X01"
clause = "spaces reach the fixture"
tag = "live-cli"
tests = ["ouro-jail/tests/conformance_j1.rs::x01_literal_argv"]

[[clause]]
id = "A01.1"
gate = "A01"
clause = "a real agent run"
tag = "credential"

[[ignored]]
test = "ouro-jail/tests/conformance_j2.rs::startup_supervisor_helper"
reason = "helper"
"#;

    const MINI_LOG: &str = "\
     Running unittests src/lib.rs (target/release/deps/ouro_jail-1d54b8c75e2e48d1)

running 1 test
test records::tests::a ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/conformance_j1.rs (target/release/deps/conformance_j1-004409195d769e4e)

running 1 test
test x01_literal_argv ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running tests/conformance_j2.rs (target/release/deps/conformance_j2-9b954a28584077d9)

running 1 test
test startup_supervisor_helper ... ignored, helper

test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s
";

    fn mini() -> (Map, Vec<(String, String)>) {
        (
            Map::parse(MINI_MAP).expect("the mini map parses"),
            spec_rows(MINI_SPEC).expect("the mini spec has rows"),
        )
    }

    fn gate<'a>(v: &'a Verdict, id: &str) -> &'a GateVerdict {
        v.gates
            .iter()
            .find(|g| g.id == id)
            .unwrap_or_else(|| panic!("no verdict for {id}: {v:#?}"))
    }

    // ------------------------------------------------------------- the log

    #[test]
    fn the_log_parser_names_tests_by_crate_source_and_libtest_name() {
        let log = parse_log(J4_LOG);
        for id in [
            "ouro-jail/tests/conformance_j1.rs::x01_literal_argv",
            "ouro-jail/src/lib.rs::platform::linux::seccomp::tests::architecture_is_checked_before_any_syscall_number",
            "ouro-fixture/src/lib.rs::harness::tests::a_skip_is_a_failure_in_conformance_mode_and_a_note_otherwise",
            "ouro-fixture/tests/harness_gate.rs::a_run_that_fails_to_start_is_an_error_not_a_pass",
            "xtask/src/main.rs::conformance::tests::a_clean_run_passes_and_the_remote_directory_is_removed",
            "ouro-jail/doc::crates/ouro-jail/src/platform/linux/tracer/mod.rs - platform::linux::tracer - compile",
        ] {
            assert_eq!(
                log.results.get(id).map(Vec::as_slice),
                Some(&[Outcome::Ok][..]),
                "{id}"
            );
        }
        // The fixture crate's integration tests are not the jail's.
        assert!(!log.results.contains_key(
            "ouro-jail/tests/harness_gate.rs::a_run_that_fails_to_start_is_an_error_not_a_pass"
        ));
    }

    #[test]
    fn the_j4_log_attributes_every_result_libtest_counted() {
        let log = parse_log(J4_LOG);
        let results: usize = log.results.values().map(Vec::len).sum();
        assert_eq!(results, 1299 + 13, "passed plus ignored in the J4 run");
        assert_eq!(log.failed_binaries, 0);
        assert!(log.skips.is_empty());
        assert!(log.summaries > 40, "{}", log.summaries);
        assert!(log.anomalies.is_empty(), "{:#?}", log.anomalies);
        assert!(log.clean());
    }

    #[test]
    fn a_result_printed_after_interleaved_output_belongs_to_the_pending_test() {
        // conformance_j2's l02 test runs a subprocess helper that prints its
        // own `running 1 test` lines before libtest prints `ok`.
        let log = parse_log(J4_LOG);
        for id in [
            "ouro-jail/tests/conformance_j2.rs::l02_startup_parent_death_window_is_closed",
            "ouro-jail/tests/conformance_j3_none.rs::an_unconfirmed_target_that_escapes_and_is_killed_stays_prepared",
            "ouro-jail/tests/observer_regression_linux.rs::r29_a_dead_supervisor_kills_its_traced_tree",
            "ouro-jail/tests/portable_state.rs::the_lease_is_exclusive_across_processes",
        ] {
            assert_eq!(
                log.results.get(id).map(Vec::as_slice),
                Some(&[Outcome::Ok][..]),
                "{id}"
            );
        }
    }

    #[test]
    fn the_j4_ignored_set_is_the_thirteen_the_j4_report_counts() {
        let ignored = parse_log(J4_LOG).ignored();
        assert_eq!(ignored.len(), 13, "{ignored:#?}");
        assert!(ignored.contains("ouro-jail/tests/conformance_j2.rs::startup_supervisor_helper"));
        assert!(ignored.contains(
            "ouro-fixture/doc::crates/ouro-fixture/src/harness/mod.rs - harness::skip_or_fail"
        ));
    }

    #[test]
    fn failed_ignored_duplicated_and_unresolved_results_are_kept_apart() {
        let log = parse_log(
            "     Running tests/t.rs (target/release/deps/t-0123456789abcdef)\n\
             running 4 tests\n\
             test a ... FAILED\n\
             test b ... ignored\n\
             test c - should panic ... ok\n\
             test d ... some output the test printed\n\
             test d ... ok\n\
             test e ... \n\
             more output\n\
             test result: FAILED. 1 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
        );
        // `t` has no lib before it: its crate is unknown.
        let id = |n: &str| format!("?/tests/t.rs::{n}");
        assert_eq!(log.results[&id("a")], vec![Outcome::Failed]);
        assert_eq!(log.results[&id("b")], vec![Outcome::Ignored]);
        assert_eq!(
            log.results[&id("c")],
            vec![Outcome::Ok],
            "should panic is stripped"
        );
        assert!(
            !log.results.contains_key(&id("e")),
            "no result was ever printed for e"
        );
        assert!(
            log.anomalies
                .iter()
                .any(|a| a.test.as_deref() == Some(id("e").as_str())),
            "{:#?}",
            log.anomalies
        );
        // `test d ... ok` while d is pending: libtest runs one test at a time,
        // so this is a nested process's line, not a second d; it is not a
        // result and it is reported.
        assert!(!log.results.contains_key(&id("d")), "{:#?}", log.results);
        assert!(
            log.anomalies
                .iter()
                .any(|a| a.test.as_deref() == Some(id("d").as_str()))
        );
        assert_eq!(log.failed_binaries, 1);
        assert!(!log.clean());
    }

    #[test]
    fn a_skip_line_makes_the_log_unclean() {
        let log = parse_log(&format!("{MINI_LOG}skipped: bubblewrap is not installed\n"));
        assert_eq!(log.skips.len(), 1);
        assert!(!log.clean());
        assert!(parse_log(MINI_LOG).clean());
        assert!(!parse_log("").clean(), "no results at all is not clean");
    }

    // ------------------------------------------------------------- the map

    #[test]
    fn test_ids_are_crate_source_and_name() {
        for good in [
            "ouro-jail/tests/conformance_j1.rs::x01_literal_argv",
            "ouro-jail/src/lib.rs::platform::linux::seccomp::tests::x",
            "xtask/src/main.rs::gates::tests::x",
            "ouro-fixture/src/bin/stand-in-jail.rs::x",
            "ouro-jail/doc::crates/ouro-jail/src/a.rs - a - compile",
        ] {
            assert!(is_test_id(good), "{good}");
        }
        for bad in [
            "conformance_j1.rs::x01_literal_argv",
            "ouro-jail/tests/conformance_j1.rs",
            "ouro-jail/tests/conformance_j1::x",
            "ouro-jail/src/other.rs::x",
            "ouro-jail/tests/a.rs::",
            "ouro-jail/tests/a.rs::has space",
            "/tests/a.rs::x",
        ] {
            assert!(!is_test_id(bad), "{bad}");
        }
    }

    #[test]
    fn a_malformed_map_is_refused_with_every_problem() {
        let bad = r#"
schema = "ouro.jail.acceptance-map/0"

[[gate]]
id = "X01"
row = "r"

[[clause]]
id = "X01.1"
gate = "X01"
clause = "c"
tag = "recorded-limit"

[[clause]]
id = "X01.1"
gate = "Q99"
clause = "c"
tag = "untested"
tests = ["ouro-jail/tests/a.rs::t"]

[[clause]]
id = "X01.3"
gate = "X01"
clause = "c"
tag = "live-cli"
tests = ["not-an-id", "ouro-jail/tests/a.rs::helper"]
checks = ["no_such_check"]

[[ignored]]
test = "ouro-jail/tests/a.rs::helper"
reason = ""
"#;
        let err = Map::parse(bad).unwrap_err();
        for needle in [
            "ouro.jail.acceptance-map/0",
            "X01.1 is recorded-limit without a `limit`",
            "clause id X01.1 is used twice",
            "gate Q99, which has no [[gate]]",
            "X01.1 is untested but lists evidence",
            "`not-an-id` is not a test id",
            "`no_such_check` is not a driver check",
            "`ouro-jail/tests/a.rs::helper` is pinned as ignored and mapped as evidence",
            "the ignored test `ouro-jail/tests/a.rs::helper` has no reason",
        ] {
            assert!(err.contains(needle), "missing `{needle}` in:\n{err}");
        }
        assert!(Map::parse("schema = [").is_err());
        assert!(
            Map::parse("schema = \"ouro.jail.acceptance-map/1\"\nsurprise = 1\n").is_err(),
            "unknown keys are refused, not ignored"
        );
    }

    #[test]
    fn a_credential_clause_belongs_only_to_a_credential_gate() {
        let bad = MINI_MAP.replace("kind = \"credential\"\n", "");
        let err = Map::parse(&bad).unwrap_err();
        assert!(err.contains("A01.1 is tagged credential"), "{err}");
    }

    #[test]
    fn the_spec_rows_are_read_from_section_fifteen_only() {
        let rows = spec_rows(MINI_SPEC).unwrap();
        assert_eq!(
            rows,
            vec![
                (
                    "X01".to_string(),
                    "Spaces reach the fixture literally.".to_string()
                ),
                (
                    "A01".to_string(),
                    "A real batch agent run records a receipt.".to_string()
                ),
            ]
        );
        assert!(spec_rows("# no section fifteen\n").is_err());
        let real = spec_rows(SPEC).unwrap();
        assert_eq!(
            real.len(),
            51,
            "{:?}",
            real.iter().map(|r| &r.0).collect::<Vec<_>>()
        );
        assert_eq!(real[0].0, "P01");
        assert_eq!(real[50].0, "A01");
    }

    #[test]
    fn a_map_that_drifts_from_the_spec_is_named() {
        let (map, rows) = mini();
        assert!(spec_problems(&map, &rows).is_empty());
        let changed = MINI_SPEC.replace("literally.", "literally, and tabs too.");
        let p = spec_problems(&map, &spec_rows(&changed).unwrap());
        assert!(
            p.iter().any(|p| p.contains("X01") && p.contains("differs")),
            "{p:?}"
        );
        let added = MINI_SPEC.replace("| A01 |", "| X02 | A new gate. |\n| A01 |");
        let p = spec_problems(&map, &spec_rows(&added).unwrap());
        assert!(
            p.iter()
                .any(|p| p.contains("X02") && p.contains("no [[gate]]")),
            "{p:?}"
        );
        let removed = MINI_SPEC.replace("| X01 | Spaces reach the fixture literally. |\n", "");
        let p = spec_problems(&map, &spec_rows(&removed).unwrap());
        assert!(
            p.iter()
                .any(|p| p.contains("X01") && p.contains("not a §15 row")),
            "{p:?}"
        );
    }

    // --------------------------------------------------------- the verdict

    #[test]
    fn a_clean_run_of_the_mini_map_passes_and_the_credential_gate_is_not_evaluated() {
        let (map, rows) = mini();
        let v = evaluate(&map, &rows, &linux(MINI_LOG), &no_checks());
        assert!(v.failures().is_empty(), "{:#?}", v.failures());
        assert_eq!(gate(&v, "X01").status, GateStatus::Pass);
        assert_eq!(gate(&v, "A01").status, GateStatus::Credential);
    }

    #[test]
    fn a_mapped_test_that_is_absent_failed_or_ignored_fails_its_gate() {
        let (map, rows) = mini();
        for (log, why) in [
            (
                MINI_LOG.replace("test x01_literal_argv ... ok\n", ""),
                "absent",
            ),
            (
                MINI_LOG.replace(
                    "test x01_literal_argv ... ok",
                    "test x01_literal_argv ... FAILED",
                ),
                "FAILED",
            ),
            (
                MINI_LOG.replace(
                    "test x01_literal_argv ... ok",
                    "test x01_literal_argv ... ignored",
                ),
                "ignored",
            ),
            (
                MINI_LOG.replace(
                    "test x01_literal_argv ... ok",
                    "test x01_literal_argv ... ok\ntest x01_literal_argv ... ok",
                ),
                "2 times",
            ),
        ] {
            let v = evaluate(&map, &rows, &linux(&log), &no_checks());
            let x01 = gate(&v, "X01");
            assert_eq!(x01.status, GateStatus::Fail, "{why}: {x01:#?}");
            assert!(
                x01.clauses[0].reasons.iter().any(|r| r.contains(why)),
                "{why}: {x01:#?}"
            );
            assert!(
                v.failures().iter().any(|f| f.starts_with("gate X01 fails")),
                "{why}: {:#?}",
                v.failures()
            );
        }
    }

    #[test]
    fn a_clause_with_no_evidence_fails_unless_it_is_a_recorded_limit() {
        let untested = MINI_MAP.replace(
            "tag = \"live-cli\"\ntests = [\"ouro-jail/tests/conformance_j1.rs::x01_literal_argv\"]",
            "tag = \"untested\"",
        );
        let (_, rows) = mini();
        let v = evaluate(
            &Map::parse(&untested).unwrap(),
            &rows,
            &linux(MINI_LOG),
            &no_checks(),
        );
        assert_eq!(gate(&v, "X01").status, GateStatus::Fail);
        assert!(
            gate(&v, "X01").clauses[0]
                .reasons
                .iter()
                .any(|r| r.contains("no test")),
            "{v:#?}"
        );

        let limit = MINI_MAP.replace(
            "tag = \"live-cli\"\ntests = [\"ouro-jail/tests/conformance_j1.rs::x01_literal_argv\"]",
            "tag = \"recorded-limit\"\nlimit = \"j4-authority.md, known gaps\"",
        );
        let v = evaluate(
            &Map::parse(&limit).unwrap(),
            &rows,
            &linux(MINI_LOG),
            &no_checks(),
        );
        assert_eq!(gate(&v, "X01").status, GateStatus::PassWithLimits);
        assert!(v.failures().is_empty(), "{:#?}", v.failures());
    }

    #[test]
    fn a_gate_the_map_lacks_fails() {
        let (map, _) = mini();
        let more = MINI_SPEC.replace("| A01 |", "| X02 | A new gate. |\n| A01 |");
        let v = evaluate(
            &map,
            &spec_rows(&more).unwrap(),
            &linux(MINI_LOG),
            &no_checks(),
        );
        assert_eq!(gate(&v, "X02").status, GateStatus::Fail);
        assert!(!v.failures().is_empty());
    }

    #[test]
    fn the_ignored_set_is_pinned_in_both_directions() {
        let (map, rows) = mini();
        // An `#[ignore]` added to a test nobody pinned fails the run.
        let extra = MINI_LOG.replace(
            "test records::tests::a ... ok",
            "test records::tests::a ... ignored",
        );
        let v = evaluate(&map, &rows, &linux(&extra), &no_checks());
        assert!(
            v.problems
                .iter()
                .any(|p| p.contains("ouro-jail/src/lib.rs::records::tests::a")
                    && p.contains("not pinned")),
            "{:#?}",
            v.problems
        );
        // A pinned helper that now runs (or vanished) fails it too.
        let ran = MINI_LOG.replace(
            "test startup_supervisor_helper ... ignored, helper",
            "test startup_supervisor_helper ... ok",
        );
        let v = evaluate(&map, &rows, &linux(&ran), &no_checks());
        assert!(
            v.problems.iter().any(|p| p.contains("startup_supervisor_helper")
                && p.contains("pinned as ignored")),
            "{:#?}",
            v.problems
        );
    }

    #[test]
    fn checks_count_as_evidence_and_an_absent_check_fails() {
        let with_check = MINI_MAP.replace(
            "tests = [\"ouro-jail/tests/conformance_j1.rs::x01_literal_argv\"]",
            "checks = [\"i01_absent\", \"suite_clean\"]",
        );
        let (_, rows) = mini();
        let map = Map::parse(&with_check).unwrap();
        let v = evaluate(&map, &rows, &linux(MINI_LOG), &no_checks());
        assert_eq!(gate(&v, "X01").status, GateStatus::Fail);
        assert!(
            gate(&v, "X01").clauses[0]
                .reasons
                .iter()
                .any(|r| r.contains("i01_absent") && r.contains("not produced")),
            "{v:#?}"
        );
        let passed = BTreeMap::from([("i01_absent".to_string(), true)]);
        assert_eq!(
            gate(&evaluate(&map, &rows, &linux(MINI_LOG), &passed), "X01").status,
            GateStatus::Pass
        );
        let failed = BTreeMap::from([("i01_absent".to_string(), false)]);
        assert_eq!(
            gate(&evaluate(&map, &rows, &linux(MINI_LOG), &failed), "X01").status,
            GateStatus::Fail
        );
        // suite_clean comes from the lane's own log.
        let dirty = format!("{MINI_LOG}skipped: no bwrap\n");
        assert_eq!(
            gate(&evaluate(&map, &rows, &linux(&dirty), &passed), "X01").status,
            GateStatus::Fail
        );
    }

    #[test]
    fn a_clause_in_a_lane_that_was_not_evaluated_is_elsewhere_not_passed() {
        let mac = MINI_MAP.replace(
            "tag = \"live-cli\"\n",
            "tag = \"portable\"\nlane = \"macos\"\n",
        );
        let (_, rows) = mini();
        let v = evaluate(
            &Map::parse(&mac).unwrap(),
            &rows,
            &linux(MINI_LOG),
            &no_checks(),
        );
        assert_eq!(gate(&v, "X01").status, GateStatus::Elsewhere);
        assert!(
            v.failures().is_empty(),
            "another lane is reported, not failed"
        );
    }

    // ------------------------------------------------------ the real map

    #[test]
    fn the_checked_in_map_is_well_formed_and_agrees_with_section_fifteen() {
        let map = Map::parse(MAP).unwrap_or_else(|e| panic!("{e}"));
        let rows = spec_rows(SPEC).unwrap();
        let problems = spec_problems(&map, &rows);
        assert!(problems.is_empty(), "{problems:#?}");
        for (id, _) in &rows {
            assert!(
                map.clause.iter().any(|c| &c.gate == id),
                "§15 {id} has no clause in the map"
            );
        }
    }

    #[test]
    fn every_mapped_test_exists_in_the_source_tree() {
        let map = Map::parse(MAP).unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut missing = Vec::new();
        for c in &map.clause {
            for t in &c.tests {
                if !test_exists(&root, t) {
                    missing.push(format!("{}: {t}", c.id));
                }
            }
        }
        for i in &map.ignored {
            if !test_exists(&root, &i.test) {
                missing.push(format!("[[ignored]]: {}", i.test));
            }
        }
        assert!(missing.is_empty(), "{missing:#?}");
    }

    /// Find `fn <name>(` in the file the id names (integration tests) or in
    /// the module file its path names (unit tests).
    fn test_exists(root: &std::path::Path, id: &str) -> bool {
        let Some((binary, name)) = id.split_once("::") else {
            return false;
        };
        let Some((krate, source)) = binary.split_once('/') else {
            return false;
        };
        let crate_dir = root.join("crates").join(krate);
        if source == "doc" {
            let Some((file, _)) = name.split_once(" - ") else {
                return false;
            };
            return root.join(file).is_file();
        }
        let segments: Vec<&str> = name.split("::").collect();
        let (fn_name, modules) = segments.split_last().unwrap();
        let needle = format!("fn {fn_name}(");
        let read = |p: std::path::PathBuf| std::fs::read_to_string(p).unwrap_or_default();
        if source.starts_with("tests/") || source.starts_with("src/bin/") {
            return read(crate_dir.join(source)).contains(&needle);
        }
        // A unit test: the longest module path prefix that names a file.
        let src = crate_dir.join("src");
        for n in (0..=modules.len()).rev() {
            let rel: std::path::PathBuf = modules[..n].iter().collect();
            let candidates = if n == 0 {
                vec![crate_dir.join(source)]
            } else {
                vec![
                    src.join(&rel).with_extension("rs"),
                    src.join(&rel).join("mod.rs"),
                ]
            };
            for file in candidates {
                if file.is_file() {
                    return read(file).contains(&needle);
                }
            }
        }
        false
    }

    /// I02: "no vendor names/protocol dependencies in the execution core".
    /// The vendor-name scan sees a dependency only through its name, so a
    /// protocol client with a neutral name would pass it. This pins the
    /// execution core's shipped dependencies (every table but
    /// dev-dependencies): adding one fails here until it is reviewed against
    /// I02 and added to the reviewed set below.
    #[test]
    fn the_execution_core_dependencies_are_the_reviewed_set() {
        const REVIEWED: &[&str] = &[
            "base64",
            "clap",
            "libc",
            "serde",
            "serde_json",
            "sha2",
            "toml",
            "uuid",
        ];
        let manifest: toml::Value =
            toml::from_str(include_str!("../../ouro-jail/Cargo.toml")).unwrap();
        let mut names = BTreeSet::new();
        let mut tables = vec![&manifest];
        if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
            tables.extend(targets.values());
        }
        for table in tables {
            for key in ["dependencies", "build-dependencies"] {
                if let Some(deps) = table.get(key).and_then(toml::Value::as_table) {
                    names.extend(deps.keys().cloned());
                }
            }
        }
        let reviewed: BTreeSet<String> = REVIEWED.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(
            names, reviewed,
            "the execution core's dependencies changed: review the change against I02 \
             (no protocol dependency) and update the reviewed set"
        );
    }

    /// Every reason a real, green run can give for a failing clause: the
    /// clause is untested, the driver produced no check (a saved log has
    /// none), or the test is newer than the log. Anything else (a mapped
    /// test that FAILED, was ignored or is reported twice, an unpinned
    /// ignore) is a map or parser error, and fails this.
    fn assert_only_expected_reasons(v: &Verdict, log: &TestLog) {
        for g in &v.gates {
            for c in &g.clauses {
                for r in &c.reasons {
                    let newer_test = r.ends_with("is absent from the linux log");
                    assert!(
                        r.starts_with("untested: ")
                            || (r.starts_with("check `")
                                && r.ends_with("was not produced by this run"))
                            || newer_test,
                        "{}: {r}",
                        c.id
                    );
                }
            }
            assert!(g.reasons.is_empty(), "{}: {:?}", g.id, g.reasons);
        }
        for p in &v.problems {
            assert!(
                p.contains("is pinned as ignored but the linux log is absent from the log"),
                "only a helper newer than the log may be missing: {p}"
            );
        }
        assert!(log.anomalies.is_empty(), "{:#?}", log.anomalies);
    }

    #[test]
    fn the_j4_log_under_the_checked_in_map_fails_only_what_it_could_not_prove() {
        let map = Map::parse(MAP).unwrap();
        let rows = spec_rows(SPEC).unwrap();
        let log = parse_log(J4_LOG);
        let v = evaluate(&map, &rows, &linux(J4_LOG), &no_checks());
        assert_only_expected_reasons(&v, &log);
        assert_eq!(
            gate(&v, "I01").status,
            GateStatus::Fail,
            "no I01 check ran in J4"
        );
        assert_eq!(gate(&v, "A01").status, GateStatus::Credential);
        assert_eq!(gate(&v, "M01").status, GateStatus::Elsewhere);
        assert!(!v.failures().is_empty());
    }

    /// The full run at the J5 base, `1328c381` (run
    /// 20260924T194045Z-1328c38108fa on the reference host: 1345 passed,
    /// 0 failed, 13 ignored).
    const BASE_LOG: &str = include_str!(
        "../../../docs/specs/jail-v1/evidence/j5-base-test-log-2026-09-24-ouro-ci.txt"
    );

    #[test]
    fn the_base_run_attributes_every_result_and_fails_only_what_it_could_not_prove() {
        let log = parse_log(BASE_LOG);
        let results: usize = log.results.values().map(Vec::len).sum();
        assert_eq!(results, 1345 + 13);
        assert!(log.clean());
        let map = Map::parse(MAP).unwrap();
        let rows = spec_rows(SPEC).unwrap();
        let v = evaluate(&map, &rows, &linux(BASE_LOG), &no_checks());
        assert_only_expected_reasons(&v, &log);
        // Given the driver checks it did not have, the base still fails
        // every clause that is untested: the verdict never passes a gate on
        // a log alone that the map says nothing proves.
        let all = CHECKS
            .iter()
            .map(|c| ((*c).to_string(), true))
            .collect::<BTreeMap<_, _>>();
        let v = evaluate(&map, &rows, &linux(BASE_LOG), &all);
        for c in map.clause.iter().filter(|c| c.tag == Tag::Untested) {
            let g = gate(&v, &c.gate);
            assert_eq!(g.status, GateStatus::Fail, "{} is untested", c.id);
        }
    }
}
