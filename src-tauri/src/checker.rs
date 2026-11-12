//! Core YARA -> YARA-X compatibility checker.
//!
//! This module is deliberately free of any Tauri dependency so it can be unit
//! tested and reused (CLI, library, tests) independently of the desktop shell.
//!
//! The strategy is layer 1 of the design: feed each rule source to the real
//! YARA-X compiler and report exactly what it reports. Because the sensor in
//! v29.3 embeds a specific YARA-X version and specific compile flags, the
//! options here are meant to mirror the sensor. Until Corelight engineering
//! confirms them, the defaults follow the published Compatibility Guide
//! (`yr compile --relaxed-re-syntax`).

use serde::Serialize;
use yara_x::{Compiler, SourceCode};

/// One error or warning emitted by the YARA-X compiler, flattened for the UI.
#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    /// "error" or "warning".
    pub severity: String,
    /// Stable code, e.g. "E013" / "invalid_escape_sequence".
    pub code: String,
    /// Short human title.
    pub title: String,
    /// Origin (file name) the finding belongs to, if the source had one.
    pub origin: Option<String>,
    /// 1-based line number of the primary label, if available.
    pub line: Option<usize>,
    /// 1-based column of the primary label, if available.
    pub column: Option<usize>,
    /// Full rendered report, exactly as the `yr` CLI would print it.
    pub report: String,
}

/// Compiler options that must mirror the target sensor to be trustworthy.
#[derive(Serialize, Clone, Debug)]
pub struct CheckOptions {
    /// Matches `--relaxed-re-syntax`. Default true per the Compatibility Guide.
    pub relaxed_re_syntax: bool,
    /// Turn slow-pattern warnings into hard errors (sensor may do this).
    pub error_on_slow_pattern: bool,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            relaxed_re_syntax: true,
            error_on_slow_pattern: false,
        }
    }
}

/// A single named source to check (e.g. one .yar file, or a pasted blob).
#[derive(Clone, Debug)]
pub struct SourceInput {
    pub origin: String,
    pub content: String,
}

/// The full result of a compatibility check.
#[derive(Serialize, Clone, Debug)]
pub struct CheckReport {
    /// True when the whole ruleset compiled with zero errors. This mirrors the
    /// sensor: any single error means the submission is rejected.
    pub compatible: bool,
    pub error_count: usize,
    pub warning_count: usize,
    pub findings: Vec<Finding>,
    /// Findings that appear ONLY under strict regex parsing, i.e. rules that
    /// compile today solely because `--relaxed-re-syntax` is enabled and would
    /// break if the sensor ever switched to strict parsing. Empty unless the
    /// primary pass ran with relaxed mode on. See `check_with_diff`.
    pub strict_risk: Vec<Finding>,
    /// Whether the strict second pass actually ran (only when relaxed was on).
    pub strict_checked: bool,
    /// Layer-2 (heuristic) semantic-drift risks: rules that compile fine but
    /// USE constructs known to match differently under YARA-X's engine. These
    /// are static guesses that need runtime verification, NOT confirmed drift.
    /// Severity on each Finding is "drift"; code is the heuristic kind.
    pub drift_risk: Vec<Finding>,
    /// Number of top-level source files compiled (1 for pasted text). Files
    /// pulled in via `include` are counted in `included_files`, not here.
    pub files_checked: usize,
    /// Number of files that were compiled *through* an `include` from another
    /// file rather than as standalone sources (0 for pasted text / non-dir).
    pub included_files: usize,
    /// The YARA-X version this app is linked against (authoritative for v29.3
    /// only once it matches the sensor's embedded version).
    pub yara_x_version: String,
    pub options: CheckOptions,
}

/// Pull the primary (line, column) out of a serialized label list.
fn primary_location(labels_json: &serde_json::Value) -> (Option<usize>, Option<usize>) {
    labels_json
        .as_array()
        .and_then(|arr| arr.first())
        .map(|first| {
            (
                first.get("line").and_then(|v| v.as_u64()).map(|n| n as usize),
                first
                    .get("column")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as usize),
            )
        })
        .unwrap_or((None, None))
}

/// Extract origin (file name) from a serialized label list.
fn primary_origin(labels_json: &serde_json::Value) -> Option<String> {
    labels_json
        .as_array()
        .and_then(|a| a.first())
        .and_then(|l| l.get("code_origin"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Run a single compile pass and return its findings (errors + warnings).
/// When `include_dir` is set, `include` statements are enabled and resolved
/// relative to that directory (mirrors `yr compile <dir>`).
fn run_pass(
    sources: &[SourceInput],
    relaxed: bool,
    opts: &CheckOptions,
    include_dir: Option<&std::path::Path>,
) -> Vec<Finding> {
    let mut compiler = Compiler::new();
    compiler.relaxed_re_syntax(relaxed);
    compiler.error_on_slow_pattern(opts.error_on_slow_pattern);
    // No ANSI escapes: the UI styles findings itself.
    compiler.colorize_errors(false);

    if let Some(dir) = include_dir {
        compiler.enable_includes(true);
        let _ = compiler.add_include_dir(dir);
    } else {
        // Pasted / single-file content can't resolve includes anyway.
        compiler.enable_includes(false);
    }

    for s in sources {
        let src = SourceCode::from(s.content.as_str()).with_origin(&s.origin);
        // Errors accumulate in the compiler; we read them all at the end.
        let _ = compiler.add_source(src);
    }

    let mut findings: Vec<Finding> = Vec::new();

    for err in compiler.errors() {
        let labels_json = serde_json::to_value(err.labels().collect::<Vec<_>>())
            .unwrap_or(serde_json::Value::Null);
        let (line, column) = primary_location(&labels_json);
        findings.push(Finding {
            severity: "error".to_string(),
            code: err.code().to_string(),
            title: err.title().to_string(),
            origin: primary_origin(&labels_json),
            line,
            column,
            report: format!("{}", err),
        });
    }

    for warn in compiler.warnings() {
        let labels_json = serde_json::to_value(warn.labels().collect::<Vec<_>>())
            .unwrap_or(serde_json::Value::Null);
        let (line, column) = primary_location(&labels_json);
        findings.push(Finding {
            severity: "warning".to_string(),
            code: warn.code().to_string(),
            title: warn.title().to_string(),
            origin: primary_origin(&labels_json),
            line,
            column,
            report: format!("{}", warn),
        });
    }

    findings
}

/// A stable identity for a finding, used to diff two passes.
fn finding_key(f: &Finding) -> (String, Option<String>, Option<usize>, Option<usize>) {
    (f.code.clone(), f.origin.clone(), f.line, f.column)
}

/// Strip YARA comments from one line, tracking `/* ... */` block state across
/// lines. Best-effort: comment markers inside a regex/string are rare enough
/// that a heuristic can tolerate the odd truncation. Returns the code portion
/// and the updated in-block flag.
fn strip_comments_line(line: &str, mut in_block: bool) -> (String, bool) {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        if in_block {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            in_block = true;
            i += 2;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            break; // rest of line is a line comment
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    (out, in_block)
}

/// Layer-2 static heuristic: flag rules that USE constructs known to match
/// differently between classic YARA and YARA-X. This does NOT run the rules;
/// it's a fast pre-filter that says "verify these", ahead of true differential
/// execution. Each hit is a `Finding` with severity "drift".
fn scan_drift(sources: &[SourceInput]) -> Vec<Finding> {
    use regex::Regex;
    // Compiled once per call (call count is tiny: one per check).
    // High-signal heuristics only: we flag constructs whose *match behavior*
    // genuinely differs between classic YARA and YARA-X — the regex engine and
    // the base64 modifier. Count/offset operators (#/@/at/in) and filesize
    // integer reads were deliberately dropped: their semantics are effectively
    // unchanged, so flagging them buried the real signal (~50% of a large feed).
    let re_regex = Regex::new(r#"\$[A-Za-z0-9_]+\s*=\s*/((?:[^/\\]|\\.)*)/"#).unwrap();
    let re_base64 = Regex::new(r"\bbase64(?:wide)?\b").unwrap();

    let mut out: Vec<Finding> = Vec::new();
    let mut push = |origin: &str, line: usize, kind: &str, title: &str, snippet: &str| {
        out.push(Finding {
            severity: "drift".to_string(),
            code: kind.to_string(),
            title: title.to_string(),
            origin: Some(origin.to_string()),
            line: Some(line),
            column: None,
            report: snippet.trim().to_string(),
        });
    };

    for src in sources {
        let mut in_block = false;
        for (idx, raw) in src.content.lines().enumerate() {
            let (code, next) = strip_comments_line(raw, in_block);
            in_block = next;
            if code.trim().is_empty() {
                continue;
            }
            let line = idx + 1;

            // H1 — regex patterns with engine-sensitive constructs.
            for cap in re_regex.captures_iter(&code) {
                let body = &cap[1];
                if body.contains(".*")
                    || body.contains(".+")
                    || body.contains(".{")
                    || body.contains('|')
                    || body.contains("\\b")
                {
                    push(
                        &src.origin,
                        line,
                        "DRIFT-REGEX",
                        "Regex uses a greedy quantifier, alternation, or word boundary — YARA-X's regex engine can differ in greediness/overlap, changing what matches (and match count/offset).",
                        raw,
                    );
                    break; // one hit per line is enough
                }
            }

            // H2 — base64 modifiers (alphabet/padding edge cases).
            if re_base64.is_match(&code) {
                push(
                    &src.origin,
                    line,
                    "DRIFT-BASE64",
                    "base64 / base64wide modifier: alphabet and padding handling has known differences — verify the encoded pattern still matches.",
                    raw,
                );
            }
        }
    }

    out
}

/// Assemble a `CheckReport` from a set of primary-pass findings.
fn build_report(
    findings: Vec<Finding>,
    strict_risk: Vec<Finding>,
    drift_risk: Vec<Finding>,
    strict_checked: bool,
    files_checked: usize,
    included_files: usize,
    opts: &CheckOptions,
) -> CheckReport {
    let error_count = findings.iter().filter(|f| f.severity == "error").count();
    let warning_count = findings.len() - error_count;
    CheckReport {
        compatible: error_count == 0,
        error_count,
        warning_count,
        findings,
        strict_risk,
        strict_checked,
        drift_risk,
        files_checked,
        included_files,
        yara_x_version: yara_x::VERSION.to_string(),
        options: opts.clone(),
    }
}

/// Core dual-pass check shared by text/file and directory entry points.
fn check_core(
    sources: &[SourceInput],
    opts: &CheckOptions,
    include_dir: Option<&std::path::Path>,
    files_checked: usize,
    included_files: usize,
) -> CheckReport {
    let primary = run_pass(sources, opts.relaxed_re_syntax, opts, include_dir);
    let drift_risk = scan_drift(sources);

    // The strict diff is only meaningful when the primary pass was relaxed;
    // otherwise there is nothing stricter to compare against.
    if !opts.relaxed_re_syntax {
        return build_report(
            primary,
            Vec::new(),
            drift_risk,
            false,
            files_checked,
            included_files,
            opts,
        );
    }

    let strict = run_pass(sources, false, opts, include_dir);
    let primary_keys: std::collections::HashSet<_> =
        primary.iter().map(finding_key).collect();

    let strict_risk: Vec<Finding> = strict
        .into_iter()
        .filter(|f| f.severity == "error" && !primary_keys.contains(&finding_key(f)))
        .collect();

    build_report(
        primary,
        strict_risk,
        drift_risk,
        true,
        files_checked,
        included_files,
        opts,
    )
}

/// Run a single compatibility check (one pass). `strict_risk` is always empty.
/// Kept as a public single-pass API for library/CLI reuse; the desktop app
/// uses [`check_with_diff`].
#[allow(dead_code)]
pub fn check(sources: &[SourceInput], opts: &CheckOptions) -> CheckReport {
    let findings = run_pass(sources, opts.relaxed_re_syntax, opts, None);
    let drift_risk = scan_drift(sources);
    build_report(findings, Vec::new(), drift_risk, false, sources.len(), 0, opts)
}

/// Dual-pass check over pasted text or individually-loaded files (no include
/// resolution — includes can't resolve without a directory).
pub fn check_with_diff(sources: &[SourceInput], opts: &CheckOptions) -> CheckReport {
    check_core(sources, opts, None, sources.len(), 0)
}

/// Parse the `include "..."` targets out of one rule file's content and
/// resolve each relative to the including file's own directory (YARA-X, like
/// C, resolves includes relative to the file that contains them). Best-effort
/// line scan — YARA `include` statements are always a bare quoted path.
fn parse_include_targets(file_path: &std::path::Path, content: &str) -> Vec<std::path::PathBuf> {
    let base = file_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut targets = Vec::new();
    for line in content.lines() {
        let t = line.trim_start();
        // Match a line beginning with `include` followed by whitespace/quote,
        // so we don't trip on identifiers like `include_foo`.
        let rest = match t.strip_prefix("include") {
            Some(r) if r.starts_with([' ', '\t', '"']) => r.trim_start(),
            _ => continue,
        };
        let rest = match rest.strip_prefix('"') {
            Some(r) => r,
            None => continue,
        };
        if let Some(end) = rest.find('"') {
            targets.push(base.join(&rest[..end]));
        }
    }
    targets
}

/// A `.yar`/`.yara` file discovered under the root, with its absolute and
/// root-relative paths plus content.
struct DiscoveredFile {
    abs: std::path::PathBuf,
    origin: String,
    content: String,
}

/// Result of collecting a rules directory: the top-level ("root") files to
/// compile, and how many files were pulled in via `include` instead (and so
/// deliberately NOT added as standalone sources, to avoid duplicate-rule
/// errors).
struct CollectedDir {
    sources: Vec<SourceInput>,
    included_files: usize,
}

/// Walk `root` and read every `.yar`/`.yara` file. Files that are `include`d
/// by another file in the tree are compiled *through* their includer, not as
/// standalone sources — otherwise a master-index feed (an `index.yar` that
/// `include`s its rule files, sitting alongside those files) would compile
/// every rule twice and report spurious duplicate-rule errors. Shared by
/// directory check and directory scan.
fn collect_dir_sources(root_path: &std::path::Path) -> Result<CollectedDir, String> {
    if !root_path.is_dir() {
        return Err(format!("{} is not a directory", root_path.display()));
    }

    let mut files: Vec<DiscoveredFile> = Vec::new();
    for entry in walkdir::WalkDir::new(root_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_yara = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
            .unwrap_or(false);
        if !is_yara {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(path) {
            let origin = path
                .strip_prefix(root_path)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            files.push(DiscoveredFile {
                abs: path.to_path_buf(),
                origin,
                content,
            });
        }
        // else: skip unreadable / non-UTF-8 files
    }

    if files.is_empty() {
        return Err(format!("no .yar/.yara files found under {}", root_path.display()));
    }

    // Canonical path -> index, so we can match include targets to discovered
    // files regardless of `./` / `..` noise in the path.
    use std::collections::HashSet;
    let canon: std::collections::HashMap<std::path::PathBuf, usize> = files
        .iter()
        .enumerate()
        .filter_map(|(i, f)| f.abs.canonicalize().ok().map(|c| (c, i)))
        .collect();

    // Mark every discovered file that is included by some other file.
    let mut included: HashSet<usize> = HashSet::new();
    for f in &files {
        for target in parse_include_targets(&f.abs, &f.content) {
            if let Ok(c) = target.canonicalize() {
                if let Some(&idx) = canon.get(&c) {
                    included.insert(idx);
                }
            }
        }
    }

    let included_files = included.len();
    let sources: Vec<SourceInput> = files
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !included.contains(i))
        .map(|(_, f)| SourceInput {
            origin: f.origin,
            content: f.content,
        })
        .collect();

    Ok(CollectedDir {
        sources,
        included_files,
    })
}

/// Dual-pass check over every `.yar`/`.yara` file under `root`, with `include`
/// statements resolved relative to `root` (mirrors `yr compile <dir>`).
pub fn check_directory(root: &str, opts: &CheckOptions) -> Result<CheckReport, String> {
    let root_path = std::path::Path::new(root);
    let collected = collect_dir_sources(root_path)?;
    let count = collected.sources.len();
    Ok(check_core(
        &collected.sources,
        opts,
        Some(root_path),
        count,
        collected.included_files,
    ))
}

// ---------------------------------------------------------------------------
// Scanning: run the compiled rules against a real sample file.
//
// Compatibility checking answers "will the sensor accept these rules?".
// Scanning answers the next question a customer actually cares about: "do the
// rules still *fire* the same way on YARA-X?". We compile the exact same
// sources (with sensor-parity flags), build a Scanner, and report which rules
// matched the uploaded sample.
// ---------------------------------------------------------------------------

/// One rule that matched the scanned sample.
#[derive(Serialize, Clone, Debug)]
pub struct RuleMatch {
    pub identifier: String,
    pub namespace: String,
    pub tags: Vec<String>,
    /// Total number of individual pattern matches across the rule.
    pub pattern_matches: usize,
}

/// Result of scanning a sample file with the compiled ruleset.
#[derive(Serialize, Clone, Debug)]
pub struct ScanReport {
    /// Name of the file that was scanned.
    pub scanned_file: String,
    /// Size of the scanned sample, in bytes.
    pub file_size: usize,
    /// How many rules compiled successfully and were available to scan with.
    pub rules_compiled: usize,
    /// Compile errors encountered while building the ruleset. Rules with errors
    /// are simply dropped, so a nonzero count means the scan ran with a subset.
    pub compile_errors: usize,
    /// Rules that matched the sample.
    pub matches: Vec<RuleMatch>,
    pub yara_x_version: String,
}

/// Compile `sources` into a runnable ruleset. Returns the built rules plus the
/// number of compile errors (rules that errored are dropped from the build).
fn build_rules(
    sources: &[SourceInput],
    opts: &CheckOptions,
    include_dir: Option<&std::path::Path>,
) -> (yara_x::Rules, usize) {
    let mut compiler = Compiler::new();
    compiler.relaxed_re_syntax(opts.relaxed_re_syntax);
    compiler.error_on_slow_pattern(opts.error_on_slow_pattern);
    compiler.colorize_errors(false);

    if let Some(dir) = include_dir {
        compiler.enable_includes(true);
        let _ = compiler.add_include_dir(dir);
    } else {
        compiler.enable_includes(false);
    }

    for s in sources {
        let src = SourceCode::from(s.content.as_str()).with_origin(&s.origin);
        let _ = compiler.add_source(src);
    }

    let compile_errors = compiler.errors().len();
    (compiler.build(), compile_errors)
}

/// Scan `data` with rules compiled from `sources`, reporting which rules fire.
fn scan_core(
    sources: &[SourceInput],
    opts: &CheckOptions,
    include_dir: Option<&std::path::Path>,
    scanned_file: String,
    data: &[u8],
) -> Result<ScanReport, String> {
    let (rules, compile_errors) = build_rules(sources, opts, include_dir);
    let rules_compiled = rules.iter().count();

    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner
        .scan(data)
        .map_err(|e| format!("scan failed: {}", e))?;

    let matches: Vec<RuleMatch> = results
        .matching_rules()
        .map(|rule| RuleMatch {
            identifier: rule.identifier().to_string(),
            namespace: rule.namespace().to_string(),
            tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
            pattern_matches: rule.patterns().map(|p| p.matches().count()).sum(),
        })
        .collect();

    Ok(ScanReport {
        scanned_file,
        file_size: data.len(),
        rules_compiled,
        compile_errors,
        matches,
        yara_x_version: yara_x::VERSION.to_string(),
    })
}

/// Scan a sample file on disk with rules compiled from pasted text / loaded
/// files (no include resolution).
pub fn scan_sources(
    sources: &[SourceInput],
    opts: &CheckOptions,
    data_path: &str,
) -> Result<ScanReport, String> {
    let path = std::path::Path::new(data_path);
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {}", data_path, e))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| data_path.to_string());
    scan_core(sources, opts, None, name, &data)
}

/// Scan a sample file on disk with rules compiled from every `.yar`/`.yara`
/// file under `root` (with includes resolved relative to `root`).
pub fn scan_directory(
    root: &str,
    opts: &CheckOptions,
    data_path: &str,
) -> Result<ScanReport, String> {
    let root_path = std::path::Path::new(root);
    let collected = collect_dir_sources(root_path)?;
    let path = std::path::Path::new(data_path);
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {}", data_path, e))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| data_path.to_string());
    scan_core(&collected.sources, opts, Some(root_path), name, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(content: &str) -> Vec<SourceInput> {
        vec![SourceInput {
            origin: "test.yar".to_string(),
            content: content.to_string(),
        }]
    }

    #[test]
    fn clean_rule_is_compatible() {
        let report = check(
            &one("rule a { strings: $a = \"foo\" condition: $a }"),
            &CheckOptions::default(),
        );
        assert!(report.compatible, "findings: {:?}", report.findings);
        assert_eq!(report.error_count, 0);
    }

    #[test]
    fn syntax_error_is_incompatible() {
        let report = check(&one("rule broken { condition true }"), &CheckOptions::default());
        assert!(!report.compatible);
        assert!(report.error_count >= 1);
        assert_eq!(report.findings[0].severity, "error");
    }

    #[test]
    fn relaxed_only_regex_shows_up_as_strict_risk() {
        // `/a{/` compiles under --relaxed-re-syntax but errors under strict:
        // exactly the "compiles today, breaks if strict is turned on" case.
        let rule = "rule r { strings: $a = /a{/ condition: $a }";
        let report = check_with_diff(&one(rule), &CheckOptions::default());
        // Passes today (relaxed on)...
        assert!(report.compatible, "should compile under relaxed mode");
        // ...but is flagged as relaxed-dependent.
        assert!(report.strict_checked);
        assert_eq!(report.strict_risk.len(), 1, "expected one strict-only error");
        assert_eq!(report.strict_risk[0].severity, "error");
    }

    #[test]
    fn no_strict_risk_when_relaxed_disabled() {
        // If the user runs strict as the primary pass, there is no second,
        // stricter pass to diff against.
        let opts = CheckOptions {
            relaxed_re_syntax: false,
            error_on_slow_pattern: false,
        };
        let report = check_with_diff(&one("rule r { strings: $a = /a{/ condition: $a }"), &opts);
        assert!(!report.strict_checked);
        assert!(report.strict_risk.is_empty());
    }

    /// Opt-in benchmark against a real corpus. Set CORELIGHT_YARA_CORPUS to a
    /// .yar file path and run: `cargo test --lib corpus -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn corpus_benchmark() {
        let path = match std::env::var("CORELIGHT_YARA_CORPUS") {
            Ok(p) => p,
            Err(_) => {
                eprintln!("set CORELIGHT_YARA_CORPUS to run this");
                return;
            }
        };
        let content = std::fs::read_to_string(&path).expect("read corpus");
        let sources = vec![SourceInput {
            origin: std::path::Path::new(&path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            content,
        }];
        let t0 = std::time::Instant::now();
        let report = check_with_diff(&sources, &CheckOptions::default());
        let dt = t0.elapsed();
        eprintln!("--- corpus: {} ---", path);
        eprintln!("compatible (relaxed):   {}", report.compatible);
        eprintln!("errors:                 {}", report.error_count);
        eprintln!("warnings:               {}", report.warning_count);
        eprintln!("relaxed-dependent:      {}", report.strict_risk.len());
        eprintln!("drift-risk (heuristic): {}", report.drift_risk.len());
        eprintln!("elapsed:                {:?}", dt);
        let mut dcodes: std::collections::HashMap<String, usize> = Default::default();
        for f in report.drift_risk.iter() {
            *dcodes.entry(f.code.clone()).or_default() += 1;
        }
        eprintln!("drift codes: {:?}", dcodes);
        // Tally error codes to see what breaks most.
        let mut codes: std::collections::HashMap<String, usize> = Default::default();
        for f in report.findings.iter().filter(|f| f.severity == "error") {
            *codes.entry(f.code.clone()).or_default() += 1;
        }
        let mut sorted: Vec<_> = codes.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!("top error codes: {:?}", &sorted[..sorted.len().min(10)]);
    }

    #[test]
    fn scan_matches_expected_rule() {
        // Write a sample file, then scan it with a rule that should fire.
        let dir = std::env::temp_dir().join("yara-scan-test");
        let _ = std::fs::create_dir_all(&dir);
        let sample = dir.join("sample.bin");
        std::fs::write(&sample, b"hello EICAR-like MALWARE token here").unwrap();

        let rules = one(
            "rule finds_malware : demo { strings: $a = \"MALWARE\" condition: $a }\n\
             rule never_fires { strings: $b = \"zzz_not_present_zzz\" condition: $b }",
        );
        let report = scan_sources(
            &rules,
            &CheckOptions::default(),
            sample.to_str().unwrap(),
        )
        .expect("scan ok");

        assert_eq!(report.rules_compiled, 2);
        assert_eq!(report.compile_errors, 0);
        assert_eq!(report.matches.len(), 1, "only one rule should match");
        assert_eq!(report.matches[0].identifier, "finds_malware");
        assert!(report.matches[0].pattern_matches >= 1);
        assert!(report.matches[0].tags.iter().any(|t| t == "demo"));
    }

    #[test]
    fn master_index_is_not_double_compiled() {
        // A feed laid out as an index.yar that `include`s its rule files,
        // sitting alongside those files. Naively compiling every file AND
        // resolving includes would define each rule twice (duplicate-rule
        // errors). The included files must be compiled only via the index.
        let dir = std::env::temp_dir().join("yara-index-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("cases")).unwrap();
        std::fs::write(
            dir.join("cases/a.yar"),
            "rule case_a { strings: $a = \"aaa\" condition: $a }",
        )
        .unwrap();
        std::fs::write(
            dir.join("cases/b.yar"),
            "rule case_b { strings: $b = \"bbb\" condition: $b }",
        )
        .unwrap();
        std::fs::write(
            dir.join("index.yar"),
            "include \"./cases/a.yar\"\ninclude \"./cases/b.yar\"",
        )
        .unwrap();

        let report =
            check_directory(dir.to_str().unwrap(), &CheckOptions::default()).expect("dir check");

        assert!(
            report.compatible,
            "master-index feed should compile cleanly, got errors: {:?}",
            report
                .findings
                .iter()
                .filter(|f| f.severity == "error")
                .collect::<Vec<_>>()
        );
        assert_eq!(report.error_count, 0);
        // index.yar is the only root; the two case files come in via include.
        assert_eq!(report.files_checked, 1);
        assert_eq!(report.included_files, 2);
    }

    #[test]
    fn drift_heuristics_flag_risky_constructs() {
        let rule = r#"
rule drifty {
    strings:
        $re = /foo.*bar/
        $b = "payload" base64
    condition:
        // comment: uint32(filesize) should be ignored here
        uint32(filesize - 4) == 0x1234 and #re > 2
}
"#;
        let report = check(&one(rule), &CheckOptions::default());
        let kinds: std::collections::HashSet<_> =
            report.drift_risk.iter().map(|f| f.code.as_str()).collect();
        assert!(kinds.contains("DRIFT-REGEX"), "kinds={:?}", kinds);
        assert!(kinds.contains("DRIFT-BASE64"), "kinds={:?}", kinds);
        // High-signal only: count/offset and filesize reads are NOT flagged
        // (their semantics are unchanged between YARA and YARA-X).
        assert!(!kinds.contains("DRIFT-FILESIZE-READ"), "kinds={:?}", kinds);
        assert!(!kinds.contains("DRIFT-COUNT-OFFSET"), "kinds={:?}", kinds);
        // Every drift finding carries severity "drift" and a line number.
        assert!(report
            .drift_risk
            .iter()
            .all(|f| f.severity == "drift" && f.line.is_some()));
    }

    #[test]
    fn clean_rule_has_no_drift_risk() {
        let report = check(
            &one("rule c { strings: $a = \"literal\" condition: $a }"),
            &CheckOptions::default(),
        );
        assert!(report.drift_risk.is_empty(), "{:?}", report.drift_risk);
    }

    #[test]
    fn unused_pattern_behavior() {
        // In YARA (classic) an unreferenced string is tolerated. This test
        // documents what YARA-X actually does with it, whatever that is.
        let report = check(
            &one("rule w { strings: $a = \"unused\" condition: true }"),
            &CheckOptions::default(),
        );
        eprintln!(
            "unused-pattern => compatible={} errors={} warnings={}",
            report.compatible, report.error_count, report.warning_count
        );
        for f in &report.findings {
            eprintln!("  [{}] {} — {}", f.severity, f.code, f.title);
        }
        // The tool's job is to surface it either way.
        assert!(report.error_count + report.warning_count >= 1);
    }
}

