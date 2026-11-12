import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { getVersion } from "@tauri-apps/api/app";

// Cap how many finding cards we render at once; a 15k-rule feed can produce
// thousands. The counts in the summary are always exact.
const MAX_RENDERED = 300;

interface Finding {
  severity: "error" | "warning" | "drift";
  code: string;
  title: string;
  origin: string | null;
  line: number | null;
  column: number | null;
  report: string;
}

interface CheckReport {
  compatible: boolean;
  error_count: number;
  warning_count: number;
  findings: Finding[];
  strict_risk: Finding[];
  strict_checked: boolean;
  drift_risk: Finding[];
  files_checked: number;
  included_files: number;
  yara_x_version: string;
  options: { relaxed_re_syntax: boolean; error_on_slow_pattern: boolean };
}

interface RuleMatch {
  identifier: string;
  namespace: string;
  tags: string[];
  pattern_matches: number;
}

interface ScanReport {
  scanned_file: string;
  file_size: number;
  rules_compiled: number;
  compile_errors: number;
  matches: RuleMatch[];
  yara_x_version: string;
}

interface LoadedFile {
  origin: string;
  content: string;
}

// Files added via the picker. When empty, we check the textarea instead.
let loadedFiles: LoadedFile[] = [];

// When the last check was a folder scan, remember the folder so "scan a
// sample" recompiles from the same rules (with includes). Null = use the
// textarea / loaded files instead.
let lastRuleDir: string | null = null;

// Whether a compatibility check has run. Scanning a sample requires validated
// rules, so we gate the scan on this and prompt the user otherwise.
let hasChecked = false;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

window.addEventListener("DOMContentLoaded", () => {
  // Show the app's own version (from tauri.conf.json) next to the brand.
  getVersion()
    .then((v) => ($("app-version").textContent = `v${v}`))
    .catch(() => {});

  // Show which YARA-X version we're linked against.
  invoke<string>("yara_x_version")
    .then((v) => ($("engine-badge").textContent = `YARA-X ${v}`))
    .catch(() => ($("engine-badge").textContent = "YARA-X (unknown)"));

  $<HTMLButtonElement>("run").addEventListener("click", runCheck);
  $<HTMLButtonElement>("clear").addEventListener("click", clearAll);
  $<HTMLButtonElement>("load-files").addEventListener("click", pickFiles);
  $<HTMLButtonElement>("load-folder").addEventListener("click", scanFolder);
  $<HTMLButtonElement>("scan-file").addEventListener("click", scanSample);
});

// Scan an entire folder of rules on disk (Rust walks it and resolves
// `include` statements relative to the folder — mirrors `yr compile <dir>`).
async function scanFolder() {
  const selected = await open({ directory: true, multiple: false });
  if (!selected || Array.isArray(selected)) return;

  const options = readOptions();
  flashVerdict(
    "empty",
    "Scanning folder…",
    "Compiling every .yar/.yara file (twice, for the strict diff). Large rule sets can take a while."
  );
  const runBtn = $<HTMLButtonElement>("run");
  runBtn.disabled = true;

  try {
    const report = await invoke<CheckReport>("check_directory_cmd", {
      path: selected,
      options,
    });
    lastRuleDir = selected;
    renderReport(report);
  } catch (e) {
    flashVerdict("fail", "Scan failed", String(e));
  } finally {
    runBtn.disabled = false;
  }
}

function readOptions() {
  return {
    relaxed_re_syntax: ($("opt-relaxed") as HTMLInputElement).checked,
    error_on_slow_pattern: ($("opt-slow") as HTMLInputElement).checked,
  };
}

function clearAll() {
  ($("rules") as HTMLTextAreaElement).value = "";
  loadedFiles = [];
  renderFileList();
  resetResults();
}

function pickFiles() {
  // Standard file input works inside the Tauri webview and needs no extra
  // plugin/capability. Content is read in JS and passed to Rust as text.
  const input = document.createElement("input");
  input.type = "file";
  input.multiple = true;
  input.accept = ".yar,.yara,.txt";
  input.addEventListener("change", async () => {
    const files = Array.from(input.files ?? []);
    for (const f of files) {
      const content = await f.text();
      loadedFiles.push({ origin: f.name, content });
    }
    renderFileList();
  });
  input.click();
}

function renderFileList() {
  const el = $("file-list");
  if (loadedFiles.length === 0) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  el.innerHTML =
    `<div class="file-list-head">${loadedFiles.length} file(s) — the textarea is ignored while files are loaded</div>` +
    loadedFiles
      .map(
        (f, i) =>
          `<span class="chip">${escapeHtml(f.origin)}<button data-i="${i}" class="chip-x" title="remove">×</button></span>`
      )
      .join("");
  el.querySelectorAll<HTMLButtonElement>(".chip-x").forEach((b) =>
    b.addEventListener("click", () => {
      loadedFiles.splice(Number(b.dataset.i), 1);
      renderFileList();
    })
  );
}

function collectSources(): LoadedFile[] {
  if (loadedFiles.length > 0) return loadedFiles;
  const text = ($("rules") as HTMLTextAreaElement).value;
  if (text.trim() === "") return [];
  return [{ origin: "pasted-rules.yar", content: text }];
}

async function runCheck() {
  const sources = collectSources();
  if (sources.length === 0) {
    flashVerdict("empty", "Nothing to check", "Paste rules or add a file first.");
    return;
  }

  const options = readOptions();

  const runBtn = $<HTMLButtonElement>("run");
  runBtn.disabled = true;
  runBtn.textContent = "Checking…";

  try {
    const report = await invoke<CheckReport>("check_rules", { sources, options });
    lastRuleDir = null;
    renderReport(report);
  } catch (e) {
    flashVerdict("fail", "Check failed", String(e));
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Check compatibility";
  }
}

function renderReport(report: CheckReport) {
  // Verdict banner
  const verdict = $("verdict");
  verdict.className = "verdict " + (report.compatible ? "pass" : "fail");
  const icon = report.compatible ? "✓" : "✕";
  const headline = report.compatible
    ? report.warning_count > 0
      ? "Compatible — with warnings"
      : "Compatible"
    : "Not compatible";
  let sub = report.compatible
    ? "Compiles on YARA-X. The sensor accepts this ruleset."
    : "The sensor will reject this ruleset until every error is fixed.";
  if (report.files_checked > 1 || report.included_files > 0) {
    sub += ` (${report.files_checked} file${report.files_checked === 1 ? "" : "s"} checked`;
    if (report.included_files > 0) {
      sub += `, ${report.included_files} pulled in via include`;
    }
    sub += ")";
  }
  verdict.innerHTML = `<div class="verdict-icon">${icon}</div>
    <div class="verdict-text"><strong>${headline}</strong><span>${escapeHtml(sub)}</span></div>`;

  // Summary counts
  const summary = $("summary");
  summary.hidden = false;
  $("stat-errors").textContent = String(report.error_count);
  $("stat-warnings").textContent = String(report.warning_count);
  const riskStat = $("stat-risk-wrap");
  if (report.strict_checked) {
    riskStat.hidden = false;
    $("stat-risk").textContent = String(report.strict_risk.length);
  } else {
    riskStat.hidden = true;
  }
  const driftStat = $("stat-drift-wrap");
  if (report.drift_risk && report.drift_risk.length > 0) {
    driftStat.hidden = false;
    $("stat-drift").textContent = String(report.drift_risk.length);
  } else {
    driftStat.hidden = true;
  }

  // Findings, errors first
  const findings = [...report.findings].sort((a, b) =>
    a.severity === b.severity ? 0 : a.severity === "error" ? -1 : 1
  );
  const container = $("findings");
  let html = "";
  if (findings.length === 0) {
    html += `<div class="no-findings">No compile issues found. 🎉</div>`;
  } else {
    const shown = findings.slice(0, MAX_RENDERED);
    if (findings.length > MAX_RENDERED) {
      html += `<div class="cap-note">Showing the first ${MAX_RENDERED} of ${findings.length} findings. The counts above are exact.</div>`;
    }
    html += shown.map((f) => findingHtml(f, f.severity)).join("");
  }

  // Relaxed-mode dependency section (cyan) — rules that only compile because
  // --relaxed-re-syntax is enabled and would break under strict parsing.
  if (report.strict_checked && report.strict_risk.length > 0) {
    html += `<div class="risk-section">
      <div class="risk-head">Relaxed-mode dependencies · ${report.strict_risk.length}</div>
      <p class="risk-note">These compile fine on the sensor, but only because it
        runs with <code>--relaxed-re-syntax</code>. They use regex syntax that
        strict YARA-X rejects. <strong>No action required for v29.3</strong> —
        fixing them is optional cleanup for a stricter / more portable ruleset.</p>
      ${report.strict_risk
        .slice(0, MAX_RENDERED)
        .map((f) => findingHtml(f, "risk"))
        .join("")}
      ${
        report.strict_risk.length > MAX_RENDERED
          ? `<div class="cap-note">Showing the first ${MAX_RENDERED} of ${report.strict_risk.length}.</div>`
          : ""
      }
    </div>`;
  }

  // Semantic-drift section (violet) — layer-2 static heuristics. These rules
  // COMPILE fine; the concern is that YARA-X may MATCH differently at runtime
  // than classic YARA did. Heuristic only: it flags constructs known to have
  // subtle behavior changes, but cannot confirm a real drift without running
  // both engines against the same data.
  if (report.drift_risk && report.drift_risk.length > 0) {
    html += `<div class="drift-section">
      <div class="drift-head">Possible semantic drift · ${report.drift_risk.length}</div>
      <p class="drift-note">These rules compile, but use constructs whose
        <strong>match behavior can differ</strong> between classic YARA and
        YARA-X — regex greediness/anchoring (different engine) and
        <code>base64</code>/<code>base64wide</code> alphabet &amp; padding
        handling. This is a <strong>heuristic flag, not a confirmed break</strong> —
        verify by scanning known samples with both engines before relying on the rule.</p>
      ${report.drift_risk
        .slice(0, MAX_RENDERED)
        .map((f) => findingHtml(f, "drift"))
        .join("")}
      ${
        report.drift_risk.length > MAX_RENDERED
          ? `<div class="cap-note">Showing the first ${MAX_RENDERED} of ${report.drift_risk.length}.</div>`
          : ""
      }
    </div>`;
  }
  container.innerHTML = html;

  // Rules have been validated; the sample-scan panel (always visible at the
  // bottom) can now compile them and run a real scan. Clear any stale results.
  hasChecked = true;
  $("scan-results").innerHTML = "";
}

// Scan a sample file with the rules from the most recent check. Uses the same
// source (folder vs. textarea/files) so the compiled ruleset matches exactly.
async function scanSample() {
  // Require validated rules first — scanning is meaningless without a ruleset
  // we know compiles on YARA-X.
  if (!hasChecked) {
    $("scan-results").innerHTML = `<div class="scan-hint">Validate your rules first: paste or load rules and click <strong>Check compatibility</strong> (or <strong>Scan folder…</strong>), then scan a sample.</div>`;
    return;
  }

  const selected = await open({ multiple: false });
  if (!selected || Array.isArray(selected)) return;

  const options = readOptions();
  const btn = $<HTMLButtonElement>("scan-file");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  $("scan-results").innerHTML = `<div class="cap-note">Scanning…</div>`;

  try {
    let report: ScanReport;
    if (lastRuleDir) {
      report = await invoke<ScanReport>("scan_directory_cmd", {
        ruleDir: lastRuleDir,
        options,
        dataPath: selected,
      });
    } else {
      const sources = collectSources();
      if (sources.length === 0) {
        $("scan-results").innerHTML = `<div class="cap-note">No rules loaded to scan with.</div>`;
        return;
      }
      report = await invoke<ScanReport>("scan_file_cmd", {
        sources,
        options,
        dataPath: selected,
      });
    }
    renderScan(report);
  } catch (e) {
    $("scan-results").innerHTML = `<div class="cap-note">Scan failed: ${escapeHtml(String(e))}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan a file…";
  }
}

function renderScan(report: ScanReport) {
  const kb = (report.file_size / 1024).toFixed(1);
  const matched = report.matches.length;
  const head = `<div class="scan-summary">
      <span class="scan-file">${escapeHtml(report.scanned_file)}</span>
      <span class="scan-meta">${kb} KB · ${report.rules_compiled} rule(s) compiled${
    report.compile_errors > 0
      ? ` · <span class="scan-warn">${report.compile_errors} rule(s) dropped (compile errors)</span>`
      : ""
  }</span>
    </div>`;

  let body: string;
  if (matched === 0) {
    body = `<div class="scan-none">No rules matched this sample.</div>`;
  } else {
    body =
      `<div class="scan-hits-head">${matched} rule(s) matched</div>` +
      report.matches
        .slice(0, MAX_RENDERED)
        .map(
          (m) => `<article class="scan-hit">
            <span class="hit-id">${escapeHtml(m.identifier)}</span>
            ${
              m.namespace && m.namespace !== "default"
                ? `<span class="hit-ns">${escapeHtml(m.namespace)}</span>`
                : ""
            }
            ${m.tags.map((t) => `<span class="hit-tag">${escapeHtml(t)}</span>`).join("")}
            <span class="hit-count">${m.pattern_matches} pattern match(es)</span>
          </article>`
        )
        .join("") +
      (matched > MAX_RENDERED
        ? `<div class="cap-note">Showing the first ${MAX_RENDERED} of ${matched}.</div>`
        : "");
  }
  $("scan-results").innerHTML = head + body;
}

// `variant` controls the color/label: "error", "warning", or "risk"
// (relaxed-mode dependency, rendered cyan).
function findingHtml(f: Finding, variant: string): string {
  const loc = [f.origin, f.line != null ? `line ${f.line}` : null]
    .filter(Boolean)
    .join(" · ");
  const label =
    variant === "risk" ? "strict-risk" : variant === "drift" ? "drift-risk" : variant;
  return `<article class="finding ${variant}">
    <div class="finding-head">
      <span class="sev">${label}</span>
      <span class="code">${escapeHtml(f.code)}</span>
      <span class="title">${escapeHtml(f.title)}</span>
    </div>
    ${loc ? `<div class="loc">${escapeHtml(loc)}</div>` : ""}
    <pre class="report">${escapeHtml(f.report)}</pre>
  </article>`;
}

function flashVerdict(kind: string, headline: string, sub: string) {
  const verdict = $("verdict");
  verdict.className = "verdict " + kind;
  verdict.innerHTML = `<div class="verdict-icon">!</div>
    <div class="verdict-text"><strong>${escapeHtml(headline)}</strong><span>${escapeHtml(sub)}</span></div>`;
  $("summary").hidden = true;
  $("findings").innerHTML = "";
  $("scan-results").innerHTML = "";
}

function resetResults() {
  const verdict = $("verdict");
  verdict.className = "verdict empty";
  verdict.innerHTML = `<div class="verdict-icon">▷</div>
    <div class="verdict-text"><strong>No results yet</strong><span>Paste rules and click “Check compatibility”.</span></div>`;
  $("summary").hidden = true;
  $("findings").innerHTML = "";
  hasChecked = false;
  $("scan-results").innerHTML = "";
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
