// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
mod checker;

use checker::{
    check_directory, check_with_diff, scan_directory, scan_sources, CheckOptions, CheckReport,
    ScanReport, SourceInput,
};
use serde::Deserialize;

/// A source file/blob passed from the frontend.
#[derive(Deserialize)]
struct SourcePayload {
    origin: String,
    content: String,
}

/// Check one or more YARA sources for YARA-X compatibility.
#[tauri::command]
fn check_rules(sources: Vec<SourcePayload>, options: CheckOptionsPayload) -> CheckReport {
    let inputs: Vec<SourceInput> = sources
        .into_iter()
        .map(|s| SourceInput {
            origin: s.origin,
            content: s.content,
        })
        .collect();
    let opts = CheckOptions {
        relaxed_re_syntax: options.relaxed_re_syntax,
        error_on_slow_pattern: options.error_on_slow_pattern,
    };
    check_with_diff(&inputs, &opts)
}

#[derive(Deserialize)]
struct CheckOptionsPayload {
    relaxed_re_syntax: bool,
    error_on_slow_pattern: bool,
}

/// Check every .yar/.yara file under a directory, resolving includes.
#[tauri::command]
fn check_directory_cmd(path: String, options: CheckOptionsPayload) -> Result<CheckReport, String> {
    let opts = CheckOptions {
        relaxed_re_syntax: options.relaxed_re_syntax,
        error_on_slow_pattern: options.error_on_slow_pattern,
    };
    check_directory(&path, &opts)
}

/// Scan a sample file with rules compiled from pasted text / loaded files.
#[tauri::command]
fn scan_file_cmd(
    sources: Vec<SourcePayload>,
    options: CheckOptionsPayload,
    data_path: String,
) -> Result<ScanReport, String> {
    let inputs: Vec<SourceInput> = sources
        .into_iter()
        .map(|s| SourceInput {
            origin: s.origin,
            content: s.content,
        })
        .collect();
    let opts = CheckOptions {
        relaxed_re_syntax: options.relaxed_re_syntax,
        error_on_slow_pattern: options.error_on_slow_pattern,
    };
    scan_sources(&inputs, &opts, &data_path)
}

/// Scan a sample file with rules compiled from a folder (includes resolved).
#[tauri::command]
fn scan_directory_cmd(
    rule_dir: String,
    options: CheckOptionsPayload,
    data_path: String,
) -> Result<ScanReport, String> {
    let opts = CheckOptions {
        relaxed_re_syntax: options.relaxed_re_syntax,
        error_on_slow_pattern: options.error_on_slow_pattern,
    };
    scan_directory(&rule_dir, &opts, &data_path)
}

/// Report which YARA-X version the app is linked against.
#[tauri::command]
fn yara_x_version() -> String {
    yara_x::VERSION.to_string()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            check_rules,
            check_directory_cmd,
            scan_file_cmd,
            scan_directory_cmd,
            yara_x_version
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
