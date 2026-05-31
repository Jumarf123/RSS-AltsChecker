use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::viewer::{ParsedFileContent, ScanResult, WalOperationKind};

#[derive(Debug, Clone)]
pub struct ReadableRecord {
    pub key_raw: Vec<u8>,
    pub value_raw: Vec<u8>,
    pub key_text: String,
    pub value_preview: String,
    pub value_full: String,
    pub sequence: u64,
    pub source: String,
}

pub fn export_scan_to_file(scan: &ScanResult, output_path: &Path) -> Result<usize, String> {
    let lines = build_scan_export_lines(scan);
    let mut content = String::new();
    for line in &lines {
        content.push_str(line);
        content.push('\n');
    }

    fs::write(output_path, content)
        .map_err(|e| format!("Failed to write {}: {e}", output_path.display()))?;
    Ok(lines.len())
}

#[derive(Debug)]
struct Operation {
    sequence: u64,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    source: String,
}

#[derive(Debug)]
struct ActiveRecord {
    sequence: u64,
    value: Vec<u8>,
    source: String,
}

pub fn build_readable_records(scan: &ScanResult, preview_chars: usize) -> Vec<ReadableRecord> {
    let mut operations = collect_operations(scan);
    operations.sort_by(|a, b| {
        a.sequence
            .cmp(&b.sequence)
            .then_with(|| a.source.cmp(&b.source))
    });

    let mut active = BTreeMap::<Vec<u8>, ActiveRecord>::new();
    for operation in operations {
        match operation.value {
            Some(value) => {
                active.insert(
                    operation.key,
                    ActiveRecord {
                        sequence: operation.sequence,
                        value,
                        source: operation.source,
                    },
                );
            }
            None => {
                active.remove(&operation.key);
            }
        }
    }

    active
        .into_iter()
        .map(|(key, entry)| {
            let key_text = decode_key_text(&key);
            let value_full = decode_value_full(&entry.value);
            let value_preview = preview_text(&value_full, preview_chars);
            ReadableRecord {
                key_raw: key,
                value_raw: entry.value,
                key_text,
                value_preview,
                value_full,
                sequence: entry.sequence,
                source: entry.source,
            }
        })
        .collect()
}

pub fn decode_key_text(bytes: &[u8]) -> String {
    if let Some(text) = try_clean_utf8(bytes) {
        return normalize_key_text(&text);
    }

    if let Some(pos) = find_delimiter(bytes, &[0, 1]) {
        let left = &bytes[..pos];
        let right = &bytes[pos + 2..];
        if let (Some(a), Some(b)) = (try_clean_utf8(left), try_clean_utf8(right)) {
            if !a.is_empty() || !b.is_empty() {
                return format!("{} :: {}", normalize_key_text(&a), normalize_key_text(&b));
            }
        }
    }

    format!(
        "binary key [{} bytes] | ascii={}",
        bytes.len(),
        ascii_fallback(bytes, 64)
    )
}

fn normalize_key_text(value: &str) -> String {
    value.replace("/^0", " | ").replace("^0", " | ")
}

pub fn decode_value_full(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }

    for candidate in text_candidates(bytes) {
        if let Some(text) = try_clean_utf8(candidate) {
            if looks_encoded_blob(&text) {
                return format!("encoded text blob [{} chars]", text.chars().count());
            }
            if let Some(pretty_json) = pretty_json(&text) {
                return pretty_json;
            }
            return text;
        }
    }

    let ascii = ascii_fallback(bytes, 96);
    format!(
        "binary value [{} bytes]; ascii preview: {}",
        bytes.len(),
        ascii
    )
}

fn build_scan_export_lines(scan: &ScanResult) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!("scan_target: {}", scan.target.display()));
    for warning in &scan.warnings {
        out.push(format!("scan_warning: {warning}"));
    }
    out.push(String::new());

    for file in &scan.files {
        let file_name = file
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>");

        match &file.content {
            ParsedFileContent::TextLog(text) => {
                out.push(format!("=== FILE: {file_name} [LOG] ==="));
                for (line_idx, line) in text.lines.iter().enumerate() {
                    out.push(format!("{:>6} | {}", line_idx + 1, line));
                }
                out.push(String::new());
            }
            ParsedFileContent::Wal(wal) => {
                out.push(format!("=== FILE: {file_name} [WAL] ==="));
                for warning in &wal.warnings {
                    out.push(format!("warning | {warning}"));
                }

                for (batch_idx, batch) in wal.batches.iter().enumerate() {
                    let batch_prefix = format!(
                        "batch={} offset={} fragments={} checksum={}",
                        batch_idx + 1,
                        batch.offset,
                        batch.fragments,
                        if batch.checksum_ok { "ok" } else { "bad" }
                    );

                    if let Some(parse_error) = &batch.parse_error {
                        out.push(format!("{batch_prefix} | parse_error={parse_error}"));
                        continue;
                    }

                    let sequence_start = batch.sequence.unwrap_or_default();
                    for (op_idx, op) in batch.operations.iter().enumerate() {
                        let sequence = sequence_start.saturating_add(op_idx as u64);
                        let key_text = normalize_line_text(&decode_key_text(&op.key));
                        match op.kind {
                            WalOperationKind::Put => {
                                let value_text = op
                                    .value
                                    .as_deref()
                                    .map(decode_value_full)
                                    .unwrap_or_else(|| "<missing>".to_string());
                                let value_text = normalize_line_text(&value_text);
                                out.push(format!(
                                    "{batch_prefix} | seq={sequence} | PUT | key={key_text} | value={value_text}"
                                ));
                            }
                            WalOperationKind::Delete => {
                                out.push(format!(
                                    "{batch_prefix} | seq={sequence} | DELETE | key={key_text}"
                                ));
                            }
                        }
                    }
                }
                out.push(String::new());
            }
            ParsedFileContent::Ldb(ldb) => {
                out.push(format!("=== FILE: {file_name} [LDB] ==="));
                for warning in &ldb.warnings {
                    out.push(format!("warning | {warning}"));
                }

                for (entry_idx, entry) in ldb.entries.iter().enumerate() {
                    let key_text = normalize_line_text(&decode_key_text(&entry.user_key));
                    if entry.value_type == 0 {
                        out.push(format!(
                            "entry={} | seq={} | DELETE | key={key_text}",
                            entry_idx + 1,
                            entry.sequence
                        ));
                    } else {
                        let value_text = normalize_line_text(&decode_value_full(&entry.value));
                        out.push(format!(
                            "entry={} | seq={} | PUT | key={key_text} | value={value_text}",
                            entry_idx + 1,
                            entry.sequence
                        ));
                    }
                }
                out.push(String::new());
            }
            ParsedFileContent::Error(message) => {
                out.push(format!("=== FILE: {file_name} [ERROR] ==="));
                out.push(message.clone());
                out.push(String::new());
            }
        }
    }

    out
}

fn collect_operations(scan: &ScanResult) -> Vec<Operation> {
    let mut operations = Vec::new();

    for file in &scan.files {
        let source = file
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_string();

        match &file.content {
            ParsedFileContent::Ldb(ldb) => {
                for entry in &ldb.entries {
                    let value = if entry.value_type == 0 {
                        None
                    } else {
                        Some(entry.value.clone())
                    };
                    operations.push(Operation {
                        sequence: entry.sequence,
                        key: entry.user_key.clone(),
                        value,
                        source: source.clone(),
                    });
                }
            }
            ParsedFileContent::Wal(wal) => {
                for batch in &wal.batches {
                    let Some(start_sequence) = batch.sequence else {
                        continue;
                    };
                    for (op_index, operation) in batch.operations.iter().enumerate() {
                        let sequence = start_sequence.saturating_add(op_index as u64);
                        match operation.kind {
                            WalOperationKind::Put => {
                                let Some(value) = operation.value.clone() else {
                                    continue;
                                };
                                operations.push(Operation {
                                    sequence,
                                    key: operation.key.clone(),
                                    value: Some(value),
                                    source: source.clone(),
                                });
                            }
                            WalOperationKind::Delete => operations.push(Operation {
                                sequence,
                                key: operation.key.clone(),
                                value: None,
                                source: source.clone(),
                            }),
                        }
                    }
                }
            }
            ParsedFileContent::TextLog(_) | ParsedFileContent::Error(_) => {}
        }
    }

    operations
}

fn text_candidates(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    out.push(bytes);
    if bytes.len() > 1 && (bytes[0] == 0x01 || bytes[0] == 0x00 || bytes[0] == 0x08) {
        out.push(&bytes[1..]);
    }
    out
}

fn try_clean_utf8(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !is_readable_text(text) {
        return None;
    }
    Some(text.trim_matches('\0').to_string())
}

fn is_readable_text(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }

    text.chars()
        .all(|ch| ch == '\n' || ch == '\r' || ch == '\t' || !ch.is_control())
}

fn pretty_json(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }

    let parsed: Value = serde_json::from_str(trimmed).ok()?;
    let sanitized = sanitize_json(parsed);
    serde_json::to_string_pretty(&sanitized).ok()
}

fn sanitize_json(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, sanitize_json(value)))
                .collect(),
        ),
        Value::Array(array) => Value::Array(array.into_iter().map(sanitize_json).collect()),
        Value::String(text) => {
            if looks_encoded_blob(&text) {
                Value::String(format!("<encoded blob: {} chars>", text.chars().count()))
            } else {
                Value::String(text)
            }
        }
        other => other,
    }
}

fn looks_encoded_blob(text: &str) -> bool {
    if text.chars().count() < 180 {
        return false;
    }

    let mut total = 0usize;
    let mut blob_like = 0usize;
    for ch in text.chars() {
        total += 1;
        if ch.is_ascii_alphanumeric()
            || ch == '+'
            || ch == '/'
            || ch == '='
            || ch == '-'
            || ch == '_'
        {
            blob_like += 1;
        }
    }

    total > 0 && blob_like * 100 / total >= 88
}

fn preview_text(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let single_line = text.replace('\n', " ").replace('\r', " ");
    let mut out = String::new();
    let mut count = 0usize;
    for ch in single_line.chars() {
        if count == max_chars {
            out.push_str("...");
            break;
        }
        out.push(ch);
        count += 1;
    }
    out
}

fn normalize_line_text(text: &str) -> String {
    text.replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

fn find_delimiter(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn ascii_fallback(bytes: &[u8], max_bytes: usize) -> String {
    bytes
        .iter()
        .take(max_bytes)
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                char::from(*b)
            } else {
                '.'
            }
        })
        .collect()
}
