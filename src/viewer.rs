use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const WAL_BLOCK_SIZE: usize = 32 * 1024;
const WAL_HEADER_SIZE: usize = 7;
const MAX_REASONABLE_ENTRY_COUNT: u32 = 1_000_000;
const TABLE_FOOTER_SIZE: usize = 48;
const TABLE_MAGIC_NUMBER: u64 = 0xdb47_7524_8b80_fb57;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub target: PathBuf,
    pub files: Vec<ParsedFile>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub path: PathBuf,
    pub content: ParsedFileContent,
}

#[derive(Debug, Clone)]
pub enum ParsedFileContent {
    TextLog(TextLogFile),
    Wal(WalFile),
    Ldb(LdbFile),
    Error(String),
}

#[derive(Debug, Clone)]
pub struct TextLogFile {
    pub lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WalFile {
    pub physical_records: usize,
    pub logical_records: usize,
    pub warnings: Vec<String>,
    pub batches: Vec<WalBatch>,
}

#[derive(Debug, Clone)]
pub struct WalBatch {
    pub offset: usize,
    pub payload_bytes: usize,
    pub fragments: usize,
    pub checksum_ok: bool,
    pub sequence: Option<u64>,
    pub declared_count: Option<u32>,
    pub trailing_bytes: usize,
    pub parse_error: Option<String>,
    pub operations: Vec<WalOperation>,
}

#[derive(Debug, Clone)]
pub struct WalOperation {
    pub kind: WalOperationKind,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalOperationKind {
    Put,
    Delete,
}

#[derive(Debug, Clone)]
pub struct LdbFile {
    pub index_entries: usize,
    pub data_blocks: usize,
    pub warnings: Vec<String>,
    pub entries: Vec<LdbEntry>,
}

#[derive(Debug, Clone)]
pub struct LdbEntry {
    pub user_key: Vec<u8>,
    pub sequence: u64,
    pub value_type: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileCategory {
    TextLog,
    Wal,
    Ldb,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalRecordType {
    Full,
    First,
    Middle,
    Last,
}

impl WalRecordType {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Full),
            2 => Some(Self::First),
            3 => Some(Self::Middle),
            4 => Some(Self::Last),
            _ => None,
        }
    }

    #[cfg(test)]
    fn as_byte(self) -> u8 {
        match self {
            Self::Full => 1,
            Self::First => 2,
            Self::Middle => 3,
            Self::Last => 4,
        }
    }
}

#[derive(Debug, Clone)]
struct WalPhysicalRecord {
    offset: usize,
    record_type: WalRecordType,
    payload: Vec<u8>,
    checksum_ok: bool,
}

#[derive(Debug)]
struct WalPhysicalParseResult {
    records: Vec<WalPhysicalRecord>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct WalLogicalRecord {
    offset: usize,
    payload: Vec<u8>,
    checksum_ok: bool,
    fragments: usize,
}

#[derive(Debug)]
struct WalLogicalParseResult {
    records: Vec<WalLogicalRecord>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchOperationKind {
    Put,
    Delete,
}

#[derive(Debug, Clone)]
struct BatchOperation {
    kind: BatchOperationKind,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

#[derive(Debug)]
struct WriteBatch {
    sequence: u64,
    declared_count: u32,
    operations: Vec<BatchOperation>,
    trailing_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
struct BlockHandle {
    offset: u64,
    size: u64,
}

#[derive(Debug)]
struct TableBlockRead {
    data: Vec<u8>,
    checksum_ok: bool,
}

#[derive(Debug, Clone)]
struct BlockEntry {
    key: Vec<u8>,
    value: Vec<u8>,
}

pub fn scan_target(target: &Path) -> Result<ScanResult, String> {
    if !target.exists() {
        return Err(format!("Path does not exist: {}", target.display()));
    }

    let mut warnings = Vec::new();
    let mut files = Vec::new();

    if target.is_file() {
        files.push(parse_file(target.to_path_buf()));
    } else if target.is_dir() {
        let mut discovered = Vec::new();
        for entry in fs::read_dir(target)
            .map_err(|e| format!("Failed to read directory {}: {e}", target.display()))?
        {
            let entry = entry.map_err(|e| {
                format!(
                    "Failed to inspect directory entry in {}: {e}",
                    target.display()
                )
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let category = classify_file(&path);
            if category != FileCategory::Other {
                discovered.push(path);
            }
        }

        discovered.sort_by_key(|path| sort_key_for_path(path));

        for path in discovered {
            files.push(parse_file(path));
        }

        if files.is_empty() {
            warnings.push(format!(
                "No supported files found in {}. Expected LOG*, *.log, *.ldb.",
                target.display()
            ));
        }
    } else {
        return Err(format!(
            "Path is neither file nor directory: {}",
            target.display()
        ));
    }

    Ok(ScanResult {
        target: target.to_path_buf(),
        files,
        warnings,
    })
}

pub fn format_bytes_for_ui(data: &[u8], max_chars: usize, force_hex: bool) -> String {
    if !force_hex {
        if let Ok(text) = std::str::from_utf8(data) {
            if is_displayable_text(text) {
                let escaped = escape_text(text);
                let (preview, truncated) = truncate_chars(&escaped, max_chars);
                if truncated {
                    return format!("\"{}\"... ({} bytes)", preview, data.len());
                }
                return format!("\"{}\"", preview);
            }
        }
    }

    format_hex_preview(data, max_chars)
}

pub fn file_kind_name(content: &ParsedFileContent) -> &'static str {
    match content {
        ParsedFileContent::TextLog(_) => "LOG",
        ParsedFileContent::Wal(_) => "WAL",
        ParsedFileContent::Ldb(_) => "LDB",
        ParsedFileContent::Error(_) => "ERROR",
    }
}

fn sort_key_for_path(path: &Path) -> (u8, String) {
    let category = classify_file(path);
    let rank = match category {
        FileCategory::TextLog => 0,
        FileCategory::Wal => 1,
        FileCategory::Ldb => 2,
        FileCategory::Other => 3,
    };
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    (rank, name)
}

fn parse_file(path: PathBuf) -> ParsedFile {
    let content = match classify_file(&path) {
        FileCategory::TextLog => match parse_text_log_file(&path) {
            Ok(parsed) => ParsedFileContent::TextLog(parsed),
            Err(err) => ParsedFileContent::Error(err),
        },
        FileCategory::Wal => match parse_wal_file(&path) {
            Ok(parsed) => ParsedFileContent::Wal(parsed),
            Err(err) => ParsedFileContent::Error(err),
        },
        FileCategory::Ldb => match parse_ldb_file(&path) {
            Ok(parsed) => ParsedFileContent::Ldb(parsed),
            Err(err) => ParsedFileContent::Error(err),
        },
        FileCategory::Other => ParsedFileContent::Error("Unsupported file type.".to_string()),
    };

    ParsedFile { path, content }
}

fn classify_file(path: &Path) -> FileCategory {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if is_text_log_name(name) {
        return FileCategory::TextLog;
    }
    if is_wal_log_name(name) {
        return FileCategory::Wal;
    }
    if has_extension(path, "ldb") {
        return FileCategory::Ldb;
    }
    FileCategory::Other
}

fn parse_text_log_file(path: &Path) -> Result<TextLogFile, String> {
    let data =
        fs::read(path).map_err(|e| format!("Failed to read text log {}: {e}", path.display()))?;
    let text = String::from_utf8_lossy(&data);
    let lines = text.lines().map(ToOwned::to_owned).collect();
    Ok(TextLogFile { lines })
}

fn parse_wal_file(path: &Path) -> Result<WalFile, String> {
    let data =
        fs::read(path).map_err(|e| format!("Failed to read WAL file {}: {e}", path.display()))?;

    let physical = parse_wal_physical_records(&data);
    if physical.records.is_empty() {
        return Err(format!(
            "No valid WAL physical records were found in {}.",
            path.display()
        ));
    }
    let logical = assemble_wal_logical_records(&physical.records);

    let mut batches = Vec::with_capacity(logical.records.len());
    for record in logical.records {
        match parse_write_batch(&record.payload) {
            Ok(batch) => {
                let operations = batch
                    .operations
                    .into_iter()
                    .map(|op| WalOperation {
                        kind: match op.kind {
                            BatchOperationKind::Put => WalOperationKind::Put,
                            BatchOperationKind::Delete => WalOperationKind::Delete,
                        },
                        key: op.key,
                        value: op.value,
                    })
                    .collect();
                batches.push(WalBatch {
                    offset: record.offset,
                    payload_bytes: record.payload.len(),
                    fragments: record.fragments,
                    checksum_ok: record.checksum_ok,
                    sequence: Some(batch.sequence),
                    declared_count: Some(batch.declared_count),
                    trailing_bytes: batch.trailing_bytes,
                    parse_error: None,
                    operations,
                });
            }
            Err(err) => {
                batches.push(WalBatch {
                    offset: record.offset,
                    payload_bytes: record.payload.len(),
                    fragments: record.fragments,
                    checksum_ok: record.checksum_ok,
                    sequence: None,
                    declared_count: None,
                    trailing_bytes: 0,
                    parse_error: Some(err),
                    operations: Vec::new(),
                });
            }
        }
    }

    let mut warnings = physical.warnings;
    warnings.extend(logical.warnings);

    Ok(WalFile {
        physical_records: physical.records.len(),
        logical_records: batches.len(),
        warnings,
        batches,
    })
}

fn parse_wal_physical_records(data: &[u8]) -> WalPhysicalParseResult {
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let block_offset = offset % WAL_BLOCK_SIZE;
        let bytes_left_in_block = WAL_BLOCK_SIZE - block_offset;

        if bytes_left_in_block < WAL_HEADER_SIZE {
            offset += bytes_left_in_block;
            continue;
        }

        if offset + WAL_HEADER_SIZE > data.len() {
            break;
        }

        let checksum = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let length = u16::from_le_bytes([data[offset + 4], data[offset + 5]]) as usize;
        let record_type_byte = data[offset + 6];

        if checksum == 0 && length == 0 && record_type_byte == 0 {
            offset += WAL_HEADER_SIZE;
            continue;
        }

        if length > bytes_left_in_block - WAL_HEADER_SIZE {
            warnings.push(format!(
                "Physical record at offset {} has invalid length {} (block remainder {}).",
                offset,
                length,
                bytes_left_in_block - WAL_HEADER_SIZE
            ));
            offset += bytes_left_in_block;
            continue;
        }

        let payload_start = offset + WAL_HEADER_SIZE;
        let payload_end = payload_start + length;
        if payload_end > data.len() {
            warnings.push(format!(
                "Truncated physical record at offset {} (declared {} byte payload).",
                offset, length
            ));
            break;
        }

        let Some(record_type) = WalRecordType::from_byte(record_type_byte) else {
            warnings.push(format!(
                "Unknown WAL record type {} at offset {}.",
                record_type_byte, offset
            ));
            offset = payload_end;
            continue;
        };

        let payload = data[payload_start..payload_end].to_vec();
        let checksum_ok = verify_wal_record_checksum(checksum, record_type_byte, &payload);
        if !checksum_ok {
            warnings.push(format!(
                "Checksum mismatch at offset {}: expected masked CRC {:08x}.",
                offset, checksum
            ));
        }

        records.push(WalPhysicalRecord {
            offset,
            record_type,
            payload,
            checksum_ok,
        });

        offset = payload_end;
    }

    WalPhysicalParseResult { records, warnings }
}

fn assemble_wal_logical_records(physical_records: &[WalPhysicalRecord]) -> WalLogicalParseResult {
    let mut logical_records = Vec::new();
    let mut warnings = Vec::new();
    let mut pending: Option<WalLogicalRecord> = None;

    for record in physical_records {
        match record.record_type {
            WalRecordType::Full => {
                if let Some(open) = pending.take() {
                    warnings.push(format!(
                        "Unterminated fragmented record started at offset {}.",
                        open.offset
                    ));
                }
                logical_records.push(WalLogicalRecord {
                    offset: record.offset,
                    payload: record.payload.clone(),
                    checksum_ok: record.checksum_ok,
                    fragments: 1,
                });
            }
            WalRecordType::First => {
                if let Some(open) = pending.take() {
                    warnings.push(format!(
                        "Discarded unterminated fragmented record started at offset {}.",
                        open.offset
                    ));
                }
                pending = Some(WalLogicalRecord {
                    offset: record.offset,
                    payload: record.payload.clone(),
                    checksum_ok: record.checksum_ok,
                    fragments: 1,
                });
            }
            WalRecordType::Middle => {
                let Some(open) = pending.as_mut() else {
                    warnings.push(format!(
                        "Found MIDDLE fragment without FIRST at offset {}.",
                        record.offset
                    ));
                    continue;
                };
                open.payload.extend_from_slice(&record.payload);
                open.fragments += 1;
                open.checksum_ok &= record.checksum_ok;
            }
            WalRecordType::Last => {
                let Some(mut open) = pending.take() else {
                    warnings.push(format!(
                        "Found LAST fragment without FIRST at offset {}.",
                        record.offset
                    ));
                    continue;
                };
                open.payload.extend_from_slice(&record.payload);
                open.fragments += 1;
                open.checksum_ok &= record.checksum_ok;
                logical_records.push(open);
            }
        }
    }

    if let Some(open) = pending {
        warnings.push(format!(
            "WAL ended while a fragmented record from offset {} was still open.",
            open.offset
        ));
    }

    WalLogicalParseResult {
        records: logical_records,
        warnings,
    }
}

fn parse_write_batch(payload: &[u8]) -> Result<WriteBatch, String> {
    if payload.len() < 12 {
        return Err(format!(
            "WriteBatch payload too short: {} bytes (minimum 12).",
            payload.len()
        ));
    }

    let sequence = u64::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]);
    let declared_count = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);

    if declared_count > MAX_REASONABLE_ENTRY_COUNT {
        return Err(format!(
            "Declared entry count {} is unreasonably large.",
            declared_count
        ));
    }

    let mut position = 12usize;
    let mut operations = Vec::with_capacity(declared_count as usize);

    for index in 0..declared_count {
        let Some(&tag) = payload.get(position) else {
            return Err(format!(
                "Unexpected end of payload before entry {} tag.",
                index + 1
            ));
        };
        position += 1;

        let key = read_length_prefixed_bytes(payload, &mut position, "key")?.to_vec();

        match tag {
            0 => operations.push(BatchOperation {
                kind: BatchOperationKind::Delete,
                key,
                value: None,
            }),
            1 => {
                let value = read_length_prefixed_bytes(payload, &mut position, "value")?.to_vec();
                operations.push(BatchOperation {
                    kind: BatchOperationKind::Put,
                    key,
                    value: Some(value),
                });
            }
            _ => {
                return Err(format!(
                    "Unknown WriteBatch operation tag {} at entry {}.",
                    tag,
                    index + 1
                ))
            }
        }
    }

    let trailing_bytes = payload.len().saturating_sub(position);

    Ok(WriteBatch {
        sequence,
        declared_count,
        operations,
        trailing_bytes,
    })
}

fn parse_ldb_file(path: &Path) -> Result<LdbFile, String> {
    let table =
        fs::read(path).map_err(|e| format!("Failed to read LDB file {}: {e}", path.display()))?;
    if table.len() < TABLE_FOOTER_SIZE {
        return Err(format!(
            "LDB file {} is too small ({} bytes).",
            path.display(),
            table.len()
        ));
    }

    let (metaindex_handle, index_handle) = parse_table_footer(&table)?;
    let mut warnings = Vec::new();

    let index_block = read_table_block(&table, index_handle)?;
    if !index_block.checksum_ok {
        warnings.push("Index block checksum mismatch.".to_string());
    }

    let index_entries = parse_block_entries(&index_block.data)?;
    let index_entry_count = index_entries.len();
    let mut data_blocks = 0usize;
    let mut entries = Vec::new();

    for (entry_index, index_entry) in index_entries.iter().enumerate() {
        let handle = decode_block_handle(&index_entry.value).map_err(|e| {
            format!(
                "Failed to decode block handle in index entry {}: {e}",
                entry_index + 1
            )
        })?;

        let block = read_table_block(&table, handle)?;
        if !block.checksum_ok {
            warnings.push(format!(
                "Data block checksum mismatch for index entry {} (offset {}).",
                entry_index + 1,
                handle.offset
            ));
        }

        data_blocks += 1;

        let data_entries = parse_block_entries(&block.data).map_err(|e| {
            format!(
                "Failed to parse data block {} (offset {}): {e}",
                entry_index + 1,
                handle.offset
            )
        })?;

        for block_entry in data_entries {
            if block_entry.key.len() < 8 {
                warnings.push(format!(
                    "Skipped short internal key ({} bytes) in data block {}.",
                    block_entry.key.len(),
                    entry_index + 1
                ));
                continue;
            }

            let split = block_entry.key.len() - 8;
            let mut tag_bytes = [0u8; 8];
            tag_bytes.copy_from_slice(&block_entry.key[split..]);
            let tag = u64::from_le_bytes(tag_bytes);
            let sequence = tag >> 8;
            let value_type = (tag & 0xff) as u8;

            entries.push(LdbEntry {
                user_key: block_entry.key[..split].to_vec(),
                sequence,
                value_type,
                value: block_entry.value,
            });
        }
    }

    if metaindex_handle.size > 0 {
        let metaindex_block = read_table_block(&table, metaindex_handle)?;
        if !metaindex_block.checksum_ok {
            warnings.push("Metaindex block checksum mismatch.".to_string());
        }
    }

    Ok(LdbFile {
        index_entries: index_entry_count,
        data_blocks,
        warnings,
        entries,
    })
}

fn parse_table_footer(table: &[u8]) -> Result<(BlockHandle, BlockHandle), String> {
    if table.len() < TABLE_FOOTER_SIZE {
        return Err("Table is smaller than the 48-byte footer.".to_string());
    }
    let footer = &table[table.len() - TABLE_FOOTER_SIZE..];
    let mut magic_bytes = [0u8; 8];
    magic_bytes.copy_from_slice(&footer[40..48]);
    let magic = u64::from_le_bytes(magic_bytes);
    if magic != TABLE_MAGIC_NUMBER {
        return Err(format!(
            "Invalid table magic number: expected {:016x}, got {:016x}.",
            TABLE_MAGIC_NUMBER, magic
        ));
    }

    let mut pos = 0usize;
    let metaindex_handle = read_block_handle(footer, &mut pos)?;
    let index_handle = read_block_handle(footer, &mut pos)?;
    Ok((metaindex_handle, index_handle))
}

fn read_block_handle(input: &[u8], position: &mut usize) -> Result<BlockHandle, String> {
    let offset = read_varint64(input, position)?;
    let size = read_varint64(input, position)?;
    Ok(BlockHandle { offset, size })
}

fn decode_block_handle(value: &[u8]) -> Result<BlockHandle, String> {
    let mut pos = 0usize;
    let handle = read_block_handle(value, &mut pos)?;
    Ok(handle)
}

fn read_table_block(table: &[u8], handle: BlockHandle) -> Result<TableBlockRead, String> {
    let offset = usize::try_from(handle.offset)
        .map_err(|_| format!("Block offset does not fit usize: {}", handle.offset))?;
    let size = usize::try_from(handle.size)
        .map_err(|_| format!("Block size does not fit usize: {}", handle.size))?;

    let trailer_offset = offset
        .checked_add(size)
        .ok_or_else(|| "Block offset + size overflowed.".to_string())?;
    let trailer_end = trailer_offset
        .checked_add(5)
        .ok_or_else(|| "Block trailer overflowed.".to_string())?;

    if trailer_end > table.len() {
        return Err(format!(
            "Block (offset {}, size {}) exceeds file length {}.",
            offset,
            size,
            table.len()
        ));
    }

    let data = &table[offset..trailer_offset];
    let compression_type = table[trailer_offset];
    let checksum = u32::from_le_bytes([
        table[trailer_offset + 1],
        table[trailer_offset + 2],
        table[trailer_offset + 3],
        table[trailer_offset + 4],
    ]);

    let checksum_ok = checksum == mask_crc32c(crc32c_with_trailing_byte(data, compression_type));

    let decoded = match compression_type {
        0 => data.to_vec(),
        1 => snappy_decompress(data)?,
        other => {
            return Err(format!(
                "Unsupported block compression type {} at offset {}.",
                other, offset
            ))
        }
    };

    Ok(TableBlockRead {
        data: decoded,
        checksum_ok,
    })
}

fn parse_block_entries(block: &[u8]) -> Result<Vec<BlockEntry>, String> {
    if block.len() < 4 {
        return Err("Block is too short to contain restart metadata.".to_string());
    }

    let mut n_restarts_bytes = [0u8; 4];
    n_restarts_bytes.copy_from_slice(&block[block.len() - 4..]);
    let restart_count = u32::from_le_bytes(n_restarts_bytes) as usize;

    let restart_bytes = restart_count
        .checked_mul(4)
        .ok_or_else(|| "Restart array size overflowed.".to_string())?;
    let metadata_bytes = restart_bytes
        .checked_add(4)
        .ok_or_else(|| "Block metadata size overflowed.".to_string())?;
    if metadata_bytes > block.len() {
        return Err(format!(
            "Invalid restart metadata: restarts={}, block_len={}.",
            restart_count,
            block.len()
        ));
    }

    let data_limit = block.len() - metadata_bytes;
    let mut pos = 0usize;
    let mut current_key = Vec::<u8>::new();
    let mut entries = Vec::new();

    while pos < data_limit {
        let shared = read_varint32(block, &mut pos)? as usize;
        let non_shared = read_varint32(block, &mut pos)? as usize;
        let value_len = read_varint32(block, &mut pos)? as usize;

        if shared > current_key.len() {
            return Err(format!(
                "Shared key prefix {} exceeds previous key length {}.",
                shared,
                current_key.len()
            ));
        }

        let key_end = pos
            .checked_add(non_shared)
            .ok_or_else(|| "Key length overflowed.".to_string())?;
        let value_end = key_end
            .checked_add(value_len)
            .ok_or_else(|| "Value length overflowed.".to_string())?;
        if value_end > data_limit {
            return Err(format!(
                "Truncated block entry: need {} bytes, only {} available in data area.",
                value_end.saturating_sub(pos),
                data_limit.saturating_sub(pos)
            ));
        }

        let mut key = current_key[..shared].to_vec();
        key.extend_from_slice(&block[pos..key_end]);
        let value = block[key_end..value_end].to_vec();

        current_key = key.clone();
        entries.push(BlockEntry { key, value });
        pos = value_end;
    }

    if pos != data_limit {
        return Err(format!(
            "Block entry area did not end on boundary: pos={}, expected={}.",
            pos, data_limit
        ));
    }

    Ok(entries)
}

fn snappy_decompress(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut pos = 0usize;
    let expected_len = read_varint64(input, &mut pos)? as usize;
    let mut out = Vec::with_capacity(expected_len);

    while pos < input.len() {
        let tag = input[pos];
        pos += 1;

        match tag & 0x03 {
            0 => {
                let mut literal_len = (tag >> 2) as usize;
                if literal_len < 60 {
                    literal_len += 1;
                } else {
                    let extra_bytes = literal_len - 59;
                    if extra_bytes > 4 {
                        return Err(format!(
                            "Invalid Snappy literal extra byte count: {}.",
                            extra_bytes
                        ));
                    }
                    if pos + extra_bytes > input.len() {
                        return Err(
                            "Unexpected end of input while reading Snappy literal length."
                                .to_string(),
                        );
                    }
                    let mut len_value = 0usize;
                    for i in 0..extra_bytes {
                        len_value |= usize::from(input[pos + i]) << (8 * i);
                    }
                    pos += extra_bytes;
                    literal_len = len_value + 1;
                }

                if pos + literal_len > input.len() {
                    return Err(format!(
                        "Snappy literal overruns input: need {}, have {}.",
                        literal_len,
                        input.len().saturating_sub(pos)
                    ));
                }
                out.extend_from_slice(&input[pos..pos + literal_len]);
                pos += literal_len;
            }
            1 => {
                if pos >= input.len() {
                    return Err("Unexpected end of input for Snappy COPY_1.".to_string());
                }
                let length = ((usize::from(tag) >> 2) & 0x7) + 4;
                let offset = ((usize::from(tag) & 0xE0) << 3) | usize::from(input[pos]);
                pos += 1;
                snappy_copy_from_output(&mut out, offset, length)?;
            }
            2 => {
                if pos + 2 > input.len() {
                    return Err("Unexpected end of input for Snappy COPY_2.".to_string());
                }
                let length = ((usize::from(tag) >> 2) & 0x3f) + 1;
                let offset = usize::from(u16::from_le_bytes([input[pos], input[pos + 1]]));
                pos += 2;
                snappy_copy_from_output(&mut out, offset, length)?;
            }
            3 => {
                if pos + 4 > input.len() {
                    return Err("Unexpected end of input for Snappy COPY_4.".to_string());
                }
                let length = ((usize::from(tag) >> 2) & 0x3f) + 1;
                let offset = usize::try_from(u32::from_le_bytes([
                    input[pos],
                    input[pos + 1],
                    input[pos + 2],
                    input[pos + 3],
                ]))
                .map_err(|_| "Snappy offset does not fit usize.".to_string())?;
                pos += 4;
                snappy_copy_from_output(&mut out, offset, length)?;
            }
            _ => unreachable!(),
        }
    }

    if out.len() != expected_len {
        return Err(format!(
            "Snappy decoded length mismatch: expected {}, got {}.",
            expected_len,
            out.len()
        ));
    }

    Ok(out)
}

fn snappy_copy_from_output(out: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), String> {
    if offset == 0 {
        return Err("Snappy COPY with zero offset is invalid.".to_string());
    }
    if offset > out.len() {
        return Err(format!(
            "Snappy COPY offset {} exceeds output size {}.",
            offset,
            out.len()
        ));
    }

    for _ in 0..length {
        let source_index = out.len() - offset;
        let byte = out[source_index];
        out.push(byte);
    }
    Ok(())
}

fn read_length_prefixed_bytes<'a>(
    payload: &'a [u8],
    position: &mut usize,
    field_name: &str,
) -> Result<&'a [u8], String> {
    let length = read_varint32(payload, position)? as usize;
    let end = position
        .checked_add(length)
        .ok_or_else(|| format!("{field_name} length overflow"))?;
    if end > payload.len() {
        return Err(format!(
            "Truncated {field_name}: declared {} bytes, only {} remain.",
            length,
            payload.len().saturating_sub(*position)
        ));
    }
    let bytes = &payload[*position..end];
    *position = end;
    Ok(bytes)
}

fn read_varint32(payload: &[u8], position: &mut usize) -> Result<u32, String> {
    let mut value = 0u32;
    let mut shift = 0u32;
    while shift <= 28 {
        let Some(&byte) = payload.get(*position) else {
            return Err("Unexpected end of payload while reading varint32.".to_string());
        };
        *position += 1;

        value |= u32::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(value);
        }
        shift += 7;
    }

    Err("Invalid varint32: too many continuation bytes.".to_string())
}

fn read_varint64(payload: &[u8], position: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while shift <= 63 {
        let Some(&byte) = payload.get(*position) else {
            return Err("Unexpected end of payload while reading varint64.".to_string());
        };
        *position += 1;

        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(value);
        }
        shift += 7;
    }
    Err("Invalid varint64: too many continuation bytes.".to_string())
}

fn verify_wal_record_checksum(stored_masked: u32, record_type: u8, payload: &[u8]) -> bool {
    let computed = mask_crc32c(crc32c_with_leading_byte(record_type, payload));
    stored_masked == computed
}

fn crc32c_with_leading_byte(prefix: u8, payload: &[u8]) -> u32 {
    let mut state = !0u32;
    state = crc32c_extend(state, std::slice::from_ref(&prefix));
    state = crc32c_extend(state, payload);
    !state
}

fn crc32c_with_trailing_byte(payload: &[u8], suffix: u8) -> u32 {
    let mut state = !0u32;
    state = crc32c_extend(state, payload);
    state = crc32c_extend(state, std::slice::from_ref(&suffix));
    !state
}

#[cfg(test)]
fn crc32c(data: &[u8]) -> u32 {
    let state = crc32c_extend(!0u32, data);
    !state
}

fn crc32c_extend(mut state: u32, data: &[u8]) -> u32 {
    for &byte in data {
        state ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(state & 1);
            state = (state >> 1) ^ (0x82f63b78 & mask);
        }
    }
    state
}

fn mask_crc32c(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282ead8)
}

fn is_text_log_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper == "LOG" || upper.starts_with("LOG.")
}

fn is_wal_log_name(name: &str) -> bool {
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    !stem.eq_ignore_ascii_case("LOG") && ext.eq_ignore_ascii_case("log")
}

fn has_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

fn is_displayable_text(value: &str) -> bool {
    value.chars().all(|ch| match ch {
        '\n' | '\r' | '\t' => true,
        _ => !ch.is_control(),
    })
}

fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn truncate_chars(input: &str, max_chars: usize) -> (String, bool) {
    if max_chars == 0 {
        return (String::new(), !input.is_empty());
    }
    let mut out = String::new();
    let mut count = 0usize;
    for ch in input.chars() {
        if count == max_chars {
            return (out, true);
        }
        out.push(ch);
        count += 1;
    }
    (out, false)
}

fn format_hex_preview(data: &[u8], max_chars: usize) -> String {
    let mut max_bytes = max_chars / 2;
    if max_bytes == 0 {
        max_bytes = 1;
    }
    let preview_len = data.len().min(max_bytes);
    let mut hex = String::with_capacity(preview_len * 2);
    for byte in &data[..preview_len] {
        let _ = write!(hex, "{byte:02x}");
    }

    if preview_len < data.len() {
        format!("0x{}... ({} bytes)", hex, data.len())
    } else {
        format!("0x{} ({} bytes)", hex, data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_matches_reference_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn write_batch_put_and_delete_parse() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&7u64.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());

        payload.push(1);
        push_len_prefixed(&mut payload, b"alpha");
        push_len_prefixed(&mut payload, b"one");

        payload.push(0);
        push_len_prefixed(&mut payload, b"beta");

        let batch = parse_write_batch(&payload).expect("batch should parse");
        assert_eq!(batch.sequence, 7);
        assert_eq!(batch.declared_count, 2);
        assert_eq!(batch.operations.len(), 2);
        assert_eq!(batch.operations[0].kind, BatchOperationKind::Put);
        assert_eq!(batch.operations[0].key, b"alpha");
        assert_eq!(
            batch.operations[0].value.as_deref().expect("value missing"),
            b"one"
        );
        assert_eq!(batch.operations[1].kind, BatchOperationKind::Delete);
        assert_eq!(batch.operations[1].key, b"beta");
    }

    #[test]
    fn logical_record_reassembly_for_fragments() {
        let physical = vec![
            WalPhysicalRecord {
                offset: 0,
                record_type: WalRecordType::First,
                payload: b"abc".to_vec(),
                checksum_ok: true,
            },
            WalPhysicalRecord {
                offset: 16,
                record_type: WalRecordType::Middle,
                payload: b"def".to_vec(),
                checksum_ok: true,
            },
            WalPhysicalRecord {
                offset: 32,
                record_type: WalRecordType::Last,
                payload: b"ghi".to_vec(),
                checksum_ok: true,
            },
        ];

        let logical = assemble_wal_logical_records(&physical);
        assert!(logical.warnings.is_empty());
        assert_eq!(logical.records.len(), 1);
        assert_eq!(logical.records[0].payload, b"abcdefghi");
        assert_eq!(logical.records[0].fragments, 3);
    }

    #[test]
    fn physical_record_parse_full_record() {
        let payload = b"xyz".to_vec();
        let record_type = WalRecordType::Full.as_byte();
        let checksum = mask_crc32c(crc32c_with_leading_byte(record_type, &payload));

        let mut wal = Vec::new();
        wal.extend_from_slice(&checksum.to_le_bytes());
        wal.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        wal.push(record_type);
        wal.extend_from_slice(&payload);

        let parsed = parse_wal_physical_records(&wal);
        assert!(parsed.warnings.is_empty());
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].record_type, WalRecordType::Full);
        assert_eq!(parsed.records[0].payload, payload);
        assert!(parsed.records[0].checksum_ok);
    }

    #[test]
    fn snappy_decompresses_literal_only_block() {
        let compressed = b"\x05\x10hello";
        let decoded = snappy_decompress(compressed).expect("snappy decode failed");
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn block_entries_parse_restart_encoded_data() {
        let mut block = Vec::new();
        push_varint32(&mut block, 0);
        push_varint32(&mut block, 3);
        push_varint32(&mut block, 3);
        block.extend_from_slice(b"key");
        block.extend_from_slice(b"val");

        block.extend_from_slice(&0u32.to_le_bytes());
        block.extend_from_slice(&1u32.to_le_bytes());

        let entries = parse_block_entries(&block).expect("parse block entries failed");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, b"key");
        assert_eq!(entries[0].value, b"val");
    }

    fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
        push_varint32(buf, bytes.len() as u32);
        buf.extend_from_slice(bytes);
    }

    fn push_varint32(buf: &mut Vec<u8>, mut value: u32) {
        while value >= 0x80 {
            buf.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        buf.push(value as u8);
    }
}
