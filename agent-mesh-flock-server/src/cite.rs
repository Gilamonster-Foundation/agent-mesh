//! The id of a cited file: the one rule the citer and the checker share, so
//! "the file is as cited" means the same bytes hashed the same way on both
//! sides.

use content_addressable::RawContentId;
use std::fs::File;
use std::io::Read as _;

/// The most bytes read from one file. A bigger file is refused, not hashed as
/// a prefix that would claim something about bytes never read.
pub const MAX_CITED_BYTES: u64 = 64 * 1024 * 1024;

/// Hash what `file` (already opened beneath its root) holds.
///
/// # Errors
/// Why it cannot be cited or checked: not a regular file, too big, or unreadable.
pub fn file_id(file: File) -> Result<RawContentId, String> {
    let meta = file.metadata().map_err(|e| format!("cannot stat: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".to_owned());
    }
    if meta.len() > MAX_CITED_BYTES {
        return Err("file too big to check".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CITED_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read: {e}"))?;
    if bytes.len() as u64 > MAX_CITED_BYTES {
        return Err("file too big to check".to_owned());
    }
    Ok(RawContentId::from_content(&bytes))
}
