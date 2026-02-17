use anyhow::Result;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// JSON output style
pub enum JsonStyle {
    /// Compact one-line JSON
    Compact,
    /// Pretty printed (indented) JSON
    Pretty,
}

/// Save any serializable data to a JSON file.
pub fn save_json_output<T: Serialize>(data: &T, out_path: &Path, style: JsonStyle) -> Result<()> {
    // Serialize depending on style
    let json = match style {
        JsonStyle::Compact => serde_json::to_string(data)?,
        JsonStyle::Pretty => serde_json::to_string_pretty(data)?,
    };

    // Write to file (create or truncate)
    let mut file = File::create(out_path)?;
    file.write_all(json.as_bytes())?;
    file.flush()?; // ensure it's written

    Ok(())
}
