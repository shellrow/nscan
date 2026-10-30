use anyhow::{Context, Result};
use serde::Serialize;
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

    // Write beside the destination so replacement is atomic on the same filesystem.
    let parent = out_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(out_path)
        .with_context(|| format!("save JSON output to {}", out_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replaces_complete_json_and_preserves_existing_output_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("result.json");
        std::fs::write(&path, "original").unwrap();
        let invalid = std::collections::BTreeMap::from([(vec![1, 2], 3)]);
        assert!(save_json_output(&invalid, &path, JsonStyle::Pretty).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original");
        save_json_output(&vec![1, 2], &path, JsonStyle::Pretty).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<i32>>(&std::fs::read_to_string(path).unwrap()).unwrap(),
            [1, 2]
        );
        assert!(
            save_json_output(
                &1,
                &dir.path().join("missing/result.json"),
                JsonStyle::Compact
            )
            .is_err()
        );
    }
}
