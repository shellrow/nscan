use std::fs;
use std::path::PathBuf;

pub fn save_text(file_path: &PathBuf, contents_text: String) -> Result<(), std::io::Error> {
    fs::write(file_path, contents_text)
}
