use std::path::PathBuf;

pub mod db;
pub mod default;

/// User configuration directory name
pub const USER_CONFIG_DIR_NAME: &str = ".nscan";

/// Get user configuration directory path, create it if not exists
pub fn get_config_dir_path() -> Option<PathBuf> {
    match home::home_dir() {
        Some(mut path) => {
            path.push(USER_CONFIG_DIR_NAME);
            if !path.exists() {
                match std::fs::create_dir_all(&path) {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("Failed to create config dir: {:?}", e);
                        return None;
                    }
                }
            }
            Some(path)
        }
        None => None,
    }
}

/// Get user configuration file path
pub fn get_user_file_path(file_name: &str) -> Option<PathBuf> {
    match get_config_dir_path() {
        Some(mut path) => {
            path.push(file_name);
            Some(path)
        }
        None => None,
    }
}
