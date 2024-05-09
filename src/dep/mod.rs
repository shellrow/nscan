#[cfg(not(target_os = "windows"))]
mod unix;
use std::{error::Error, fmt};

#[cfg(not(target_os = "windows"))]
pub use self::unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

// Custom error type for dependency check
#[derive(Debug)]
pub struct DependencyError {
    pub dependency: String,
    pub message: String,
}

impl DependencyError {
    pub fn new(dependency: &str, message: &str) -> Self {
        Self {
            dependency: String::from(dependency),
            message: String::from(message),
        }
    }
}

impl fmt::Display for DependencyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.dependency, self.message)
    }
}

impl Error for DependencyError {
    fn description(&self) -> &str {
        &self.message
    }
}
