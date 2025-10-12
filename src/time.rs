use tracing_subscriber::fmt::time::FormatTime;
use std::fmt;
use chrono::Local;

/// DateTime format for logging that includes date, time, and timezone (YYYY-MM-DD HH:MM:SS.mmmmmm+00:00)
/// Same as `ChronoLocal::rfc_3339()` but with a custom format
pub struct LocalDateTime;

impl FormatTime for LocalDateTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
        write!(w, "{}", Local::now().format("%Y-%m-%d %H:%M:%S%.6f%:z"))
    }
}

/// Time format for logging that only includes the time (HH:MM:SS.mmmmmm+00:00)
pub struct LocalTimeOnly;

impl FormatTime for LocalTimeOnly {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
        write!(w, "{}", Local::now().format("%H:%M:%S%.6f%:z"))
    }
}
