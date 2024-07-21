use indicatif::ProgressStyle;

pub const SECTION_DIVIDER: &str = "────────────────────────────────────────";

pub fn log(message: &str, level: &str) {
    if crate::app::is_quiet_mode() {
        return;
    }
    println!("[{}] {}", level, message);
}

pub fn log_with_time(message: &str, level: &str) {
    if crate::app::is_quiet_mode() {
        return;
    }
    let now: String = crate::sys::time::get_systime();
    println!("[{}] [{}] {}", now, level, message);
}

pub fn log_with_datetime(message: &str, level: &str) {
    if crate::app::is_quiet_mode() {
        return;
    }
    let now: String = crate::sys::time::get_sysdate();
    println!("[{}] [{}] {}", now, level, message);
}

pub fn get_progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template(
            "{spinner:.green} {msg} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
        )
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"])
        .progress_chars("#>-")
}
