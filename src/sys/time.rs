use std::time::Duration;

pub fn get_sysdate() -> String {
    let now = chrono::Local::now();
    now.to_rfc3339()
}

pub fn get_systime() -> String {
    let now = chrono::Local::now();
    now.format("%H:%M:%S").to_string()
}

pub fn ceil_duration_millis(duration: Duration) -> Duration {
    let millis = duration.as_millis();
    if millis % 1000 == 0 {
        duration
    } else {
        Duration::from_millis(millis as u64 + 1)
    }
}
