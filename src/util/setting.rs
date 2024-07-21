use std::time::Duration;

const DEFAULT_WAIT_TIME_FACTOR: f64 = 2.0;
const MINIMUM_WAIT_TIME: Duration = Duration::from_millis(50);

pub fn caluculate_wait_time(rtt: Duration) -> Duration {
    if rtt < MINIMUM_WAIT_TIME {
        return MINIMUM_WAIT_TIME;
    }

    let num_cores = num_cpus::get_physical();
    let num_threads = num_cpus::get();

    let factor = if num_cores <= 2 || num_threads <= 4 {
        // If the number of cores is less than or equal to 2
        // or the number of threads is less than or equal to 4
        // , increase the factor
        DEFAULT_WAIT_TIME_FACTOR * 2.0
    } else {
        // Otherwise, the factor is the default value
        DEFAULT_WAIT_TIME_FACTOR
    };

    let wait_time = rtt.as_secs_f64() * factor;
    Duration::from_secs_f64(wait_time)
}
