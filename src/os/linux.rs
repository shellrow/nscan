use sudo::RunningAs;

pub fn privileged() -> bool {
    let user_privilege = sudo::check();
    match user_privilege {
        RunningAs::Root => {
            true
        },
        RunningAs::User => {
            false
        },
        RunningAs::Suid => {
            true
        },
    }
}

pub fn escalate_if_needed() {
    match sudo::escalate_if_needed() {
        Ok(_) => {},
        Err(_) => {},
    }
}
