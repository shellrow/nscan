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