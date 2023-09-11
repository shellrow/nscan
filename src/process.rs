pub fn privileged() -> bool {
    privilege::user::privileged()
}
