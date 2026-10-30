use std::sync::LazyLock;

/// Fixed common-port preset bundled with this version of nscan.
pub fn common_ports() -> &'static [u16] {
    static PORTS: LazyLock<Vec<u16>> = LazyLock::new(|| {
        serde_json::from_str(crate::config::db::COMMON_PORTS_JSON)
            .expect("invalid common-port preset")
    });
    &PORTS
}

#[cfg(test)]
mod tests {
    #[test]
    fn preset_is_sorted_unique_and_nonzero() {
        let ports = super::common_ports();
        assert_eq!(ports.len(), 1000);
        assert!(ports[0] > 0);
        assert!(ports.windows(2).all(|p| p[0] < p[1]));
    }
}
