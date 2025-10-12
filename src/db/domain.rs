use crate::config::db::TOP_SUBDOMAIN_WORDS_JSON;

/// Get top subdomain wordlist
pub fn get_subdomain_wordlist() -> Vec<String> {
    serde_json::from_str(TOP_SUBDOMAIN_WORDS_JSON).unwrap_or_default()
}
