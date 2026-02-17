/// Default port list
pub const DEFAULT_PORTS_JSON: &str = include_str!("../../resources/nscan-default-ports.json");
/// OS class by TTL values
pub const OS_CLASS_TTL_JSON: &str = include_str!("../../resources/nscan-os-class-ttl.json");
/// Well-known ports
pub const WELLKNOWN_PORTS_JSON: &str = include_str!("../../resources/nscan-wellknown-ports.json");
/// OS database and fingerprints
pub const OS_DB_JSON: &str = include_str!("../../resources/nscan-os-db.json");
/// Service database and fingerprints
pub const SERVICE_DB_JSON: &str = include_str!("../../resources/nscan-service-db.json");
/// probe types and definitions
pub const SERVICE_PROBES_JSON: &str = include_str!("../../resources/nscan-service-probes.json");
/// Port and probe type mappings
pub const PORT_PROBES_JSON: &str = include_str!("../../resources/nscan-port-probes.json");
/// TLS OID mappings
pub const TLS_OID_MAP_JSON: &str = include_str!("../../resources/nscan-tls-oid-map.json");
/// Top subdomain words for subdomain scanning
pub const TOP_SUBDOMAIN_WORDS_JSON: &str =
    include_str!("../../resources/nscan-top-subdomains.json");
