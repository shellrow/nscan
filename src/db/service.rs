use ndb_tcp_service::TcpServiceDb;
use ndb_udp_service::UdpServiceDb;
use anyhow::Result;
use std::{collections::HashMap, sync::OnceLock};

use crate::{config, endpoint::Port, service::probe::{PortProbeDb, ProbePayload, ProbePayloadDb, ResponseSignature, ResponseSignaturesDb, ServiceProbe}};

pub static TCP_SERVICE_DB: OnceLock<TcpServiceDb> = OnceLock::new();
pub static UDP_SERVICE_DB: OnceLock<UdpServiceDb> = OnceLock::new();
pub static PORT_PROBE_DB: OnceLock<HashMap<Port, Vec<ServiceProbe>>> = OnceLock::new();
pub static SERVICE_PROBE_DB: OnceLock<HashMap<ServiceProbe, ProbePayload>> = OnceLock::new();
pub static RESPONSE_SIGNATURES_DB: OnceLock<Vec<ResponseSignature>> = OnceLock::new();

/// Get a reference to the initialized TCP service database.
pub fn tcp_service_db() -> &'static TcpServiceDb {
    TCP_SERVICE_DB.get().expect("TCP_SERVICE_DB not initialized")
}

/// Get a reference to the initialized UDP service database.
pub fn udp_service_db() -> &'static UdpServiceDb {
    UDP_SERVICE_DB.get().expect("UDP_SERVICE_DB not initialized")
}

/// Get a reference to the initialized Port Probe database.
pub fn port_probe_db() -> &'static HashMap<Port, Vec<ServiceProbe>> {
    PORT_PROBE_DB.get().expect("PORT_PROBE_DB not initialized")
}

/// Get a reference to the initialized Service Probe database.
pub fn service_probe_db() -> &'static HashMap<ServiceProbe, ProbePayload> {
    SERVICE_PROBE_DB.get().expect("SERVICE_PROBE_DB not initialized")
}

/// Get a reference to the initialized Response Signatures database.
pub fn response_signatures_db() -> &'static Vec<ResponseSignature> {
    RESPONSE_SIGNATURES_DB.get().expect("RESPONSE_SIGNATURES_DB not initialized")
}

/// Initialize TCP Service database
pub fn init_tcp_service_db() -> Result<()> {
    let tcp_service_db = TcpServiceDb::bundled();
    TCP_SERVICE_DB
        .set(tcp_service_db)
        .map_err(|_| anyhow::anyhow!("Failed to set TCP_SERVICE_DB in OnceLock"))?;
    Ok(())
}

/// Initialize UDP Service database
pub fn init_udp_service_db() -> Result<()> {
    let udp_service_db = UdpServiceDb::bundled();
    UDP_SERVICE_DB
        .set(udp_service_db)
        .map_err(|_| anyhow::anyhow!("Failed to set UDP_SERVICE_DB in OnceLock"))?;
    Ok(())
}

/// Initialize Port Probe database
pub fn init_port_probe_db() -> Result<()> {
    let port_probe_db: PortProbeDb = serde_json::from_str(config::db::PORT_PROBES_JSON)
        .expect("Invalid port-probes.json format");
    
    let mut map: HashMap<Port, Vec<ServiceProbe>> = HashMap::new();
    for (port, probes) in port_probe_db.map {
        let service_probes: Vec<ServiceProbe> = probes
            .into_iter()
            .map(|probe| ServiceProbe::from_str(&probe).expect("Invalid service probe format"))
            .collect();
        for service_probe in service_probes {
            let port = Port::new(port, service_probe.transport());
            map.entry(port).or_insert_with(Vec::new).push(service_probe);
        }
    }
    PORT_PROBE_DB
        .set(map)
        .map_err(|_| anyhow::anyhow!("Failed to set PORT_PROBE_DB in OnceLock"))?;
    Ok(())
}

/// Initialize Service Probe database
pub fn init_service_probe_db() -> Result<()> {
    let probe_payload_db: ProbePayloadDb = serde_json::from_str(config::db::SERVICE_PROBES_JSON)
        .expect("Invalid service-probes.json format");
    let mut service_probe_map: HashMap<ServiceProbe, ProbePayload> = HashMap::new();
    for probe_payload in probe_payload_db.probes {
        let service_probe: ServiceProbe = ServiceProbe::from_str(&probe_payload.id)
            .expect("Invalid service probe format");
        service_probe_map.insert(service_probe, probe_payload);
    }
    SERVICE_PROBE_DB
        .set(service_probe_map)
        .map_err(|_| anyhow::anyhow!("Failed to set SERVICE_PROBE_DB in OnceLock"))?;
    Ok(())
}

/// Initialize Response Signatures database
pub fn init_response_signatures_db() -> Result<()> {
    let response_signatures_db: ResponseSignaturesDb = serde_json::from_str(config::db::SERVICE_DB_JSON)
        .expect("Invalid nscan-service-db.json format");
    RESPONSE_SIGNATURES_DB
        .set(response_signatures_db.signatures)
        .map_err(|_| anyhow::anyhow!("Failed to set RESPONSE_SIGNATURES_DB in OnceLock"))?;
    Ok(())
}

/// Get the service name for a given TCP port
pub fn get_tcp_service_name(port: u16) -> Option<String> {
    match TCP_SERVICE_DB.get() {
        Some(db) => {
            match db.get(port) {
                Some(service) => Some(service.name.clone()),
                None => None,
            }
        }
        None => None,
    }
}

/// Get the service names for a list of TCP ports
pub fn get_tcp_service_names(ports: &[u16]) -> HashMap<u16, String> {
    let mut result = HashMap::new();
    if let Some(db) = TCP_SERVICE_DB.get() {
        for &port in ports {
            if let Some(service) = db.get(port) {
                result.insert(port, service.name.clone());
            } else {
                result.insert(port, "Unknown".to_string());
            }
        }
    }
    result
}

/// Get the map of port to service probes
pub fn get_port_probes() -> HashMap<u16, Vec<ServiceProbe>> {
    let mut port_probe_map: HashMap<u16, Vec<ServiceProbe>> = HashMap::new();
    let port_probe_db: PortProbeDb = serde_json::from_str(config::db::PORT_PROBES_JSON).expect("Invalid os-ttl.json format");
    for (port, probes) in port_probe_db.map {
        for probe in probes {
            let service_probe: ServiceProbe = ServiceProbe::from_str(&probe).expect("Invalid service probe format");
            port_probe_map.entry(port).or_insert_with(Vec::new).push(service_probe);
        }
    }
    port_probe_map
}

/// Get the map of service probes to their payloads
pub fn get_service_probes() -> HashMap<ServiceProbe, ProbePayload> {
    let mut service_probe_map: HashMap<ServiceProbe, ProbePayload> = HashMap::new();
    let probe_payload_db: ProbePayloadDb = serde_json::from_str(config::db::SERVICE_PROBES_JSON).expect("Invalid service-probes.json format");
    for probe_payload in probe_payload_db.probes {
        let service_probe: ServiceProbe = ServiceProbe::from_str(&probe_payload.id).expect("Invalid service probe format");
        service_probe_map.insert(service_probe, probe_payload);
    }
    service_probe_map
}

/// Get the list of response signatures
pub fn get_service_response_signatures() -> Vec<ResponseSignature> {
    let response_signatures_db: ResponseSignaturesDb = serde_json::from_str(config::db::SERVICE_DB_JSON).expect("Invalid nscan-service-os-db.json format");
    response_signatures_db.signatures
}
