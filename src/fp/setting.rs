use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use crate::protocol::Protocol;

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum  FingerprintType {
    IcmpEcho,
    IcmpTimestamp,
    IcmpAddressMask,
    IcmpInformation,
    IcmpUnreachable,
    TcpSynAck,
    TcpRstAck,
    TcpEcn,
}

impl FingerprintType {
    pub fn protocol(&self) -> Protocol {
        match self {
            FingerprintType::IcmpEcho => Protocol::ICMP,
            FingerprintType::IcmpTimestamp => Protocol::ICMP,
            FingerprintType::IcmpAddressMask => Protocol::ICMP,
            FingerprintType::IcmpInformation => Protocol::ICMP,
            FingerprintType::IcmpUnreachable => Protocol::UDP,
            FingerprintType::TcpSynAck => Protocol::TCP,
            FingerprintType::TcpRstAck => Protocol::TCP,
            FingerprintType::TcpEcn => Protocol::TCP,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct FingerprintSetting {
    pub if_index: u32,
    pub dst_hostname: String,
    pub dst_ip: IpAddr,
    pub protocol: Protocol,
    pub fingerprint_type: FingerprintType,
    pub count: u32,
    pub receive_timeout: u64,
    pub probe_timeout: u64,
}

impl Default for FingerprintSetting {
    fn default() -> Self {
        Self {
            if_index: 0,
            dst_hostname: "localhost".to_string(),
            dst_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            protocol: Protocol::ICMP,
            fingerprint_type: FingerprintType::IcmpEcho,
            count: 1,
            receive_timeout: 1000,
            probe_timeout: 30000,
        }
    }
}
