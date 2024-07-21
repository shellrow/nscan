use super::domain::Domain;
use super::result::DomainScanResult;
use futures::{stream, StreamExt};
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[cfg(not(any(unix, target_os = "windows")))]
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::AsyncResolver;

use super::setting::DEFAULT_USER_AGENT_FIREFOX;
#[cfg(feature = "passive")]
use crate::config::URL_CRT;
#[cfg(feature = "passive")]
use crate::model::CertEntry;
use crate::scan::result::ScanStatus;
#[cfg(feature = "passive")]
use reqwest::Url;

/// Structure for domain scan  
///
/// Should be constructed using DomainScanner::new
#[derive(Clone)]
pub struct DomainScanner {
    /// Base Domain Name of scan target.  
    pub base_domain: String,
    /// Word-list of name
    pub word_list: Vec<String>,
    /// Timeout setting of domain scan.  
    pub timeout: Duration,
    /// Resolve timeout setting of domain scan.
    pub resolve_timeout: Duration,
    /// Concurrent limit of domain scan.
    pub concurrent_limit: usize,
    /// Result of domain scan.  
    pub scan_result: DomainScanResult,
    /// Sender for progress messaging
    tx: Arc<Mutex<Sender<String>>>,
    /// Receiver for progress messaging
    rx: Arc<Mutex<Receiver<String>>>,
    /// Run passive scan
    pub passive: bool,
    /// User-Agent for passive scan
    user_agent: String,
}

impl DomainScanner {
    /// Construct new UriScanner  
    pub fn new() -> Result<DomainScanner, String> {
        let (tx, rx) = channel();
        let domain_scanner = DomainScanner {
            base_domain: String::new(),
            word_list: vec![],
            timeout: Duration::from_millis(30000),
            resolve_timeout: Duration::from_millis(1000),
            concurrent_limit: 100,
            scan_result: DomainScanResult::new(),
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
            passive: false,
            user_agent: DEFAULT_USER_AGENT_FIREFOX.to_string(),
        };
        Ok(domain_scanner)
    }
    /// Set base Domain of scan target.  
    pub fn set_base_domain(&mut self, base_domain: String) {
        self.base_domain = base_domain;
    }
    /// Add word to word-list
    pub fn add_word(&mut self, word: String) {
        self.word_list.push(word);
    }
    /// Set word-list
    pub fn set_word_list(&mut self, word_list: Vec<&str>) {
        self.word_list.clear();
        for word in word_list {
            self.word_list.push(word.to_string())
        }
    }
    /// Set scan timeout  
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    /// Set active/passive scan (default is active)
    pub fn set_passive(&mut self, passive: bool) {
        self.passive = passive;
    }
    /// Set user-agent for passive scan
    pub fn set_user_agent(&mut self, user_agent: String) {
        self.user_agent = user_agent;
    }
    async fn scan_domain(&self) -> Result<Vec<Domain>, ()> {
        if self.passive {
            #[cfg(feature = "passive")]
            match timeout(
                self.timeout,
                scan_subdomain_passive(
                    self.base_domain.clone(),
                    &self.tx,
                    self.resolve_timeout,
                    self.concurrent_limit,
                    self.user_agent.clone(),
                ),
            )
            .await
            {
                Ok(domains) => {
                    return Ok(domains);
                }
                Err(_) => {
                    return Err(());
                }
            }
            #[cfg(not(feature = "passive"))]
            return Err(());
        } else {
            match timeout(
                self.timeout,
                scan_subdomain(
                    self.base_domain.clone(),
                    self.word_list.clone(),
                    &self.tx,
                    self.resolve_timeout,
                    self.concurrent_limit,
                ),
            )
            .await
            {
                Ok(domains) => {
                    return Ok(domains);
                }
                Err(_) => {
                    return Err(());
                }
            }
        }
    }
    /// Run scan with current settings.
    ///
    /// Results are stored in DomainScanner::scan_result
    pub async fn run_scan(&mut self) {
        if self.passive && cfg!(not(feature = "passive")) {
            self.scan_result.scan_status =
                ScanStatus::Error(String::from("Passive scan not supported"));
            return;
        }
        let start_time = Instant::now();
        let res = self.scan_domain().await;
        match res {
            Ok(domains) => {
                self.scan_result.domains = domains;
                self.scan_result.scan_status = ScanStatus::Done;
            }
            Err(_) => {
                self.scan_result.scan_status = ScanStatus::Timeout;
            }
        }
        self.scan_result.scan_time = Instant::now().duration_since(start_time);
    }
    /// Return scan result.
    pub fn get_result(&mut self) -> DomainScanResult {
        return self.scan_result.clone();
    }
    /// Run scan and return result
    pub async fn scan(&mut self) -> DomainScanResult {
        self.run_scan().await;
        self.scan_result.clone()
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<String>>> {
        self.rx.clone()
    }
}

#[cfg(any(unix, target_os = "windows"))]
async fn resolve_domain(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver = AsyncResolver::tokio_from_system_conf().unwrap();
    match resolver.lookup_ip(host_name).await {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        }
        Err(_) => {}
    }
    ips
}

#[cfg(feature = "async")]
#[cfg(not(any(unix, target_os = "windows")))]
async fn resolve_domain(host_name: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver =
        AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.lookup_ip(host_name).await {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        }
        Err(_) => {}
    }
    ips
}

#[cfg(feature = "passive")]
fn extract_domain(target: String) -> String {
    let mut domain_name: String = target;
    match domain_name.strip_prefix("*.") {
        Some(d) => {
            domain_name = d.to_string();
        }
        None => {}
    }
    domain_name
}

#[cfg(feature = "passive")]
fn is_subdomain(domain: String, apex_domain: String) -> bool {
    domain.contains(&apex_domain)
        && domain.ends_with(&apex_domain)
        && domain.len() > apex_domain.len()
}

async fn scan_subdomain(
    base_domain: String,
    word_list: Vec<String>,
    ptx: &Arc<Mutex<Sender<String>>>,
    resolve_timeout: Duration,
    concurrent_limit: usize,
) -> Vec<Domain> {
    let mut result: Vec<Domain> = vec![];
    let scan_results: Arc<Mutex<Vec<Domain>>> = Arc::new(Mutex::new(vec![]));
    let mut target_domains: Vec<String> = vec![];
    for word in word_list {
        target_domains.push(format!("{}.{}", word, base_domain));
    }
    let results = stream::iter(target_domains)
        .map(|domain| async move {
            let mut d: Domain = Domain {
                domain_name: domain.clone(),
                ips: vec![],
            };
            match timeout(resolve_timeout, resolve_domain(domain.clone())).await {
                Ok(ips) => {
                    d.ips = ips;
                    match ptx.lock() {
                        Ok(lr) => match lr.send(domain) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    }
                }
                Err(_) => match ptx.lock() {
                    Ok(lr) => match lr.send(domain) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                },
            }
            d
        })
        .buffer_unordered(concurrent_limit);
    results
        .for_each(|domain| async {
            if domain.ips.len() > 0 {
                scan_results.lock().unwrap().push(domain);
            }
        })
        .await;
    for domain in scan_results.lock().unwrap().iter() {
        result.push(domain.to_owned());
    }
    result
}

#[cfg(feature = "passive")]
async fn scan_subdomain_passive(
    base_domain: String,
    ptx: &Arc<Mutex<Sender<String>>>,
    resolve_timeout: Duration,
    concurrent_limit: usize,
    user_agent: String,
) -> Vec<Domain> {
    let mut result: Vec<Domain> = vec![];
    let scan_results: Arc<Mutex<Vec<Domain>>> = Arc::new(Mutex::new(vec![]));
    let mut certs: Vec<CertEntry> = vec![];
    //"https://crt.sh/?dNSName=example.com&output=json"
    let url = match Url::parse_with_params(
        URL_CRT,
        &[
            ("dNSName", base_domain.clone().as_str()),
            ("output", "json"),
        ],
    ) {
        Ok(url) => url,
        Err(e) => {
            println!("{}", e);
            return result;
        }
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("failed to build HTTP reqest client");
    let res = client
        .get(url)
        .header(reqwest::header::USER_AGENT, user_agent)
        .send()
        .await;
    match res {
        Ok(r) => {
            if r.status().is_success() {
                match r.text().await {
                    Ok(res_text) => {
                        let certs_json: serde_json::Value = serde_json::from_str(res_text.as_str())
                            .unwrap_or(serde_json::json!({}));
                        if certs_json.is_array() {
                            let cert_array = certs_json.as_array().unwrap();
                            for cert in cert_array {
                                match serde_json::to_string(cert) {
                                    Ok(cert) => {
                                        let cert: CertEntry =
                                            match serde_json::from_str(cert.as_str()) {
                                                Ok(cert) => cert,
                                                Err(_) => continue,
                                            };
                                        certs.push(cert);
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                    Err(_) => {}
                };
            }
        }
        Err(_) => {}
    }
    let mut target_domains: Vec<String> = vec![];
    for cert in certs {
        let domain_name: String = extract_domain(cert.common_name);
        if is_subdomain(domain_name.clone(), base_domain.clone())
            && !target_domains.contains(&domain_name)
        {
            target_domains.push(domain_name);
        }
        let name_values: Vec<&str> = cert.name_value.trim().split("\n").collect();
        for value in name_values {
            let name: String = extract_domain(value.to_string());
            if is_subdomain(name.clone(), base_domain.clone()) && !target_domains.contains(&name) {
                target_domains.push(name);
            }
        }
    }
    let results = stream::iter(target_domains)
        .map(|domain| async move {
            let mut d: Domain = Domain {
                domain_name: domain.clone(),
                ips: vec![],
            };
            match timeout(resolve_timeout, resolve_domain(domain.clone())).await {
                Ok(ips) => {
                    d.ips = ips;
                    match ptx.lock() {
                        Ok(lr) => match lr.send(domain) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    }
                }
                Err(_) => match ptx.lock() {
                    Ok(lr) => match lr.send(domain) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                },
            }
            d
        })
        .buffer_unordered(concurrent_limit);
    results
        .for_each(|domain| async {
            if domain.ips.len() > 0 {
                scan_results.lock().unwrap().push(domain);
            }
        })
        .await;
    for domain in scan_results.lock().unwrap().iter() {
        result.push(domain.to_owned());
    }
    result
}
