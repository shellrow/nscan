use super::domain::Domain;
use super::result::DomainScanResult;
use futures::{stream, StreamExt};
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use hickory_resolver::AsyncResolver;
use crate::scan::result::ScanStatus;

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
    async fn scan_domain(&self) -> Result<Vec<Domain>, ()> {
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
    /// Run scan with current settings.
    ///
    /// Results are stored in DomainScanner::scan_result
    pub async fn run_scan(&mut self) {
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
