pub mod domain;
pub mod os;
pub mod oui;
pub mod port;
pub mod service;
pub mod tls;

use anyhow::Result;
use futures::StreamExt;
use std::time::{Duration, Instant};

/// Initialization function type
type InitFn = fn() -> Result<()>;

/// Database initialization task
struct DbTask {
    name: &'static str,
    init: InitFn,
}

const TASK_TCP_SERVICE: DbTask = DbTask {
    name: "tcp_service_db",
    init: || service::init_tcp_service_db(),
};
const TASK_UDP_SERVICE: DbTask = DbTask {
    name: "udp_service_db",
    init: || service::init_udp_service_db(),
};
const TASK_PORT_PROBE: DbTask = DbTask {
    name: "port_probe_db",
    init: || service::init_port_probe_db(),
};
const TASK_SVC_PROBE: DbTask = DbTask {
    name: "service_probe_db",
    init: || service::init_service_probe_db(),
};
const TASK_RESP_SIGS: DbTask = DbTask {
    name: "response_signatures",
    init: || service::init_response_signatures_db(),
};
const TASK_TLS_OID: DbTask = DbTask {
    name: "tls_oid_map",
    init: || tls::init_tls_oid_map(),
};
const TASK_OS_DB: DbTask = DbTask {
    name: "os_db",
    init: || os::init_os_db(),
};
const TASK_OUI_DB: DbTask = DbTask {
    name: "oui_db",
    init: || oui::init_oui_db(),
};

/// Database initialization result record
#[derive(Debug, Clone)]
pub struct InitRecord {
    pub name: &'static str,
    pub elapsed: Duration,
    pub ok: bool,
    pub error: Option<String>,
}

/// Database initialization report
#[derive(Debug, Clone)]
pub struct InitReport {
    pub total: Duration,
    pub records: Vec<InitRecord>,
}

/// Database initializer (for once-only initialization)
pub struct DbInitializer {
    tasks: Vec<&'static DbTask>,
}

impl DbInitializer {
    /// Create new initializer
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }
    /// Add TCP service DB
    pub fn with_tcp_services(mut self) -> Self {
        self.tasks.push(&TASK_TCP_SERVICE);
        self
    }
    /// Add UDP service DB
    pub fn with_udp_services(mut self) -> Self {
        self.tasks.push(&TASK_UDP_SERVICE);
        self
    }
    /// Add port probe DB
    pub fn with_port_probe(mut self) -> Self {
        self.tasks.push(&TASK_PORT_PROBE);
        self
    }
    /// Add service probe DB
    pub fn with_service_probe(mut self) -> Self {
        self.tasks.push(&TASK_SVC_PROBE);
        self
    }
    /// Add response signatures DB
    pub fn with_response_sigs(mut self) -> Self {
        self.tasks.push(&TASK_RESP_SIGS);
        self
    }
    /// Add TLS OID map
    pub fn with_tls_oids(mut self) -> Self {
        self.tasks.push(&TASK_TLS_OID);
        self
    }
    /// Add OS DB
    pub fn with_os_db(mut self) -> Self {
        self.tasks.push(&TASK_OS_DB);
        self
    }
    /// Add OUI DB
    pub fn with_oui_db(mut self) -> Self {
        self.tasks.push(&TASK_OUI_DB);
        self
    }
    /// Add all databases
    pub fn with_all() -> Self {
        Self::new()
            .with_tcp_services()
            .with_udp_services()
            .with_port_probe()
            .with_service_probe()
            .with_response_sigs()
            .with_tls_oids()
            .with_os_db()
            .with_oui_db()
    }

    /// Run initialization tasks, return report
    pub async fn init(self) -> InitReport {
        use futures::stream;

        // Remove duplicate tasks (even if the same preset is stacked, it will only be done once)
        let mut uniq: Vec<&'static DbTask> = Vec::new();
        for t in self.tasks {
            if !uniq.iter().any(|u| u.name == t.name) {
                uniq.push(t);
            }
        }

        let uniq_count = uniq.len();
        tracing::debug!("Initializing databases ({} task(s))...", uniq_count);
        let t0 = Instant::now();

        let results = stream::iter(uniq)
            .map(|task| async move {
                let start = Instant::now();
                let res = (task.init)();
                let ok = res.is_ok();
                let err = res.err().map(|e| e.to_string());
                InitRecord {
                    name: task.name,
                    elapsed: start.elapsed(),
                    ok,
                    error: err,
                }
            })
            .buffer_unordered(uniq_count)
            .collect::<Vec<_>>()
            .await;

        let total = t0.elapsed();

        for r in &results {
            if r.ok {
                tracing::debug!("DB init ok: {} ({:?})", r.name, r.elapsed);
            } else {
                tracing::error!(
                    "DB init failed: {} ({:?}) - {}",
                    r.name,
                    r.elapsed,
                    r.error.as_deref().unwrap_or("?")
                );
            }
        }
        tracing::debug!("DB init done: {:?} total", total);

        InitReport {
            total,
            records: results,
        }
    }
}
