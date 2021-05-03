use netscan::PortScanType;
use super::{sys, db};
use std::time::Duration;
use dns_lookup::lookup_host;

pub struct PortOption{
    pub ip_addr: String,
    pub start_port: u16,
    pub end_port: u16,
    pub port_list: Vec<u16>,
    pub app_port: u16,
    pub scan_type: PortScanType,
    pub default_scan: bool,
    pub use_list: bool,
    pub list_path: String,
    pub if_name: String,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub include_detail: bool,
    pub save_path: String,
}

pub struct HostOption{
    pub ip_addr: String,
    pub scan_host_addr: bool,
    pub use_list: bool,
    pub list_path: String,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub include_detail: bool,
    pub save_path: String,
}

impl PortOption {
    pub fn new() -> PortOption {
        let port_option = PortOption {
            ip_addr: String::new(),
            start_port: 0,
            end_port: 0,
            port_list: vec![],
            app_port: 65432,
            scan_type: PortScanType::SynScan,
            default_scan: false,
            use_list: false,
            list_path: String::new(),
            if_name: String::new(),
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(100),
            include_detail: false,
            save_path: String::new(),
        };
        return port_option;
    }
    pub fn set_option(&mut self, arg_value: String){
        let a_vec: Vec<&str> = arg_value.split(":").collect();
        let host = a_vec[0].to_string();
        if a_vec.len() > 1 {
            let port_opt = a_vec[1].to_string();
            if port_opt.contains("-") {
                let range: Vec<&str> = port_opt.split("-").collect();
                match range[0].parse::<u16>() {
                    Ok(s_port) => {
                        self.start_port = s_port;
                    },
                    Err(_) =>{},
                }
                match range[1].parse::<u16>() {
                    Ok(e_port) => {
                        self.end_port = e_port;
                    },
                    Err(_) =>{},
                }
                if self.start_port < self.end_port {
                    for i in self.start_port..self.end_port + 1{
                        self.port_list.push(i);
                    }
                }
            }else if port_opt.contains(","){
                let port_list: Vec<&str> = port_opt.split(",").collect();
                for p in port_list {
                    match p.parse::<u16>(){
                        Ok(port) =>{
                            self.port_list.push(port);
                        },
                        Err(_) =>{},
                    }
                }
            }
        }else{
            self.port_list = db::get_default_ports();
            self.default_scan = true;
        }
        if sys::is_ipaddr(host.clone()) {
            self.ip_addr = host;
        }else {
            match lookup_host(&host) {
                Ok(addrs) => {
                    for addr in addrs {
                        if addr.is_ipv4() {
                            self.ip_addr = addr.to_string();
                            break;
                        }
                    }
                },
                Err(_) => {
                    self.ip_addr = host;
                },
            }
        }
    }
    pub fn set_file_path(&mut self, file_path: String){
        if !file_path.is_empty() {
            self.use_list = true;
            self.list_path = file_path;   
        }
    }
    pub fn set_if_name(&mut self, if_name: String){
        if !if_name.is_empty() {
            self.if_name = if_name;
        }
    }
    pub fn set_timeout(&mut self, ms_str: String){
        let timeout: u64 = ms_str.parse().unwrap();
        self.timeout = Duration::from_millis(timeout);
    }
    pub fn set_wait_time(&mut self, ms_str: String){
        let wait_time: u64 = ms_str.parse().unwrap();
        self.wait_time = Duration::from_millis(wait_time);
    }
    pub fn set_scan_type(&mut self, port_scan_type: String){
        let port_scan_type = port_scan_type.as_str();
        let scan_type = match port_scan_type {
            "SYN" => {PortScanType::SynScan},
            "CONNECT" => {PortScanType::ConnectScan},
            "FIN" => {PortScanType::FinScan},
            "XMAS" => {PortScanType::XmasScan},
            "NULL" => {PortScanType::NullScan},
            _ => {PortScanType::SynScan},
        };
        self.scan_type = scan_type;
    }
    pub fn set_include_detail(&mut self, include: bool){
        self.include_detail = include;
    }
    pub fn set_save_path(&mut self, save_path: String){
        self.save_path = save_path;
    }
    pub fn show_options(&self){
        sys::print_fix32("Port Scan Options", sys::FillStr::Hyphen);
        println!("{}IP Address: {}", sys::SPACE4, self.ip_addr);
        if self.use_list {
            println!("{}Port List (file path): {}", sys::SPACE4, self.list_path);
        }else{
            if self.start_port < self.end_port {
                println!("{}Port Range: {}-{}", sys::SPACE4, self.start_port, self.end_port);
            }else{
                if self.default_scan {
                    println!("{}Port List: nscan-default-ports (1005 ports)", sys::SPACE4);
                }else{
                    println!("{}Port List: {:?}", sys::SPACE4, self.port_list);
                }
            }
        }
        match self.scan_type {
            PortScanType::SynScan => {println!("{}Scan Type: Syn Scan", sys::SPACE4);},
            PortScanType::FinScan => {println!("{}Scan Type: Fin Scan", sys::SPACE4);},
            PortScanType::XmasScan => {println!("{}Scan Type: Xmas Scan", sys::SPACE4);},
            PortScanType::NullScan => {println!("{}Scan Type: Null Scan", sys::SPACE4);},
            PortScanType::ConnectScan => {println!("{}Scan Type: Connect Scan", sys::SPACE4);},
        }
        sys::print_fix32("", sys::FillStr::Hyphen);
    }
}

impl HostOption {
    pub fn new() -> HostOption {
        let host_option = HostOption {
            ip_addr: String::new(),
            scan_host_addr: true,
            use_list: false,
            list_path: String::new(),
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(100),
            include_detail: false,
            save_path: String::new(),
        };
        return host_option;
    }
    pub fn set_option(&mut self, arg_value: String){
        match sys::get_network_address(arg_value){
            Ok(ip_str) =>{
                self.ip_addr = ip_str;
            },
            Err(e) => {
                error!("{}", e.to_string());
                std::process::exit(0);
            },
        }
    }
    pub fn set_file_path(&mut self, file_path: String){
        if !file_path.is_empty() {
            self.scan_host_addr = false;
            self.use_list = true;
            self.list_path = file_path;   
        }
    }
    pub fn set_timeout(&mut self, ms_str: String){
        let timeout: u64 = ms_str.parse().unwrap();
        self.timeout = Duration::from_millis(timeout);
    }
    pub fn set_wait_time(&mut self, ms_str: String){
        let wait_time: u64 = ms_str.parse().unwrap();
        self.wait_time = Duration::from_millis(wait_time);
    }
    pub fn set_include_detail(&mut self, include: bool){
        self.include_detail = include;
    }
    pub fn set_save_path(&mut self, save_path: String){
        self.save_path = save_path;
    }
    pub fn show_options(&self){
        sys::print_fix32("Host Scan Options", sys::FillStr::Hyphen);
        if self.scan_host_addr {
            println!("{}Target Network: {}", sys::SPACE4, self.ip_addr);
        }else{
            println!("{}Target: Specified in list {}", sys::SPACE4, self.list_path);
        }
        sys::print_fix32("", sys::FillStr::Hyphen);
    }
}
