use netscan::PortScanType;
use super::sys;
use std::time::Duration;

pub struct PortOption{
    pub ip_addr: String,
    pub start_port: u16,
    pub end_port: u16,
    pub app_port: u16,
    pub scan_type: PortScanType,
    pub use_wordlist: bool,
    pub wordlist_path: String,
    pub if_name: String,
    pub timeout: Duration,
    pub save_path: String,
}

pub struct HostOption{
    pub ip_addr: String,
    pub scan_host_addr: bool,
    pub use_wordlist: bool,
    pub wordlist_path: String,
    pub timeout: Duration,
    pub save_path: String,
}

impl PortOption {
    pub fn new() -> PortOption {
        let port_option = PortOption {
            ip_addr: String::new(),
            start_port: 0,
            end_port: 0,
            app_port: 65432,
            scan_type: PortScanType::SynScan,
            use_wordlist: false,
            wordlist_path: String::new(),
            if_name: String::new(),
            timeout: Duration::from_millis(30000),
            save_path: String::new(),
        };
        return port_option;
    }
    pub fn set_option(&mut self, arg_value: String){
        let a_vec: Vec<&str> = arg_value.split(":").collect();
        let addr = a_vec[0].to_string();
        let port_range = a_vec[1].to_string();
        let range: Vec<&str> = port_range.split("-").collect();
        let s_port: u16 = range[0].parse().unwrap();
        let e_port: u16 = range[1].parse().unwrap();
        self.ip_addr = addr;
        self.start_port = s_port;
        self.end_port = e_port;
    }
    pub fn set_file_path(&mut self, file_path: String){
        if !file_path.is_empty() {
            self.use_wordlist = true;
            self.wordlist_path = file_path;   
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
    pub fn set_save_path(&mut self, save_path: String){
        self.save_path = save_path;
    }
    pub fn show_options(&self){
        sys::print_fix32("Port Scan Options", sys::FillStr::Hyphen);
        println!("{}IP Address: {}", sys::SPACE4, self.ip_addr);
        println!("{}Port Range: {}-{}", sys::SPACE4, self.start_port, self.end_port);
        match self.scan_type {
            PortScanType::SynScan => {println!("{}Scan Type: Syn Scan", sys::SPACE4);},
            PortScanType::FinScan => {println!("{}Scan Type: Fin Scan", sys::SPACE4);},
            PortScanType::XmasScan => {println!("{}Scan Type: Xmas Scan", sys::SPACE4);},
            PortScanType::NullScan => {println!("{}Scan Type: Null Scan", sys::SPACE4);},
        }
        sys::print_fix32("", sys::FillStr::Hyphen);
    }
}

impl HostOption {
    pub fn new() -> HostOption {
        let host_option = HostOption {
            ip_addr: String::new(),
            scan_host_addr: true,
            use_wordlist: false,
            wordlist_path: String::new(),
            timeout: Duration::from_millis(30000),
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
            self.use_wordlist = true;
            self.wordlist_path = file_path;   
        }
    }
    pub fn set_timeout(&mut self, ms_str: String){
        let timeout: u64 = ms_str.parse().unwrap();
        self.timeout = Duration::from_millis(timeout);
    }
    pub fn set_save_path(&mut self, save_path: String){
        self.save_path = save_path;
    }
    pub fn show_options(&self){
        sys::print_fix32("Host Scan Options", sys::FillStr::Hyphen);
        if self.scan_host_addr {
            println!("{}Target Network: {}", sys::SPACE4, self.ip_addr);
        }else{
            println!("{}Target: Specified in word list {}", sys::SPACE4, self.wordlist_path);
        }
        sys::print_fix32("", sys::FillStr::Hyphen);
    }
}
