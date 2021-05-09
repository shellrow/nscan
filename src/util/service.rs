use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::io::{BufReader, BufWriter};
use std::net::{ToSocketAddrs,TcpStream};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use dns_lookup::lookup_addr;
use native_tls::TlsConnector;
use std::io::prelude::*;
use rayon::prelude::*;
use std::sync::mpsc::Sender;

pub fn detect_service_version(ipaddr:Ipv4Addr, ports: Vec<u16>, accept_invalid_certs: bool, thread_tx: Sender<usize>) -> HashMap<u16, String> {
    let service_map: Arc<Mutex<HashMap<u16, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let thread_tx: Arc<Mutex<Sender<usize>>> = Arc::new(Mutex::new(thread_tx));
    let conn_timeout = Duration::from_millis(50);
    ports.into_par_iter().for_each(|port| 
        {
            let socket_addr_str = format!("{}:{}", ipaddr, port);
            let mut addrs = socket_addr_str.to_socket_addrs().expect("Invalid socket addr.");
            if let Some(addr) = addrs.find(|x| (*x).is_ipv4()) {
                match TcpStream::connect_timeout(&addr, conn_timeout) {
                    Ok(stream) => {
                        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("Failed to set read timeout.");
                        let mut reader = BufReader::new(&stream);
                        let mut writer = BufWriter::new(&stream);
                        let msg: String;
                        match port {
                            80 => {
                                write_head_request(&mut writer, ipaddr.to_string());
                                let header = read_response(&mut reader);
                                msg = parse_header(header);
                            },
                            443 => {
                                let header = head_request_secure(ipaddr.to_string(), accept_invalid_certs);
                                msg = parse_header(header);
                            },
                            _ => {
                                msg = read_response(&mut reader).replace("\r\n", "");
                            },
                        }
                        service_map.lock().unwrap().insert(port, msg);
                    },
                    Err(_) => {},
                }
            }
            thread_tx.lock().unwrap().send(1).unwrap();
        }
    );
    thread_tx.lock().unwrap().send(0).unwrap();
    let result_map: HashMap<u16, String> = service_map.lock().unwrap().clone();
    return result_map;
}

fn read_response(reader: &mut BufReader<&TcpStream>) -> String {
    let mut msg = String::new();
    match reader.read_to_string(&mut msg) {
        Ok(_) => {},
        Err(_) => {},
    }
    return msg;
}

fn write_head_request(writer: &mut BufWriter<&TcpStream>, ipaddr:String) {
    let msg = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\n\r\n", ipaddr);
    match writer.write(msg.as_bytes()) {
        Ok(_) => {},
        Err(_) => {},
    }
    writer.flush().unwrap();
}

fn parse_header(response_header: String) -> String {
    let header_fields: Vec<&str>  = response_header.split("\r\n").collect();
    if header_fields.len() == 1 {
        return response_header;
    }
    let mut result_vec: Vec<String> = vec![];
    for field in header_fields {
        if field.contains("Server:") || field.contains("Location:") {
            result_vec.push(field.to_string());
        }
    }
    return result_vec.iter().map(|s| s.trim()).collect::<Vec<_>>().join("\n");
}

fn head_request_secure(ipaddr:String, accept_invalid_certs: bool) -> String {
    let ip_addr: std::net::IpAddr = match IpAddr::from_str(&ipaddr) {
        Ok(ip) => ip,
        Err(_) => return String::new(),
    };
    let host = match lookup_addr(&ip_addr){
        Ok(host) => host,
        Err(_) => ipaddr,
    };
    let connector = if accept_invalid_certs {
        match TlsConnector::builder().danger_accept_invalid_certs(true).build() {
            Ok(c) => c,
            Err(e) => return e.to_string(),
        }
    }else{
        match TlsConnector::new() {
            Ok(c) => c,
            Err(e) => return e.to_string(),
        }
    };
    let stream = match TcpStream::connect(format!("{}:443", host)) {
        Ok(s) => s,
        Err(e) => return e.to_string(),
    };
    match stream.set_read_timeout(Some(Duration::from_secs(20))) {
        Ok(_) => {},
        Err(e) => return e.to_string(),
    }
    let mut stream = match connector.connect(&host, stream) {
        Ok(s) => s,
        Err(e) => return e.to_string(),
    };
    let msg = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\n\r\n", host);
    match stream.write(msg.as_bytes()){
        Ok(_) => {},
        Err(e) => return e.to_string(),
    }
    let mut res = vec![];
    match stream.read_to_end(&mut res){
        Ok(_) => {
            let result = String::from_utf8_lossy(&res);
            return result.to_string();
        },
        Err(e) => return e.to_string(),
    };
}
