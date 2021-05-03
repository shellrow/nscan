use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::io::{BufReader, BufWriter};
use std::net::{ToSocketAddrs,TcpStream};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use reqwest::header::SERVER;
use dns_lookup::lookup_addr;
use std::io::prelude::*;
use rayon::prelude::*;

pub fn detect_service_version(ipaddr:Ipv4Addr, ports: Vec<u16>) -> HashMap<u16, String> {
    let service_map: Arc<Mutex<HashMap<u16, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let conn_timeout = Duration::from_millis(50);
    ports.into_par_iter().for_each(|port| 
        {
            let socket_addr_str = format!("{}:{}", ipaddr, port);
            let mut addrs = socket_addr_str.to_socket_addrs().expect("Invalid socket addr.");
            if let Some(addr) = addrs.find(|x| (*x).is_ipv4()) {
                match TcpStream::connect_timeout(&addr, conn_timeout) {
                    Ok(stream) => {
                        stream.set_read_timeout(Some(Duration::from_secs(2))).expect("Failed to set read timeout.");
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
                                msg = head_request_secure(ipaddr.to_string());
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
        }
    );
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
    for field in header_fields {
        if field.contains("Server:") {
            return field.replace("Server: ", "");
        }
    }
    return String::new();
}

fn head_request_secure(ipaddr:String) -> String {
    let ip_addr: std::net::IpAddr = match IpAddr::from_str(&ipaddr) {
        Ok(ip) => ip,
        Err(_) => return String::new(),
    };
    let host = match lookup_addr(&ip_addr){
        Ok(host) => host,
        Err(_) => ipaddr,
    };
    let client = match reqwest::blocking::Client::builder().danger_accept_invalid_certs(true).build() {
        Ok(c) => c,
        Err(_) => {
            return String::new();
        },
    };
    let url: String = format!("https://{}/", host);
    match client.head(&url).send() {
        Ok(res) => {
            if res.status().is_success() {
                if let Some(server) = res.headers().get(SERVER){
                    match server.to_str() {
                        Ok(server_info) => {
                            return server_info.to_string();
                        },
                        Err(_) => {
                            return String::new();
                        },
                    }
                }
            }
        },
        Err(e) => {
            return e.to_string();
        },
    }
    return String::new();
}
