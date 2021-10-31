use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::io::{BufReader, BufWriter};
use std::net::{TcpStream,SocketAddr};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use native_tls::TlsConnector;
use std::io::prelude::*;
use rayon::prelude::*;
use crate::db;

pub fn detect_service_version(ipaddr:Ipv4Addr, ports: Vec<u16>, host_name: String, accept_invalid_certs: bool) -> HashMap<u16, String> {
    let service_map: Arc<Mutex<HashMap<u16, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let conn_timeout = Duration::from_millis(50);
    let nscan_http_ports = db::get_http_ports();
    let nscan_https_ports = db::get_https_ports();
    ports.into_par_iter().for_each(|port| 
        {
            let sock_addr: SocketAddr = SocketAddr::new(IpAddr::V4(ipaddr), port);
            match TcpStream::connect_timeout(&sock_addr, conn_timeout) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("Failed to set read timeout.");
                    let mut reader = BufReader::new(&stream);
                    let mut writer = BufWriter::new(&stream);
                    let msg: String;
                    if nscan_http_ports.contains(&port) {
                        write_head_request(&mut writer, ipaddr.to_string());
                        let header = read_response(&mut reader);
                        msg = parse_header(header);
                    }else if nscan_https_ports.contains(&port) {
                        let header = head_request_secure(host_name.clone(), port, accept_invalid_certs);
                        msg = parse_header(header);
                    }else{
                        msg = read_response(&mut reader).replace("\r\n", "");
                    }
                    service_map.lock().unwrap().insert(port, msg);
                },
                Err(_) => {},
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
    if header_fields.len() == 1 {
        return response_header;
    }
    let mut result_vec: Vec<String> = vec![];
    for field in header_fields {
        if field.contains("Server:") || field.contains("Location:") {
            result_vec.push(field.to_string());
        }
    }
    return result_vec.iter().map(|s| s.trim()).collect::<Vec<_>>().join("\t");
}

fn head_request_secure(host_name: String, port: u16, accept_invalid_certs: bool) -> String {
    if host_name.is_empty() {
        return String::from("Invalid host name");
    }
    let sock_addr: String = format!("{}:{}",host_name, port);
    let connector = if accept_invalid_certs {
        match TlsConnector::builder().danger_accept_invalid_certs(true).build() {
            Ok(c) => c,
            Err(e) => return format!("Error: {}",e.to_string()),
        }
    }else{
        match TlsConnector::new() {
            Ok(c) => c,
            Err(e) => return format!("Error: {}",e.to_string()),
        }
    };
    let stream = match TcpStream::connect(sock_addr.clone()) {
        Ok(s) => s,
        Err(e) => return format!("Error: {}",e.to_string()),
    };
    match stream.set_read_timeout(Some(Duration::from_secs(10))) {
        Ok(_) => {},
        Err(e) => return format!("Error: {}",e.to_string()),
    }
    let mut stream = match connector.connect(host_name.as_str(), stream) {
        Ok(s) => s,
        Err(e) => return format!("Error: {}",e.to_string()),
    };
    let msg = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\n\r\n", host_name);
    match stream.write(msg.as_bytes()){
        Ok(_) => {},
        Err(e) => return format!("Error: {}",e.to_string()),
    }
    let mut res = vec![];
    match stream.read_to_end(&mut res){
        Ok(_) => {
            let result = String::from_utf8_lossy(&res);
            return result.to_string();
        },
        Err(e) => return format!("Error: {}",e.to_string()),
    };
}
