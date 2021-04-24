use super::sys;
use rusqlite::{Connection, Transaction, params};
use std::fs::read_to_string;

pub struct Service {
    pub port_number: String,
    pub protocol: String,
    pub service_name: String,
    pub description: String,
}

#[derive(Clone)]
pub struct Oui {
    pub mac_addr: String,
    pub mac_prefix: String,
    pub vendor_name: String,
    pub vendor_name_detail: String,
}

pub fn get_db_connection() -> Result<Connection, String> {
    let file_path = sys::get_db_file_path();
    let c = Connection::open(file_path);
    match c {
        Ok(conn) => Ok(conn),
        Err(e) => Err(format!("Failed to open nscan database. {}", e)),
    }
}

pub fn update_db() -> Result<(), String> {
    let save_path = sys::get_db_file_path();
    match sys::download_file(sys::DB_FILE_URL, save_path.to_str().unwrap()) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{}", e)),
    }
}

pub fn init_db() {
    let conn = match get_db_connection() {
        Ok(conn) => conn,
        Err(e) => panic!("{}", e),
    };
    let sql_str = 
    "CREATE TABLE IF NOT EXISTS SERVICE ( 
        SERIAL_ID INTEGER PRIMARY KEY AUTOINCREMENT,  
        PORT_NUMBER TEXT, 
        PROTOCOL TEXT, 
        SERVICE_NAME TEXT,
        DESCRIPTION TEXT);
     CREATE TABLE IF NOT EXISTS OUI ( 
        SERIAL_ID INTEGER PRIMARY KEY AUTOINCREMENT,  
        MAC_PREFIX TEXT, 
        VENDOR_NAME TEXT,
        VENDOR_NAME_DETAIL TEXT); 
    ";
    match conn.execute_batch(sql_str) {
        Ok(_) => {},
        Err(err) => println!("Error: Create Table: {}", err),
    }
    match conn.close(){
        Ok(_) => {},
        Err(err) => println!("Error: Failed to close database : {:?}", err), 
    }
}

pub fn delete_service(tx: &Transaction) -> Result<(), String> {
    match tx.execute_batch("DELETE FROM SERVICE; DELETE FROM sqlite_sequence WHERE name='SERVICE';") {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("{}", err)),
    }
}

pub fn insert_service(tx: &Transaction, service: Service) -> Result<(), String> {
    let sql_str_ins = "INSERT INTO SERVICE (PORT_NUMBER,PROTOCOL,SERVICE_NAME,DESCRIPTION) VALUES(?1,?2,?3,?4);";
    match tx.execute(sql_str_ins, params![service.port_number,service.protocol,service.service_name,service.description]) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("{}", err)),
    }
}

pub fn delete_oui(tx: &Transaction) -> Result<(), String> {
    match tx.execute_batch("DELETE FROM OUI; DELETE FROM sqlite_sequence WHERE name='OUI';") {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("{}", err)),
    }
}

pub fn insert_oui(tx: &Transaction, oui: Oui) -> Result<(), String> {
    let sql_str_ins = "INSERT INTO OUI (MAC_PREFIX,VENDOR_NAME,VENDOR_NAME_DETAIL) VALUES(?1,?2,?3);";
    match tx.execute(sql_str_ins, params![oui.mac_prefix,oui.vendor_name,oui.vendor_name_detail]) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("{}", err)),
    }
}

pub fn update_service(file_path: &String) -> Result<(), String> {
    let mut conn = match get_db_connection() {
        Ok(conn) => conn,
        Err(e) => return Err(format!("{}", e)),
    };
    let data = read_to_string(file_path);
    let text = match data {
        Ok(content) => content,
        Err(e) => return Err(format!("{}", e)),
    };
    let rows: Vec<&str> = text.split("\n").collect();
    let tx = match conn.transaction(){
        Ok(tx) => tx,
        Err(e) => return Err(format!("{}", e)),
    };
    match delete_service(&tx) {
        Ok(_) => {},
        Err(e) => return Err(format!("{}", e)),
    }
    for row in rows {
        let v: Vec<&str>;
        if file_path.contains(".csv") || file_path.contains(".CSV"){
            v = row.trim().split(",").collect();
        }else{
            v = row.split_whitespace().collect();
        }
        if v.len() < 4 {
            continue;
        }
        if v[1].is_empty() || !sys::is_numeric(v[1]){
            continue;
        }
        //v[0]:service_name, v[1]:port_number, v[2]:transport_protocol, v[3]:description
        let service = Service {
            port_number: String::from(v[1]),
            protocol: String::from(v[2]),
            service_name: String::from(v[0]),
            description: String::from(v[3]),
        };
        match insert_service(&tx, service) {
            Ok(_) => {},
            Err(e) => return Err(format!("{}", e)),
        }
    }
    match tx.commit() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{}", e)),
    }
}

pub fn update_oui(file_path: &String)  -> Result<(), String> {
    let mut conn = match get_db_connection() {
        Ok(conn) => conn,
        Err(e) => return Err(format!("{}", e)),
    };
    let data = read_to_string(file_path);
    let text = match data {
        Ok(content) => content,
        Err(e) => return Err(format!("{}", e)),
    };
    let rows: Vec<&str> = text.split("\n").collect();
    let tx = match conn.transaction(){
        Ok(tx) => tx,
        Err(e) => return Err(format!("{}", e)),
    };
    match delete_oui(&tx) {
        Ok(_) => {},
        Err(e) => return Err(format!("{}", e)),
    }
    for row in rows {
        if row.starts_with("#"){
            continue;
        }
        let v: Vec<&str>;
        if file_path.contains(".csv") || file_path.contains(".CSV"){
            v = row.trim().split(",").collect();
        }else{
            v = row.split_whitespace().collect();
        }
        if v.len() < 3 {
            continue;
        }
        //Vendor detail name may contain spaces
        let mut detail_name: String = String::new();
        if v.len() > 3{
            for i in 2..v.len() {
                detail_name = format!("{} {}", detail_name, v[i]);
            }
        }else{
            detail_name = String::from(v[2]);
        }
        //v[0]:service_name, v[1]:port_number, v[2]:transport_protocol, v[3]:description
        let oui = Oui {
            mac_addr: String::new(),
            mac_prefix: String::from(v[0]),
            vendor_name: String::from(v[1]),
            vendor_name_detail: detail_name,
        };
        match insert_oui(&tx, oui) {
            Ok(_) => {},
            Err(e) => return Err(format!("{}", e)),
        }
    }
    match tx.commit() {
        Ok(_) => Ok(()),
        Err(e) => return Err(format!("{}", e)),
    }
}

pub fn get_service(conn: &Connection, port_number: &str, protocol: &str) -> Result<Service, String> {
    let sql_str = 
    "SELECT 
        PORT_NUMBER, 
        PROTOCOL, 
        SERVICE_NAME, 
        DESCRIPTION  
     FROM 
        SERVICE  
     WHERE 
        PORT_NUMBER = :port_number   
        AND PROTOCOL = :protocol ";
    let service = conn.query_row_named(sql_str, &[(":port_number", &port_number),(":protocol", &protocol)], 
    |row| {
            Ok(Service {
                port_number: row.get(0)?,
                protocol: row.get(1)?,
                service_name: row.get(2)?,
                description: row.get(3)?,
            })
        }
    );
    match service {
        Ok(service) => Ok(service),
        Err(e) => return Err(format!("{}", e)),
    }
}

pub fn get_vendor_info(conn: &Connection, mac_addr: &str) -> Result<Oui, String>{
    if mac_addr.len() < 17{
        return Err(String::from("Invalid mac address"))
    }
    let prefix8 = &mac_addr[0..8].to_uppercase();
    let prefix11 = &mac_addr[0..11].to_uppercase();
    let sql_str = 
    "SELECT 
        MAC_PREFIX,
        VENDOR_NAME, 
        VENDOR_NAME_DETAIL 
     FROM 
        OUI  
     WHERE 
        (MAC_PREFIX = :prefix8 OR MAC_PREFIX LIKE :prefix11 + '%')   
     ORDER BY MAC_PREFIX DESC";
    let oui = conn.query_row_named(sql_str, &[(":prefix8", &prefix8), (":prefix11", &prefix11)], 
    |row| {
            Ok(Oui {
                mac_addr: mac_addr.to_string(),
                mac_prefix: row.get(0)?,
                vendor_name: row.get(1)?,
                vendor_name_detail: row.get(2)?,
            })
        }
    );
    match oui {
        Ok(oui) => Ok(oui),
        Err(e) => return Err(format!("{}", e)),
    }
}
