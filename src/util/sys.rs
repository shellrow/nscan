use reqwest;
use std::io::prelude::*;
use std::fs::{self, File};
use std::{env, io};
use std::path::{PathBuf};
use std::net::{IpAddr};
use std::str::FromStr;
use ipnet::{Ipv4Net, Ipv6Net};

#[cfg(any(unix, macos))]
use sudo::RunningAs;

#[cfg(target_os = "windows")]
use super::win;

pub const NSCAN_DATA_DIR: &str = "data";
//pub const NSCAN_INI_FILE: &str = "nscan.ini";
pub const NSCAN_DB_FILE: &str = "nscan.db";
pub const SPACE4: &str = "    ";
pub const DB_FILE_URL: &str = "https://github.com/shellrow/dataset/raw/main/nscan/nscan.db";

#[allow(dead_code)]
pub enum FillStr{
    Hyphen,
    Equal,
}

pub fn get_exe_dir_path() -> io::Result<PathBuf> {
    let mut dir = env::current_exe()?;
    dir.pop();
    Ok(dir)
}

/* pub fn get_config_file_path() -> PathBuf{
    let mut path = get_exe_dir_path().expect("could not get exe dir path.");
    path.push(NSCAN_DATA_DIR);
    path.push(NSCAN_INI_FILE);
    return path;
} */

pub fn get_db_file_path() -> PathBuf{
    let mut path = get_exe_dir_path().expect("could not get exe dir path.");
    //let mut path = env::current_dir().expect("could not get exe dir path.");
    path.push(NSCAN_DATA_DIR);
    path.push(NSCAN_DB_FILE);
    return path;
}

pub fn get_network_address(ip_str: String) -> Result<String, String>{
    let addr = IpAddr::from_str(&ip_str);
    match addr {
        Ok(ip_addr) => {
            match ip_addr {
                IpAddr::V4(ipv4_addr) => {
                    let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24).unwrap();
                    Ok(net.network().to_string())
                },
                IpAddr::V6(ipv6_addr) => {
                    let net: Ipv6Net = Ipv6Net::new(ipv6_addr, 24).unwrap();
                    Ok(net.network().to_string())
                },
            }
        },
        Err(_) => {
            Err(String::from("Invalid IP Address"))
        }
    }
}

pub fn print_fix32(msg: &str, fill_str: FillStr){
    if msg.len() >= 32 {
        println!("{}", msg);
        return;
    }
    match fill_str {
        FillStr::Hyphen => {
            println!("-{}{}",msg,"-".repeat(31 - msg.len()));
        },
        FillStr::Equal => {
            println!("={}{}",msg,"=".repeat(31 - msg.len()));
        },
    }
}

pub fn is_numeric(v: &str) -> bool{
    let dec = v.trim().parse::<f64>();
    match dec {
        Ok(_) => return true,
        Err(_) => return false, 
    }
}

pub fn download_file(url: &str, save_path: &str) -> Result<(), String> {
    let response = match reqwest::blocking::get(url) {
        Ok(response) => response,
        Err(e) => return Err(format!("{}", e)),
    };
    let mut out = match File::create(save_path){
        Ok(out) => out,
        Err(e) => return Err(format!("{}", e)),
    };
    let content = match response.bytes(){
        Ok(content) => content,
        Err(e) => return Err(format!("{}", e)),
    };
    match out.write_all(&content){
        Ok(_) => {},
        Err(e) => return Err(format!("{}", e)),
    }
    Ok(())
}

#[cfg(any(unix, macos))]
pub fn check_root() -> bool{
    let user_privilege = sudo::check();
    match user_privilege {
        RunningAs::Root => {
            true
        },
        RunningAs::User => {
            false
        },
        RunningAs::Suid => {
            true
        },
    }
}

#[cfg(target_os = "windows")]
pub fn check_root() -> bool{
    if win::is_elevated() {
        return true;
    } else {
        return false;
    }
}

pub fn save_file(file_path: String, data: String){
    let msg = format!("Unable to write file: {}", &file_path);
    fs::write(file_path, data).expect(&msg);
}

/*
fn read<T: std::str::FromStr>() -> T {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).ok();
    s.trim().parse().ok().unwrap()
}
*/
