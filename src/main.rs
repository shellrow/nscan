#[macro_use]
extern crate clap;

extern crate ipnet;
extern crate netscan;

mod process;
mod option;
mod define;
mod db;
mod model;
mod parser;
mod handler;
mod interface;
mod validator;
mod network;
mod probe;
mod result;
mod printer;

use std::env;
use chrono::{Local, DateTime};
use clap::{App, AppSettings, Arg, ArgGroup};
use crossterm::style::Colorize;

#[cfg(target_os = "windows")]
fn get_os_type() -> String{"windows".to_owned()}

#[cfg(target_os = "linux")]
fn get_os_type() -> String{"linux".to_owned()}

#[cfg(target_os = "macos")]
fn get_os_type() -> String{"macos".to_owned()}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        show_app_desc();
        std::process::exit(0);
    }
    let app = get_app_settings();
    let matches = app.get_matches();
    let mut require_admin = if get_os_type() == "windows"{false}else{true};
    //Scan
    show_banner_with_starttime();
    if matches.is_present("port"){
        if let Some(p) = matches.value_of("portscantype") {
            if p == "CONNECT" {
                require_admin = false;
            }else{
                if matches.is_present("async") && get_os_type() == "windows" {
                    exit_with_error_message("Asynchronous TCP SYN SCAN is not supported on Windows");
                }
            }
        }else{
            if matches.is_present("async") && get_os_type() == "windows" {
                exit_with_error_message("Asynchronous TCP SYN SCAN is not supported on Windows");
            }
        }
        if require_admin && !process::privileged() {
            exit_with_error_message("This feature requires administrator privileges.");
        }
        let opt = parser::parse_port_args(matches);
        handler::handle_port_scan(opt);
    }else if matches.is_present("network") || matches.is_present("host") {
        if require_admin && !process::privileged() {
            exit_with_error_message("This feature requires administrator privileges.");
        }
        let opt = parser::parse_host_args(matches);
        handler::handle_host_scan(opt);
    }else{
        exit_with_error_message("Scan mode not specified.");
    }
}

fn get_app_settings<'a, 'b>() -> App<'a, 'b> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .author(define::CRATE_AUTHOR_GITHUB)
        .about(crate_description!())
        .arg(Arg::with_name("port")
            .help("Scan ports of the specified host. \nUse default port list if port range omitted. \nExamples \n-p 192.168.1.8 -s -O \n-p 192.168.1.8:1-1000 \n-p 192.168.1.8:22,80,8080 \n-p 192.168.1.8 -l custom-list.txt")
            .short("p")
            .long("port")
            .takes_value(true)
            .value_name("ip_addr:port")
            .validator(validator::validate_port_opt)
        )
        .arg(Arg::with_name("network")
            .help("Scan hosts in specified network \nExample: -n 192.168.1.0 -O")
            .short("n")
            .long("network")
            .takes_value(true)
            .value_name("ip_addr")
            .validator(validator::validate_network_opt)
        )
        .arg(Arg::with_name("host")
            .help("Scan hosts in specified host-list \nExamples \n-H custom-list.txt -O \n-H 192.168.1.10,192.168.1.20,192.168.1.30 -O")
            .short("H")
            .long("host")
            .takes_value(true)
            .value_name("host_list")
            .validator(validator::validate_host_opt)
        )
        .arg(Arg::with_name("timeout")
            .help("Set timeout in ms - Ex: -t 10000")
            .short("t")
            .long("timeout")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_timeout)
        )
        .arg(Arg::with_name("waittime")
            .help("Set waittime in ms (default:100ms) - Ex: -w 200")
            .short("w")
            .long("waittime")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_waittime)
        )
        .arg(Arg::with_name("rate")
            .help("Set sendrate in ms - Ex: -r 1")
            .short("r")
            .long("rate")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_waittime)
        )
        .arg(Arg::with_name("portscantype")
            .help("Set port scan type (default:SYN) - SYN, CONNECT")
            .short("P")
            .long("portscantype")
            .takes_value(true)
            .value_name("scantype")
            .validator(validator::validate_portscantype)
        )
        .arg(Arg::with_name("interface")
            .help("Specify network interface by IP address - Ex: -i 192.168.1.4")
            .short("i")
            .long("interface")
            .takes_value(true)
            .value_name("name")
            .validator(validator::validate_interface)
        )
        .arg(Arg::with_name("list")
            .help("Use list - Ex: -l custom-list.txt")
            .short("l")
            .long("list")
            .takes_value(true)
            .value_name("file_path")
            .validator(validator::validate_filepath)
        )
        .arg(Arg::with_name("service")
            .help("Enable service detection")
            .short("s")
            .long("service")
            .takes_value(false)
        )
        .arg(Arg::with_name("acceptinvalidcerts")
            .help("Accept invalid certs (This introduces significant vulnerabilities)")
            .short("A")
            .long("acceptinvalidcerts")
            .takes_value(false)
        )
        .arg(Arg::with_name("output")
            .help("Save scan result in json format - Ex: -o result.json")
            .short("o")
            .long("output")
            .takes_value(true)
            .value_name("file_path")
        )
        .arg(Arg::with_name("async")
            .help("Perform asynchronous scan")
            .short("a")
            .long("async")
            .takes_value(false)
        )
        .arg(Arg::with_name("OS")
            .help("Enable OS detection")
            .short("O")
            .long("OS")
            .takes_value(false)
        )
        .group(ArgGroup::with_name("mode")
            .args(&["port", "network", "host"])
        )
        .setting(AppSettings::DeriveDisplayOrder)
        ;
        app
}

fn show_app_desc() {
    println!("{} {} ({}) {}", crate_name!(), crate_version!(), define::CRATE_UPDATE_DATE, get_os_type());
    println!("{}", crate_description!());
    println!("{}", define::CRATE_AUTHOR_GITHUB);
    println!();
    println!("'{} --help' for more information.", crate_name!());
    println!();
}

fn show_banner_with_starttime() {
    println!("{} {} {}", crate_name!(), crate_version!(), get_os_type());
    println!("{}", define::CRATE_REPOSITORY);
    println!();
    let local_datetime: DateTime<Local> = Local::now();
    println!("Scan started at {}", local_datetime);
    println!();
}

fn exit_with_error_message(message: &str) {
    println!();
    println!("{} {}", "Error:".red(), message);
    std::process::exit(0);
}
