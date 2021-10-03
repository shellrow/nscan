#[macro_use]
extern crate clap;

extern crate ipnet;
extern crate netscan;

mod os;
mod option;
mod define;
mod db;
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
    let mut require_admin = true;
    //Scan
    show_banner_with_starttime();
    if matches.is_present("port"){
        if let Some(p) = matches.value_of("portscantype") {
            if p == "CONNECT" {
                require_admin = false;
            }
        }
        if require_admin && !os::privileged() {
            println!("{} This feature requires administrator privileges. ","Error:".red());
            std::process::exit(0);
        }
        let opt = parser::parse_port_args(matches);
        handler::handle_port_scan(opt);
    }else if matches.is_present("host") {
        if !os::privileged() {
            println!("{} This feature requires administrator privileges. ","Error:".red());
            std::process::exit(0);
        }
        let opt = parser::parse_host_args(matches);
        handler::handle_host_scan(opt);
    }else{
        println!();
        println!("Error: Scan mode not specified.");
        std::process::exit(0);
    }
}

fn get_app_settings<'a, 'b>() -> App<'a, 'b> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .author(define::CRATE_AUTHOR_GITHUB)
        .about(crate_description!())
        .arg(Arg::with_name("port")
            .help("Scan ports of the specified host. \nUse default port list if port range omitted. \nExamples \n-p 192.168.1.8 -d \n-p 192.168.1.8:1-1000 \n-p 192.168.1.8:22,80,8080 \n-p 192.168.1.8 -l custom-list.txt")
            .short("p")
            .long("port")
            .takes_value(true)
            .value_name("ip_addr:port")
            .validator(validator::validate_port_opt)
        )
        .arg(Arg::with_name("host")
            .help("Scan hosts in specified network or list \nExamples \n-n 192.168.1.0 -d \n-n -l custom-list.txt")
            .short("n")
            .long("host")
            .takes_value(true)
            .value_name("ip_addr")
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
            .help("Set waittime in ms (default:100ms) - Ex: -a 200")
            .short("a")
            .long("waittime")
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
            .help("Specify network interface by name - Ex: -i en0")
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
        .arg(Arg::with_name("detail")
            .help("Get details (service version and OS)")
            .short("d")
            .long("detail")
            .takes_value(false)
        )
        .arg(Arg::with_name("acceptinvalidcerts")
            .help("Accept invalid certs (This introduces significant vulnerabilities)")
            .short("A")
            .long("acceptinvalidcerts")
            .takes_value(false)
        )
        .arg(Arg::with_name("save")
            .help("Save scan result to file - Ex: -s result.txt")
            .short("s")
            .long("save")
            .takes_value(true)
            .value_name("file_path")
        )
        .group(ArgGroup::with_name("mode")
            .args(&["port", "host"])
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
