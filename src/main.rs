#[macro_use]
extern crate clap;

mod db;
mod define;
mod handler;
mod models;
mod network;
mod option;
mod os;
mod output;
mod parser;
mod result;
mod scan;
mod sys;
mod validator;
mod json_models;

use chrono::{DateTime, Local};
use clap::{App, AppSettings, Arg, ArgGroup, Command};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        show_app_desc();
        std::process::exit(0);
    }
    let app = get_app_settings();
    let matches = app.get_matches();
    show_banner_with_starttime();
    
    let pb = output::get_spinner();
    pb.set_message("Initializing ...");
    let opt: option::ScanOption = parser::parse_args(matches);
    pb.finish_and_clear();

    output::show_options(opt.clone());
    match opt.command_type {
        option::CommandType::PortScan => match opt.port_scan_type {
            option::ScanType::TcpSynScan => {
                if opt.async_scan && sys::get_os_type() == "windows" {
                    exit_with_error_message("Async TCP SYN Scan is not supported on Windows");
                }
                if privilege::user::privileged() {
                    async_io::block_on(async {
                        handler::handle_port_scan(opt).await;
                    })
                } else {
                    exit_with_error_message("Requires administrator privilege");
                }
            }
            option::ScanType::TcpConnectScan => async_io::block_on(async {
                handler::handle_port_scan(opt).await;
            }),
            _ => {}
        },
        option::CommandType::HostScan => match opt.protocol {
            option::Protocol::ICMPv4 | option::Protocol::ICMPv6 => {
                if privilege::user::privileged() {
                    async_io::block_on(async {
                        handler::handle_host_scan(opt).await;
                    })
                } else {
                    exit_with_error_message("Requires administrator privilege");
                }
            }
            _ => async_io::block_on(async {
                handler::handle_host_scan(opt).await;
            }),
        }
    }
}

fn get_app_settings<'a>() -> Command<'a> {
    let app: App = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::new("port")
            .help("Scan ports of the specified host. \nUse default port list if port range omitted. \nExamples: \n--port 192.168.1.8 -S -O \n--port 192.168.1.8:1-1000 \n--port 192.168.1.8:22,80,8080 \n--port 192.168.1.8 -l custom-list.txt")
            .short('p')
            .long("port")
            .takes_value(true)
            .value_name("target")
            .validator(validator::validate_port_opt)
        )
        .arg(Arg::new("host")
            .help("Scan hosts in specified network or host-list. \nExamples: \n--host 192.168.1.0 \n--host 192.168.1.0/24 \n--host custom-list.txt \n--host 192.168.1.10,192.168.1.20,192.168.1.30")
            .short('n')
            .long("host")
            .takes_value(true)
            .value_name("target")
            .validator(validator::validate_hostscan_opt)
        )
        .arg(Arg::new("interface")
            .help("Specify the network interface")
            .short('i')
            .long("interface")
            .takes_value(true)
            .value_name("name")
            .validator(validator::validate_interface)
        )
        .arg(Arg::new("source")
            .help("Specify the source IP address")
            .short('s')
            .long("source")
            .takes_value(true)
            .value_name("ip_addr")
            .validator(validator::validate_interface)
        )
        .arg(Arg::new("protocol")
            .help("Specify the protocol")
            .short('P')
            .long("protocol")
            .takes_value(true)
            .value_name("protocol")
            .validator(validator::validate_protocol)
        )
        .arg(Arg::new("maxhop")
            .help("Set max hop(TTL) for ping or traceroute")
            .short('m')
            .long("maxhop")
            .takes_value(true)
            .value_name("maxhop")
            .validator(validator::validate_ttl)
        )
        .arg(Arg::new("scantype")
            .help("Specify the scan-type")
            .short('T')
            .long("scantype")
            .takes_value(true)
            .value_name("scantype")
            .validator(validator::validate_portscantype)
        )
        .arg(Arg::new("timeout")
            .help("Set timeout in ms - Example: -t 10000")
            .short('t')
            .long("timeout")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_timeout)
        )
        .arg(Arg::new("waittime")
            .help("Set wait-time in ms (default:100ms) - Example: -w 200")
            .short('w')
            .long("waittime")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_waittime)
        )
        .arg(Arg::new("rate")
            .help("Set send-rate in ms - Example: -r 1")
            .short('r')
            .long("rate")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_waittime)
        )
        .arg(Arg::new("count")
            .help("Set number of requests or pings to be sent")
            .short('c')
            .long("count")
            .takes_value(true)
            .value_name("count")
            .validator(validator::validate_count)
        )
        .arg(Arg::new("service")
            .help("Enable service detection")
            .short('S')
            .long("service")
            .takes_value(false)
        )
        .arg(Arg::new("os")
            .help("Enable OS detection")
            .short('O')
            .long("os")
            .takes_value(false)
        )
        .arg(Arg::new("async")
            .help("Perform asynchronous scan")
            .short('A')
            .long("async")
            .takes_value(false)
        )
        .arg(Arg::new("list")
            .help("Use list - Example: -l custom-list.txt")
            .short('l')
            .long("list")
            .takes_value(true)
            .value_name("file_path")
            .validator(validator::validate_filepath)
        )
        .arg(Arg::new("wellknown")
            .help("Use well-known ports")
            .short('W')
            .long("wellknown")
        )
        .arg(Arg::new("save")
            .help("Save scan result in json format - Example: -o result.json")
            .short('o')
            .long("save")
            .takes_value(true)
            .value_name("file_path")
        )
        .arg(Arg::new("acceptinvalidcerts")
            .help("Accept invalid certs (This introduces significant vulnerabilities)")
            .long("acceptinvalidcerts")
            .takes_value(false)
        )
        .group(ArgGroup::new("mode").args(&["port", "host"]))
        .setting(AppSettings::DeriveDisplayOrder)
        ;
    app
}

fn show_app_desc() {
    println!(
        "{} {} ({}) {}",
        crate_name!(),
        crate_version!(),
        define::CRATE_UPDATE_DATE,
        sys::get_os_type()
    );
    println!("{}", crate_description!());
    println!("{}", crate_authors!());
    println!("{}", define::CRATE_REPOSITORY);
    println!();
    println!("'{} --help' for more information.", crate_name!());
    println!();
}

fn show_banner_with_starttime() {
    println!(
        "{} {} {}",
        crate_name!(),
        crate_version!(),
        sys::get_os_type()
    );
    println!("{}", define::CRATE_REPOSITORY);
    println!();
    let local_datetime: DateTime<Local> = Local::now();
    println!("Probe started at {}", local_datetime);
    println!();
}

fn exit_with_error_message(message: &str) {
    println!();
    println!("Error: {}", message);
    std::process::exit(0);
}
