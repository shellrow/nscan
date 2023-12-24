[crates-badge]: https://img.shields.io/crates/v/nscan.svg
[crates-url]: https://crates.io/crates/nscan
[license-badge]: https://img.shields.io/crates/l/nscan.svg

# nscan [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform network scan tool for host and service discovery.   
Aim to be simple and fast.  

## Features
- Port Scan
- Host Scan
- Service detection
- OS detection

## Installation
### Cargo Install
```
cargo install nscan
```

## Basic Usage
```
USAGE:
    nscan [OPTIONS]

OPTIONS:
    -p, --port <target>                 Scan ports of the specified host.
                                        Use default port list if port range omitted.
                                        Examples:
                                        --port 192.168.1.8 -S -O
                                        --port 192.168.1.8:1-1000
                                        --port 192.168.1.8:22,80,8080
                                        --port 192.168.1.8 -l custom-list.txt
    -n, --host <target>                 Scan hosts in specified network or host-list.
                                        Examples:
                                        --host 192.168.1.0
                                        --host 192.168.1.0/24
                                        --host custom-list.txt
                                        --host 192.168.1.10,192.168.1.20,192.168.1.30
    -e, --interfaces                    List network interfaces
    -i, --interface <interface_name>    Specify the network interface
    -s, --source <ip_addr>              Specify the source IP address
    -P, --protocol <protocol>           Specify the protocol
    -T, --scantype <scantype>           Specify the scan-type
    -t, --timeout <duration>            Set timeout in ms - Example: -t 10000
    -w, --waittime <duration>           Set wait-time in ms (default:100ms) - Example: -w 200
    -r, --rate <duration>               Set send-rate in ms - Example: -r 1
    -R, --random                        Don't randomize targets. By default, nscan randomizes the
                                        order of targets.
    -c, --count <count>                 Set number of requests or pings to be sent
    -S, --service                       Enable service detection
    -A, --async                         Perform asynchronous scan
    -l, --list <file_path>              Use list - Example: -l custom-list.txt
    -W, --wellknown                     Use well-known ports
    -j, --json                          Displays results in JSON format.
    -o, --save <file_path>              Save scan result in json format - Example: -o result.json
        --acceptinvalidcerts            Accept invalid certs (This introduces significant
                                        vulnerabilities)
    -h, --help                          Print help information
    -V, --version                       Print version information
```

## Supported platforms
- Linux
- macOS
- Windows

## Privileges
`nscan` uses a raw socket which require elevated privileges. Execute with administrator privileges.

## Note for Windows Users
If you are using Windows, please consider the following points before building and running the application:

- Npcap or WinPcap Installation:
    - Ensure that you have [Npcap](https://npcap.com/#download) or WinPcap installed on your system.
    - If using Npcap, make sure to install it with the "Install Npcap in WinPcap API-compatible Mode" option.
- Build Dependencies:
    - Place the Packet.lib file from the [Npcap SDK](https://npcap.com/#download) or WinPcap Developers pack in a directory named lib at the root of this repository.
    - You can use any of the locations listed in the %LIB% or $Env:LIB environment variables.
    - For the 64-bit toolchain, the Packet.lib is located in <SDK>/Lib/x64/Packet.lib.
    - For the 32-bit toolchain, the Packet.lib is located in <SDK>/Lib/Packet.lib.

## My related projects
This tool also serves as a test for my following projects.  
- [default-net](https://github.com/shellrow/default-net) Cross-platform library for network interface and gateway 
- [netscan](https://github.com/shellrow/netscan) Cross-platform network scan library 
- [xenet](https://github.com/shellrow/xenet) Cross-platform networking library
