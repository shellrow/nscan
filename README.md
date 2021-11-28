[crates-badge]: https://img.shields.io/crates/v/nscan.svg
[crates-url]: https://crates.io/crates/nscan
[license-badge]: https://img.shields.io/crates/l/nscan.svg
[netscan-url]: https://github.com/shellrow/netscan

# nscan [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform network scan tool for host and service discovery.   
Aim to be simple and fast.  

## Features
- Port Scan
- Host Scan
- Async Port Scan (Currently only Unix-Like OS is supported)
- Async Host Scan (Currently only Unix-Like OS is supported)

## Installation
### Cargo Install
```
cargo install nscan
```

### Download from GitHub Releases 
Pre-built binaries for several OS/architectures are available  
in [Releases](https://github.com/shellrow/nscan/releases) section.  

## Basic Usage
```
USAGE:
    nscan [FLAGS] [OPTIONS]

FLAGS:
    -s, --service               Enable service detection
    -A, --acceptinvalidcerts    Accept invalid certs (This introduces significant vulnerabilities)
    -a, --async                 Perform asynchronous scan
    -O, --OS                    Enable OS detection
    -h, --help                  Prints help information
    -V, --version               Prints version information

OPTIONS:
    -p, --port <ip_addr:port>        Scan ports of the specified host. 
                                     Use default port list if port range omitted. 
                                     Examples 
                                     -p 192.168.1.8 -s -O 
                                     -p 192.168.1.8:1-1000 
                                     -p 192.168.1.8:22,80,8080 
                                     -p 192.168.1.8 -l custom-list.txt
    -n, --network <ip_addr>          Scan hosts in specified network 
                                     Example: -n 192.168.1.0 -O
    -H, --host <host_list>           Scan hosts in specified host-list 
                                     Examples 
                                     -H custom-list.txt -O 
                                     -H 192.168.1.10,192.168.1.20,192.168.1.30 -O
    -t, --timeout <duration>         Set timeout in ms - Ex: -t 10000
    -w, --waittime <duration>        Set waittime in ms (default:100ms) - Ex: -w 200
    -r, --rate <duration>            Set sendrate in ms - Ex: -r 1
    -P, --portscantype <scantype>    Set port scan type (default:SYN) - SYN, CONNECT
    -i, --interface <name>           Specify network interface by IP address - Ex: -i 192.168.1.4
    -l, --list <file_path>           Use list - Ex: -l custom-list.txt
    -o, --output <file_path>         Save scan result in json format - Ex: -o result.json
```

## Example
Port scan with service version and OS detection   
```
sudo nscan -p 192.168.1.8 -s -O
```

Host scan with OS detection 
```
sudo nscan -n 192.168.1.0 -O  
```

-a(--async) flag for asynchronous scan  
-o(--output) option for save json format data to file  

## Supported platforms
- Linux
- macOS (OS X)
- Windows

