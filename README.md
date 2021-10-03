[crates-badge]: https://img.shields.io/crates/v/nscan.svg
[crates-url]: https://crates.io/crates/nscan
[license-badge]: https://img.shields.io/crates/l/nscan.svg
[netscan-url]: https://github.com/shellrow/netscan

# nscan [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform network scan tool for host and service discovery. Written in Rust.  
Aim to be simple and fast.  

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
    -d, --detail                Get details (service version and OS)
    -A, --acceptinvalidcerts    Accept invalid certs (This introduces significant vulnerabilities)
    -h, --help                  Prints help information
    -V, --version               Prints version information

OPTIONS:
    -p, --port <ip_addr:port>        Scan ports of the specified host. 
                                     Use default port list if port range omitted. 
                                     Examples 
                                     -p 192.168.1.8 -d 
                                     -p 192.168.1.8:1-1000 
                                     -p 192.168.1.8:22,80,8080 
                                     -p 192.168.1.8 -l custom-list.txt
    -n, --host <ip_addr>             Scan hosts in specified network or list 
                                     Examples 
                                     -n 192.168.1.0 -d 
                                     -n -l custom-list.txt
    -t, --timeout <duration>         Set timeout in ms - Ex: -t 10000
    -a, --waittime <duration>        Set waittime in ms (default:100ms) - Ex: -a 200
    -P, --portscantype <scantype>    Set port scan type (default:SYN) - SYN, CONNECT
    -i, --interface <name>           Specify network interface by name - Ex: -i en0
    -l, --list <file_path>           Use list - Ex: -l custom-list.txt
    -s, --save <file_path>           Save scan result to file - Ex: -s result.txt
```

## Example
Port scan and service version detection   
```
sudo nscan -p 192.168.1.8 -d 
```

Host scan  
```
sudo nscan -n 192.168.1.0   
```

## Supported platforms
- Linux
- macOS (OS X)
- Windows

## About netscan (lib)
Please check my [repository][netscan-url] for detail

## Security Notes
`-A(--acceptinvalidcerts)` flag allow you to trust invalid certificates and attempt TLS connection.  
This flag should not be used unless you are explicitly aware of it, such as when the service you are managing uses self-signed certificate.
