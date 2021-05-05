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
    -p, --port <ip_addr:port>        Port Scan - Ex: -p 192.168.1.8:1-1024 (or 192.168.1.8:22,80,443)
    -n, --host <ip_addr>             Scan hosts in specified network - Ex: -n 192.168.1.0
    -t, --timeout <duration>         Set timeout in ms - Ex: -t 10000
    -a, --waittime <duration>        Set waittime in ms (default:100ms) - Ex: -a 200
    -P, --portscantype <scantype>    Set port scan type (default:SYN) - Ex: -P SYN
    -i, --interface <name>           Specify network interface by name - Ex: -i en0
    -l, --list <file_path>           Use list - Ex: -l common-ports.txt
    -s, --save <file_path>           Save scan result to file - Ex: -s result.txt
```

## Example
Port scan and service version detection  
If you omit the port specification, use nscan-default-ports  
```
shellrow@MacBook-Pro nscan % sudo nscan -p 192.168.1.8 -d
nscan 0.4.0 macos
https://github.com/shellrow/nscan

Scan started at 2021-05-04 23:58:40.139326

----Port Scan Options-------------------------------------------
    IP Address: 192.168.1.8
    Port List: nscan-default-ports (1005 ports)
    Scan Type: Syn Scan
----------------------------------------------------------------

Scanning ports... Done
Detecting service version... Done

----Scan Reports------------------------------------------------
3 open port(s) / scanned 1005 port(s) 
    PORT    SERVICE
      22    ssh
            SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2
      80    http
            Server: Apache/2.4.38 (Raspbian)
    5900    rfb
            RFB 005.000
----------------------------------------------------------------
Scan Time: 1.732023441s
(Including 100ms of wait time)
```

Host scan  
```
shellrow@MacBook-Pro nscan % sudo nscan -n 192.168.1.0    
nscan 0.4.0 macos
https://github.com/shellrow/nscan

Scan started at 2021-05-04 23:58:12.324610

----Host Scan Options-------------------------------------------
    Target Network: 192.168.1.0
----------------------------------------------------------------

Scanning... Done

----Scan Reports------------------------------------------------
5 host(s) up / 254 IP address(es)
    IP ADDR             MAC ADDR
    192.168.1.1         00:80:87:77:a1:b1 OkiElect
    192.168.1.4         27:8c:fd:b7:a2:b2 Own device
    192.168.1.8         b8:27:eb:f1:a3:b3 Raspberr
    192.168.1.16        30:9c:23:d6:a4:b4 Micro-St
    192.168.1.32        74:d4:35:b2:a5:b5 Giga-Byt
----------------------------------------------------------------
Scan Time: 543.253681ms
(Including 100ms of wait time)
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

## Additional Notes
This tool is intended for network analysis.  
