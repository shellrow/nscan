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
    -S, --singlethread          Run port scan in single-thread (default is multi-thread)
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
If you omit the port specification, use nscan-default-ports.  
```
shellrow@MacBook-Pro nscan % sudo nscan -p 192.168.1.8 -d -m
nscan 0.6.0 macos
https://github.com/shellrow/nscan

Scan started at 2021-06-27 02:03:16.422970

+------------------------------------------------+
|                Port Scan Options               |
+-------------+----------------------------------+
| IP Address  | 192.168.1.8                      |
+-------------+----------------------------------+
| Port List   | nscan-default-ports (1005 ports) |
+-------------+----------------------------------+
| Scan Type   | Syn Scan                         |
+-------------+----------------------------------+

Scanning ports... 
[00:00:00] ██████████████████████████████████████████████████████████████████████████ 1005/1005 Done
Detecting service version... 
[00:00:05] ████████████████████████████████████████████████████████████████████████████████ 3/3 Done

+---------------------------------------------------------------------+
|                             Scan Reports                            |
+---------------------------------------------------------------------+
|                3 open port(s) / scanned 1005 port(s)                |
+--------------+-------------+----------------------------------------+
| PORT         | SERVICE     | SERVICE VERSION                        |
+--------------+-------------+----------------------------------------+
| 22           | ssh         | SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb1 |
|              |             | 0u2                                    |
+--------------+-------------+----------------------------------------+
| 80           | http        | Server: Apache/2.4.38 (Raspbian)       |
+--------------+-------------+----------------------------------------+
| 5900         | rfb         | RFB 005.000                            |
+--------------+-------------+----------------------------------------+

+----------------------------------------+
|               Performance              |
+-------------------------+--------------+
| Port Scan Time          | 440.466082ms |
+-------------------------+--------------+
| Service Detection Time  | 5.065088811s |
+-------------------------+--------------+
```

Host scan  
```
shellrow@MacBook-Pro nscan % sudo nscan -n 192.168.1.0
nscan 0.6.0 macos
https://github.com/shellrow/nscan

Scan started at 2021-06-26 20:48:06.204886

+------------------------------+
|       Host Scan Options      |
+----------------+-------------+
| Target Network | 192.168.1.0 |
+----------------+-------------+
| Scan Type      | ICMP        |
+----------------+-------------+

Scanning... 
[00:00:00] ████████████████████████████████████████████████████████████████████████████ 254/254 Done

+-------------------------------------------------+
|                   Scan Reports                  |
+-------------------------------------------------+
|        5 host(s) up / 254 IP address(es)        |
+---------------+-------------------+-------------+
| IP ADDR       | MAC ADDR          | VENDOR NAME |
+---------------+-------------------+-------------+
| 192.168.1.1   | 00:80:87:77:a0:b0 | OkiElect    |
+---------------+-------------------+-------------+
| 192.168.1.4   | 27:8c:fd:b7:a1:b1 | Own device  |
+---------------+-------------------+-------------+
| 192.168.1.8   | b8:27:eb:f1:a2:b2 | Raspberr    |
+---------------+-------------------+-------------+
| 192.168.1.16  | 30:9c:23:d6:a3:b3 | Micro-St    |
+---------------+-------------------+-------------+
| 192.168.1.32  | 74:d4:35:b2:a4:b4 | Giga-Byt    |
+---------------+-------------------+-------------+

+--------------------------+
|        Performance       |
+-----------+--------------+
| Scan Time | 542.996373ms |
+-----------+--------------+
```

## Supported platforms
- Linux
- macOS (OS X)
- Windows

## Scan performance  
nscan supports multi-threaded port scanning, but some environments (especially VMs) may experience performance problems.  

## About netscan (lib)
Please check my [repository][netscan-url] for detail

## Security Notes
`-A(--acceptinvalidcerts)` flag allow you to trust invalid certificates and attempt TLS connection.  
This flag should not be used unless you are explicitly aware of it, such as when the service you are managing uses self-signed certificate.
