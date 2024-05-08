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
- OS familly detection

## Installation
### Releases
You can download archives of precompiled binaries from the [releases](https://github.com/shellrow/nscan/releases) .

### Cargo Install
```
cargo install nscan
```

## Basic Usage

## Default port scan
Simply, specify the target
```
nscan --target scanme.nmap.org
```

## sub-commands and options 
```
Usage: nscan [OPTIONS] [COMMAND]

Commands:
  pscan       Scan port. nscan pscan --help for more information
  hscan       Scan host in specified network or host-list. nscan hscan --help for more information
  subdomain   Find subdomains. nscan subdomain --help for more information
  nei         Resolve IP address to MAC address
  interfaces  Show network interfaces
  interface   Show default network interface
  check       Check dependencies (Windows only)
  help        Print this message or the help of the given subcommand(s)

Options:
  -t, --target <target>             Specify the target host. IP address or Hostname
  -i, --interface <interface_name>  Specify the network interface
      --noping                      Disable initial ping
  -F, --full                        Scan all ports (1-65535)
  -j, --json                        Displays results in JSON format.
  -o, --save <file_path>            Save scan result in JSON format - Example: -o result.json
  -h, --help                        Print help
  -V, --version                     Print version
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
- [netdev](https://github.com/shellrow/netdev) Cross-platform library for network interface and gateway 
- [nex](https://github.com/shellrow/nex) Cross-platform networking library
