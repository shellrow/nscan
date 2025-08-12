[crates-badge]: https://img.shields.io/crates/v/nscan.svg
[crates-url]: https://crates.io/crates/nscan
[license-badge]: https://img.shields.io/crates/l/nscan.svg

# nscan [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform network scan tool for host and service discovery.   
Aims to be simple, fast, and efficient in performance.

## Features
- Port scan
- Host scan
- Service detection
- OS family detection
- Subdomain scan

## Installation
### Install prebuilt binaries via shell script

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/nscan/releases/latest/download/nscan-installer.sh | sh
```

### Install prebuilt binaries via powershell script

```sh
irm https://github.com/shellrow/nscan/releases/latest/download/nscan-installer.ps1 | iex
```

### From Releases
You can download archives of precompiled binaries from the [releases](https://github.com/shellrow/nscan/releases) .

### Using Cargo

```sh
cargo install nscan
```

Or you can use [binstall](https://github.com/cargo-bins/cargo-binstall) for install nscan from github release.
```sh
cargo binstall nscan
```

## Basic Usage

## Default Port Scan
To scan the default ports on a target, simply specify the target:
```
nscan --target scanme.nmap.org
```

## Sub-commands and Options 
```
Usage: nscan [OPTIONS] [COMMAND]

Commands:
  port        Scan port. nscan port --help for more information
  host        Scan host in specified network or host-list. nscan host --help for more information
  subdomain   Find subdomains. nscan subdomain --help for more information
  interfaces  Show network interfaces
  interface   Show default network interface
  help        Print this message or the help of the given subcommand(s)

Options:
  -t, --target <target>             Specify the target host. IP address or Hostname
  -i, --interface <interface_name>  Specify the network interface
      --noping                      Disable initial ping
  -F, --full                        Scan all ports (1-65535)
  -j, --json                        Displays results in JSON format.
  -o, --save <file_path>            Save scan result in JSON format - Example: -o result.json
  -q, --quiet                       Quiet mode. Suppress output. Only show final results.
  -h, --help                        Print help
  -V, --version                     Print version
```

## Supported platforms
- Linux
- macOS
- Windows

## Privileges
`nscan` uses raw sockets, which require elevated privileges. Execute with administrator rights.

## Notes for Windows Users
When using nscan on Windows, please consider the following:

- Npcap/WinPcap Installation:
    - Ensure that [Npcap](https://npcap.com/#download) or WinPcap is installed on your system.
    - If using Npcap, install it with the "Install Npcap in WinPcap API-compatible Mode" option.
- Build Dependencies:
    - Place the Packet.lib file from the [Npcap SDK](https://npcap.com/#download) or WinPcap Developers pack in a directory named lib at the root of this repository.
    - The file can be found in the %LIB% or $Env:LIB environment variables.
    - Locate Packet.lib in <SDK>/Lib/x64/Packet.lib for the 64-bit toolchain or <SDK>/Lib/Packet.lib for the 32-bit toolchain.

## Notice
`nscan` will now be succeeded by [nrev](https://github.com/shellrow/nrev), our network mapping tool. Updates to `nscan` will be limited going forward, as we aim to keep `nscan` focused on scanning-specific tasks. 
