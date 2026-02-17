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

### Show help
```sh
nscan --help
```

```
Usage: nscan [OPTIONS] <COMMAND>

Commands:
  port       Scan ports on target host(s) (TCP/UDP/QUIC)
  host       Discover alive hosts (ICMP/UDP/TCP)
  domain     Subdomain enumeration
  interface  Show network interface information
  help       Print this message or the help of the given subcommand(s)

Options:
      --log-level <LOG_LEVEL>  Global log level [default: info] [possible values: error, warn, info, debug, trace]
      --log-file               Log to file (in addition to stdout)
      --log-file-path <FILE>   Log file path (default: ~/.nscan/logs/nscan.log)
      --quiet                  Suppress non-error logs
  -o, --output <FILE>          Save result to a JSON file
      --no-stdout              Suppress stdout output (use with --output)
  -h, --help                   Print help
  -V, --version                Print version
```

### Sub-commands help
```
nscan port --help
nscan host --help
nscan domain --help
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
`nscan` will now be succeeded by [nrev](https://github.com/shellrow/nrev), our network mapping tool.  
Updates to `nscan` will be limited going forward, as we aim to keep `nscan` focused on scanning-specific tasks.
