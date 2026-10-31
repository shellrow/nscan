[crates-badge]: https://img.shields.io/crates/v/nscan.svg
[crates-url]: https://crates.io/crates/nscan
[license-badge]: https://img.shields.io/crates/l/nscan.svg

# nscan [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Cross-platform network scanner for host and service discovery.

## Features
- Port scan
- Host scan
- Service detection
- Optional service and OS identification through Nmap
- Subdomain scan

## Installation
### Install prebuilt binaries via shell script

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/nscan/releases/latest/download/nscan-installer.sh | sh
```

### Install prebuilt binaries via PowerShell

```sh
irm https://github.com/shellrow/nscan/releases/latest/download/nscan-installer.ps1 | iex
```

### From Releases
Download precompiled binaries from [Releases](https://github.com/shellrow/nscan/releases).

### Using Cargo

```sh
cargo install nscan
```

Alternatively, install a precompiled binary with [cargo-binstall](https://github.com/cargo-bins/cargo-binstall):
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
  port       Scan ports on target host(s) (TCP/QUIC)
  host       Discover alive hosts (ICMP/UDP/TCP)
  domain     Subdomain enumeration
  interface  Show network interface information
  help       Print this message or the help of the given subcommand(s)

Options:
      --log-level <LOG_LEVEL>  Global log level [default: info] [possible values: error, warn, info, debug, trace]
      --log-file               Log to file (in addition to stderr)
      --log-file-path <FILE>   Log file path (default: ~/.nscan/nscan.log)
      --quiet                  Suppress non-error logs
  -o, --output <FILE>          Save result to a JSON file
      --no-stdout              Suppress stdout output (use with --output)
  -h, --help                   Print help
  -V, --version                Print version
```

### Subcommand help
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
TCP connect scans, QUIC probes, DNS enumeration, and interface listing do not require raw-socket privileges. TCP SYN scans and host discovery require raw packet access and an appropriate interface. `--interface` applies to nscan raw probes; connect scans use operating-system routing. OS identification uses Nmap and requires the privileges and capture driver needed by Nmap.

## Notes for Windows Users
- Npcap/WinPcap Installation:
    - Ensure that [Npcap](https://npcap.com/#download) or WinPcap is installed on your system.
    - If using Npcap, install it with the "Install Npcap in WinPcap API-compatible Mode" option.
- Build Dependencies:
    - Place the Packet.lib file from the [Npcap SDK](https://npcap.com/#download) or WinPcap Developers pack in a directory named lib at the root of this repository.
    - The file can be found in the %LIB% or $Env:LIB environment variables.
    - Locate Packet.lib in <SDK>/Lib/x64/Packet.lib for the 64-bit toolchain or <SDK>/Lib/Packet.lib for the 32-bit toolchain.

## Examples

```sh
# Unprivileged TCP connect scan with service detection
nscan port example.com --ports 22,80,443 --service-detect

# Save JSON without printing the report; logs go to stderr
nscan port 192.0.2.10 --ports 1-1024 --output scan.json --no-stdout

# Read targets from a file, including nested files relative to the parent file
nscan port @targets.txt --ports 443 --concurrency 100

# Probe QUIC separately from TCP
nscan port example.com --proto quic --ports 443
```

## Service detection

`--service-detect` (`-S`) collects banners, HTTP headers, and TLS metadata. Use `--service-probe banner|http|https|tls|quic` to override automatic probe selection:

```sh
nscan port example.com --ports 9443 -S --service-probe https
```

For detailed TCP service/version detection, add `--nmap`. Use `--os-detect` (`-O`) for OS detection. These options require a separate Nmap installation; OS detection also requires privileges.

```sh
nscan port example.com --ports 22,80,443 --nmap --output scan.json
```

## Output

Reports are printed to stdout; logs use stderr. Use `--no-stdout` to suppress the report and `--quiet` to suppress non-error diagnostics. `--log-file-path` enables file logging. Global options can appear before or after the subcommand.

`--output` writes JSON, replacing the destination atomically. The parent directory must exist. A failed serialization or write leaves the previous report intact.

| Exit status | Meaning |
| --- | --- |
| `0` | Command completed |
| `1` | Execution or output error |
| `2` | Invalid command-line arguments |

Domain scans may return partial results with exit status `0`. Check `complete`, `attempted`, and `total` in the JSON output.

## Scan options and limits

- `--ports common` (default) selects a fixed set of 1,000 ports. Use explicit lists or ranges for custom scans; `top-N` is no longer supported.
- Domain enumeration uses a small starter wordlist. Supply `--wordlist FILE` for broader coverage.
- Port scanning supports TCP and QUIC. Generic UDP port scanning is not supported; UDP host discovery is available. QUIC uses the connect method.
- Connect scans use OS routing without a preliminary ping. Set `--connect-timeout-ms` to override the default timeout. `--no-ping` skips the preliminary ping for raw scans.
- `--ordered` scans hosts and ports in ascending IP/port order. Target files can include other files using paths relative to the containing file. Repeated files are read once; nesting is limited to 32 levels.
- Each scan accepts up to 65,536 target addresses and 1,000,000 host/port pairs. Concurrency must be between 1 and 4,096; ports must be between 1 and 65,535. Split larger scans into batches.
- Hostname lookups have a five-second timeout. `--task-timeout-ms` bounds each port scan phase, including queued connections.
- `--read-timeout-ms` sets the timeout for each service operation. A complete service probe is limited to four times that value. Exceeding the packet capture buffer limit ends the scan with an error.

## Interpreting results

TCP ports are reported as `closed` after a connection refusal or reset. Timeouts are reported as `filtered`. For QUIC, `filtered` can also mean that the port does not run a QUIC service.

`service.name` is the observed protocol; `service.registered_name` is the conventional port label. Banners, HTTP Server headers, and TTL values are observations, not verified product or OS identities. TLS probes accept untrusted certificates for discovery.

Wildcard DNS answers are retained and marked with `wildcard_detected`. Detection uses one random name and may miss rotating or intermittent wildcard responses.

Raw scans do not retry adaptively. Packet loss, filtering, and ICMP rate limits can cause hosts to be missed. Raw routing relies on the selected interface and gateway; VPNs, multiple interfaces, scoped IPv6 addresses, and simultaneous scans may produce unreliable results. QUIC/HTTP3 interoperability testing is limited.
