[netscan-url]: https://github.com/shellrow/netscan
# nscan
Cross-platform network scan tool for host and service discovery.  
Aim to be simple and fast.  

## Basic Usage
```
USAGE:
    nscan [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

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
```
shellrow@MacBook-Pro nscan % sudo nscan -p 192.168.1.8:1-1024
Password:
nscan 0.2.0 macos
https://github.com/shellrow/nscan

Scan started at 2021-05-02 17:55:50.142328 +09:00

----Port Scan Options-------------------------------------------
    IP Address: 192.168.1.8
    Port Range: 1-1024
    Scan Type: Syn Scan
----------------------------------------------------------------

Scanning... Done

----Scan Reports------------------------------------------------
      22    ssh
      80    http
     443    https
----------------------------------------------------------------
Scan Time: 1.784271557s
(Including 100ms of wait time)
```

## About netscan (lib)
Please check my [repository][netscan-url] for detail
