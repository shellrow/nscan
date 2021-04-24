[netscan-url]: https://github.com/shellrow/netscan
# nscan
Cross-platform network scan tool for host and service discovery

## Basic Usage
```
nscan 0.1.0
shellrow <https://github.com/shellrow>
Cross-platform network scan tool for host and service discovery

USAGE:
    nscan [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -p, --port <ip_addr:port_range>    Port Scan - Ex: -p 192.168.1.8:1-1000
    -n, --host <ip_addr>               Scan hosts in specified network - Ex: -n 192.168.1.0
    -t, --timeout <duration>           Set timeout in ms - Ex: -t 10000
    -i, --interface <name>             Specify network interface by name - Ex: -i en0
    -w, --word <file_path>             Use word list - Ex: -w common.txt
    -s, --save <file_path>             Save scan result to file - Ex: -s result.txt

SUBCOMMANDS:
    update    Update nscan database
    help      Prints this message or the help of the given subcommand(s)
```

## About netscan (lib)
Please check my [repository][netscan-url] for detail