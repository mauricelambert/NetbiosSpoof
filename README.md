![LocalResolver logo](https://mauricelambert.github.io/info/python/code/LocalResolver_small.png "LocalResolver logo")

# LocalResolver

## Description

This package implements local hostname resolver tool with scapy (using netbios and LLMNR query).

This tool is useful to:
 - reverse lookup local IP addresses
 - resolve manually hostnames/IP from Linux or hardened Windows
 - resolve hostname with old machines (Windows 2000-2012)
 - identify:
     - Machines with old protocols like Netbios or LLMNR,
     - Hostname spoofer (or two machines with the same name),

## Requirements

This package require: 

 - python3
 - python3 Standard Library
 - Scapy
 - PythonToolsKit

## Installation

```bash
pip install LocalResolver 
```

## Examples

### Command lines

```bash
LocalResolver -h
LocalResolver --retry 5 --timeout 5 --interval 2 192.168.1.2   # very long
LocalResolver 192.168.1.3 192.168.1.2 WIN10 HOMEPC test.local
LocalResolver --no-netbios --no-dns fe80::3317:f73e:2166:bbd8/64
LocalResolver --no-llmnr --no-mdns fe80::3317:f73e:2166:bbd8/64
```

### Python3

```python
from LocalResolver import LocalResolver, resolve_local_name, resolve_local_ip

[r.hostname for r in resolve_local_ip("192.168.5.2")]
[r.ip for r in resolve_local_ip("192.168.5.2", retry=2, inter=1, timeout=3, netbios=True, llmnr=True, mdns=True, dns=True)]
[(r.ip, r.source) for r in resolve_local_name("WIN10")]
[(r.ip, r.source) for r in resolve_local_name("HOMEPC", retry=2, inter=1, timeout=3, netbios=True, llmnr=True, mdns=True, dns=True)]
```

## Links

 - [Github Page](https://github.com/mauricelambert/LocalResolver)
 - [Documentation](https://mauricelambert.github.io/info/python/code/LocalResolver.html)
 - [Download as python executable](https://mauricelambert.github.io/info/python/code/LocalResolver.pyz)
 - [Pypi package](https://pypi.org/project/LocalResolver/)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
