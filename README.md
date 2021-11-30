![NetbiosSpoof logo](https://mauricelambert.github.io/info/python/security/NetbiosSpoof_small.png "NetbiosSpoof logo")

# NetbiosSpoof

## Description

This package implements a Hostname Spoofer (Netbios, LLMNR and Local DNS).

## Requirements

This package require :
 - python3
 - python3 Standard Library
 - Scapy

## Installation

```bash
pip install NetbiosSpoof
```

## Usages

### Command lines

```bash
python3 -m NetbiosSpoof
python3 NetbiosSpoof.pyz
NetbiosSpoof
NetbiosSpoof --help
NetbiosSpoof -h
NetbiosSpoof -v -i 172.17.0.
```

### Python3

```python
from NetbiosSpoof import NetbiosSpoof
NetbiosSpoof().start()

spoofer = NetbiosSpoof("172.17.0.")
spoofer.start(True)
spoofer.stop()
```

## Links

 - [Github Page](https://github.com/mauricelambert/NetbiosSpoof)
 - [Pypi](https://pypi.org/project/NetbiosSpoof/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/NetbiosSpoof.html)
 - [Executable](https://mauricelambert.github.io/info/python/security/NetbiosSpoof.pyz)

## Help

```text
usage: NetbiosSpoof.pyz [-h] [--iface IFACE] [--verbose]

This script spoofs host names on a network.

optional arguments:
  -h, --help            show this help message and exit
  --iface IFACE, -i IFACE
                        Part of the IP, MAC or name of the interface
  --verbose, -v         Mode verbose (print debug message)
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).