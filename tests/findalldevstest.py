#!/usr/bin/env python

# coding: utf-8

from __future__ import absolute_import, division, print_function

import sys
import socket
import ctypes as ct

import libpcap as pcap
from libpcap._platform import sockaddr_in, sockaddr_in6


def main(argv):

    global program_name
    program_name = os.path.basename(argv[0])

    alldevs = ct.POINTER(pcap.pcap_if_t)()
    errbuf  = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
    if pcap.findalldevs(ct.byref(alldevs), errbuf) == -1:
        print("Error in pcap.findalldevs: {!s}".format(
              errbuf.value.decode("utf-8")), file=sys.stderr)
        sys.exit(1)

    d = alldevs
    while d:
        d = d.contents
        ifprint(d)
        d = d.next

    s = pcap.lookupdev(errbuf)
    if s is None:
        print("Error in pcap.lookupdev: {!s}".format(
              errbuf.value.decode("utf-8")), file=sys.stderr)
    else:
        print("Preferred device name: {!s}".format(s.decode("utf-8")))

    net  = pcap.bpf_u_int32()
    mask = pcap.bpf_u_int32()
    if pcap.lookupnet(s, ct.byref(net), ct.byref(mask), errbuf) < 0:
        print("Error in pcap.lookupnet: {!s}".format(
              errbuf.value.decode("utf-8")), file=sys.stderr)
    else:
        print("Preferred device is on network: {}/{}".format(
              iptos(net), iptos(mask)))

    return 0


def ifprint(d): # pcap_if_t*

    print("{!s}".format(d.name.decode("utf-8")))
    if d.description:
        print("\tDescription: {!s}".format(d.description.decode("utf-8")))
    print("\tLoopback: {}".format(
          "yes" if d.flags & pcap.PCAP_IF_LOOPBACK else "no"))

    a = d.addresses
    while a:
        a = a.contents

        addr      = a.addr
        netmask   = a.netmask
        broadaddr = a.broadaddr
        dstaddr   = a.dstaddr
        if addr.contents.sa_family == socket.AF_INET:
            print("\tAddress Family: AF_INET")
            if addr:
                print("\t\tAddress: {}".format(socket.inet_ntoa(ct.cast(addr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
            if netmask:
                print("\t\tNetmask: {}".format(socket.inet_ntoa(ct.cast(netmask, ct.POINTER(sockaddr_in)).contents.sin_addr)))
            if broadaddr:
                print("\t\tBroadcast Address: {}".format(socket.inet_ntoa(ct.cast(broadaddr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
            if dstaddr:
                print("\t\tDestination Address: {}".format(socket.inet_ntoa(ct.cast(dstaddr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
        #ifdef INET6
        elif addr.contents.sa_family == socket.AF_INET6:
            print("\tAddress Family: AF_INET6")
            if addr:
                print("\t\tAddress: {}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
            if netmask:
                print("\t\tNetmask: {}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(netmask, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
            if broadaddr:
                print("\t\tBroadcast Address: {}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(broadaddr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
            if dstaddr:
                print("\t\tDestination Address: {}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(dstaddr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
        #endif
        else:
            print("\tAddress Family: Unknown ({:d})".format(
                  addr.contents.sa_family))

        a = a.next

    print()


# From tcptraceroute

IPTOSBUFFERS = 12

output = [None] * IPTOSBUFFERS
which  = 0

def iptos(inp): # pcap.bpf_u_int32 inp

    global output
    global which

    p = ct.cast(ct.pointer(inp), ct.POINTER(ct.c_ubyte))
    which = 0 if (which + 1) == IPTOSBUFFERS else (which + 1)
    output[which] = "{:d}.{:d}.{:d}.{:d}".format(p[0], p[1], p[2], p[3])
    return output[which]


sys.exit(main(sys.argv) or 0)


# eof
