# coding: utf-8

from __future__ import absolute_import, print_function

import sys
import socket
import ctypes as ct

import libpcap as pcap

#https://github.com/sqlmapproject/sqlmap/blob/master/thirdparty/wininetpton/win_inet_pton.py


def main():

    alldevs = ct.POINTER(pcap.pcap_if_t)()
    errbuf  = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
    if pcap.findalldevs(ct.byref(alldevs), errbuf) == -1:
        print("Error in pcap.findalldevs: {!s}".format(errbuf.value), file=sys.stderr)
        sys.exit(1)

    d = alldevs
    while d:
        d = d.contents
        ifprint(d)
        d = d.next

    s = pcap.lookupdev(errbuf)
    if s is None:
        print("Error in pcap.lookupdev: {!s}".format(errbuf.value), file=sys.stderr)
    else:
        print("Preferred device name: {!s}".format(s.decode("utf-8")))

    net  = pcap.bpf_u_int32()
    mask = pcap.bpf_u_int32()
    if pcap.lookupnet(s, ct.byref(net), ct.byref(mask), errbuf) < 0:
        print("Error in pcap.lookupnet: {!s}".format(errbuf.value), file=sys.stderr)
    else:
        print("Preferred device is on network: {}/{}".format(iptos(net), iptos(mask)))
    
    sys.exit(0)


def ifprint(d): # pcap_if_t*

    print("{!s}".format(d.name.decode("utf-8")))
    if d.description:
        print("\tDescription: {!s}".format(d.description.decode("utf-8")))
    print("\tLoopback: {!s}".format("yes" if d.flags & pcap.PCAP_IF_LOOPBACK else "no"))

    a = d.addresses
    while a:
        a = a.contents

        addr      = a.addr
        netmask   = a.netmask
        broadaddr = a.broadaddr
        dstaddr   = a.dstaddr
        if addr.contents.sa_family == socket.AF_INET:
            print("\tAddress Family: AF_INET")
            """
            if addr:
                print("\t\tAddress: {!s}".format(socket.inet_ntoa(((struct sockaddr_in *)addr)->sin_addr)))
            if netmask:
                print("\t\tNetmask: {!s}".format(socket.inet_ntoa(((struct sockaddr_in *)netmask)->sin_addr)))
            if broadaddr:
                print("\t\tBroadcast Address: {!s}".format(socket.inet_ntoa(((struct sockaddr_in *)broadaddr)->sin_addr)))
            if dstaddr:
                print("\t\tDestination Address: {!s}".format(socket.inet_ntoa(((struct sockaddr_in *)dstaddr)->sin_addr)))
            """
        #ifdef INET6
        elif addr.contents.sa_family == socket.AF_INET6:
            print("\tAddress Family: AF_INET6")
            """
            if addr:
                print("\t\tAddress: {!s}".format(socket.inet_ntop(socket.AF_INET6, ((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr)))
            if netmask:
                print("\t\tNetmask: {!s}".format(socket.inet_ntop(socket.AF_INET6, ((struct sockaddr_in6 *)netmask)->sin6_addr.s6_addr)))
            if broadaddr:
                print("\t\tBroadcast Address: {!s}".format(socket.inet_ntop(socket.AF_INET6, ((struct sockaddr_in6 *)broadaddr)->sin6_addr.s6_addr)))
            if dstaddr:
                print("\t\tDestination Address: {!s}".format(socket.inet_ntop(socket.AF_INET6, ((struct sockaddr_in6 *)dstaddr)->sin6_addr.s6_addr)))
            """
        #endif
        else:
            print("\tAddress Family: Unknown ({:d})".format(addr.contents.sa_family))

        a = a.next

    print()


# From tcptraceroute

IPTOSBUFFERS = 12

output = [None] * IPTOSBUFFERS
which  = 0

def iptos(inp): # pcap.bpf_u_int32 in

    global output
    global which

    p = ct.cast(ct.pointer(inp), ct.POINTER(ct.c_ubyte))
    which = 0 if (which + 1) == IPTOSBUFFERS else (which + 1)
    output[which] = "{:d}.{:d}.{:d}.{:d}".format(p[0], p[1], p[2], p[3])
    return output[which]


main()


# eof
