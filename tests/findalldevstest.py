# coding: utf-8

from __future__ import absolute_import, print_function

import sys
import socket
import ctypes as ct

import libpcap as pcap

# IPv4 AF_INET sockets:

class in_addr(ct.Union):
    _fields_ = [
    ("s_addr", ct.c_uint32),  # ct.c_ulong
]

class sockaddr_in(ct.Structure):
    _fields_ = [
    ("sin_family", ct.c_short),       # e.g. AF_INET, AF_INET6   
    ("sin_port",   ct.c_ushort),      # e.g. htons(3490)         
    ("sin_addr",   in_addr),          # see struct in_addr, below
    ("sin_zero",   (ct.c_char * 8)),  # padding, zero this if you want to
]

# IPv6 AF_INET6 sockets:

class in6_addr(ct.Union):
    _fields_ = [
    ("s6_addr",   (ct.c_ubyte * 16)),
]

class sockaddr_in6(ct.Structure):
    _fields_ = [
    ('sin6_family',   ct.c_short),   # address family, AF_INET6      
    ('sin6_port',     ct.c_ushort),  # port number, Network Byte Order
    ('sin6_flowinfo', ct.c_ulong),   # IPv6 flow information         
    ('sin6_addr',     in6_addr),     # IPv6 address                  
    ('sin6_scope_id', ct.c_ulong),   # Scope ID                      
]


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
            if addr:
                print("\t\tAddress: {!s}".format(socket.inet_ntoa(ct.cast(addr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
            if netmask:
                print("\t\tNetmask: {!s}".format(socket.inet_ntoa(ct.cast(netmask, ct.POINTER(sockaddr_in)).contents.sin_addr)))
            if broadaddr:
                print("\t\tBroadcast Address: {!s}".format(socket.inet_ntoa(ct.cast(broadaddr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
            if dstaddr:
                print("\t\tDestination Address: {!s}".format(socket.inet_ntoa(ct.cast(dstaddr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
        #ifdef INET6
        elif addr.contents.sa_family == socket.AF_INET6:
            print("\tAddress Family: AF_INET6")
            if addr:
                print("\t\tAddress: {!s}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
            if netmask:
                print("\t\tNetmask: {!s}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(netmask, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
            if broadaddr:
                print("\t\tBroadcast Address: {!s}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(broadaddr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
            if dstaddr:
                print("\t\tDestination Address: {!s}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(dstaddr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
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
