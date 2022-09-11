#!/usr/bin/env python

# Copyright (c) 2016-2022, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

import sys
import os
import socket
from getpass import getpass
import ctypes as ct

import libpcap as pcap
from libpcap._platform import sockaddr_in, sockaddr_in6
from pcaptestutils import *  # noqa


def main(argv=sys.argv[1:]):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    source = argv[0].encode("utf-8") if len(argv) >= 1 else None

    exit_status = 0

    errbuf  = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
    alldevs = ct.POINTER(pcap.pcap_if_t)()

    #ifdef ENABLE_REMOTE
    if source is not None:
        if pcap.findalldevs_ex(source, None, ct.byref(alldevs), errbuf) == -1:
            # OK, try it with a user name and password.
            username = input("User name: ")
            if not username:
                exit_status = 1
                return exit_status
            password = getpass("Password: ")

            auth = pcap.rmtauth()
            auth.type     = pcap.RPCAP_RMTAUTH_PWD
            auth.username = username
            auth.password = password
            if pcap.findalldevs_ex(source, ct.byref(auth), ct.byref(alldevs), errbuf) == -1:
                print("Error in pcap.findalldevs: {}".format(ebuf2str(errbuf)),
                      file=sys.stderr)
                exit_status = 1
                return exit_status
    else:
    #endif
        if pcap.findalldevs(ct.byref(alldevs), errbuf) == -1:
            print("Error in pcap.findalldevs: {}".format(ebuf2str(errbuf)),
                  file=sys.stderr)
            exit_status = 1
            return exit_status

    pdev = alldevs
    while pdev:
        dev = pdev.contents
        if not ifprint(dev):
            exit_status = 2
        pdev = dev.next

    if alldevs:
        device = alldevs[0].name
        net  = pcap.bpf_u_int32()
        mask = pcap.bpf_u_int32()
        if pcap.lookupnet(device, ct.byref(net), ct.byref(mask), errbuf) < 0:
            # XXX - this doesn't distinguish between "a real error
            # occurred" and "this interface doesn't *have* an IPv4
            # address".  The latter shouldn't be treated as an error.
            #
            # We look for the interface name, followed by a colon and
            # a space, and, if we find it,w e see if what follows it
            # is "no IPv4 address assigned".
            devnamelen = len(device)
            if (errbuf[:devnamelen] == device[:devnamelen] and
                errbuf[devnamelen:devnamelen+2] == b": " and
                errbuf[devnamelen+2:] == b"no IPv4 address assigned"):
                print("Preferred device is not on an IPv4 network")
            else:
                print("Error in pcap.lookupnet: {}".format(ebuf2str(errbuf)),
                      file=sys.stderr)
                exit_status = 2
        else:
            print("Preferred device is on network: {}/{}".format(
                  iptos(net), iptos(mask)))

    pcap.freealldevs(alldevs)

    return exit_status


def ifprint(dev: pcap.pcap_if_t):

    status = True  # success

    print("{}".format(dev.name.decode("utf-8")))
    if dev.description:
        print("\tDescription: {}".format(dev.description.decode("utf-8")))

    flags = []
    if dev.flags & pcap.PCAP_IF_UP:
        flags.append("UP")
    if dev.flags & pcap.PCAP_IF_RUNNING:
        flags.append("RUNNING")
    if dev.flags & pcap.PCAP_IF_LOOPBACK:
        flags.append("LOOPBACK")
    if dev.flags & pcap.PCAP_IF_WIRELESS:
        flags.append("WIRELESS")
    conn_status = dev.flags & pcap.PCAP_IF_CONNECTION_STATUS
    if dev.flags & pcap.PCAP_IF_WIRELESS:
        if conn_status == pcap.PCAP_IF_CONNECTION_STATUS_UNKNOWN:
            flags.append(" (association status unknown)")
        elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_CONNECTED:
            flags.append(" (associated)")
        elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
            flags.append(" (not associated)")
        elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
            pass
    else:
        if conn_status == pcap.PCAP_IF_CONNECTION_STATUS_UNKNOWN:
            flags.append(" (connection status unknown)")
        elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_CONNECTED:
            flags.append(" (connected)")
        elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
            flags.append(" (disconnected)")
        elif conn_status == pcap.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
            pass
    print("\tFlags: {}".format(", ".join(flags)))

    pa = dev.addresses
    while pa:
        a = pa.contents

        addr      = a.addr
        netmask   = a.netmask
        broadaddr = a.broadaddr
        dstaddr   = a.dstaddr
        if not addr:
            print("\tWarning: a.addr is NULL, skipping this address.",
                  file=sys.stderr)
            status = False
        else:
            if addr.contents.sa_family == socket.AF_INET:
                print("\tAddress Family: AF_INET")
                if addr:
                    print("\t\tAddress: {}".format(socket.inet_ntop(socket.AF_INET, ct.cast(addr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
                if netmask:
                    print("\t\tNetmask: {}".format(socket.inet_ntop(socket.AF_INET, ct.cast(netmask, ct.POINTER(sockaddr_in)).contents.sin_addr)))
                if broadaddr:
                    print("\t\tBroadcast Address: {}".format(socket.inet_ntop(socket.AF_INET, ct.cast(broadaddr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
                if dstaddr:
                    print("\t\tDestination Address: {}".format(socket.inet_ntop(socket.AF_INET, ct.cast(dstaddr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
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
                print("\tAddress Family: Unknown ({:d})".format(addr.contents.sa_family))

        pa = a.next

    print()
    return status


# From tcptraceroute

IPTOSBUFFERS = 12

output = [None] * IPTOSBUFFERS
which  = 0

def iptos(inp: pcap.bpf_u_int32):
    global output
    global which
    p = ct.cast(ct.pointer(inp), ct.POINTER(ct.c_ubyte))
    which = 0 if (which + 1) == IPTOSBUFFERS else (which + 1)
    output[which] = "{:d}.{:d}.{:d}.{:d}".format(p[0], p[1], p[2], p[3])
    return output[which]


if __name__.rpartition(".")[-1] == "__main__":
    sys.exit(main())
