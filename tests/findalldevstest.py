#!/usr/bin/env python

# Copyright (c) 2016-2019, Adam Karpierz
# Licensed under the BSD license
# http://opensource.org/licenses/BSD-3-Clause

from __future__ import absolute_import, division, print_function

import sys
import os
import socket
if sys.version_info.major <= 2:
    import win_inet_pton
    input = raw_input
from getpass import getpass
import ctypes as ct

import libpcap as pcap
from libpcap._platform import sockaddr_in, sockaddr_in6


def main(argv):

    global program_name
    program_name = os.path.basename(argv[0])

    exit_status = 0

    alldevs = ct.POINTER(pcap.pcap_if_t)()
    errbuf  = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)

    #ifdef ENABLE_REMOTE
    if len(argv) >= 2:
        source = argv[1]
        if pcap.findalldevs_ex(source, NULL, ct.byref(alldevs), errbuf) == -1:

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
                print("Error in pcap.findalldevs: {!s}".format(
                      errbuf.value.decode("utf-8", "ignore")), file=sys.stderr)
                exit_status = 1
                return exit_status
    else:
    #endif
        if pcap.findalldevs(ct.byref(alldevs), errbuf) == -1:
            print("Error in pcap.findalldevs: {!s}".format(
                  errbuf.value.decode("utf-8", "ignore")), file=sys.stderr)
            exit_status = 1
            return exit_status

    d = alldevs
    while d:
        d = d.contents
        if not ifprint(d):
            exit_status = 2
        d = d.next

    if alldevs:
        net  = pcap.bpf_u_int32()
        mask = pcap.bpf_u_int32()
        if pcap.lookupnet(alldevs[0].name, ct.byref(net), ct.byref(mask), errbuf) < 0:
            print("Error in pcap.lookupnet: {!s}".format(
                  errbuf.value.decode("utf-8", "ignore")), file=sys.stderr)
            exit_status = 2
        else:
            print("Preferred device is on network: {}/{}".format(
                  iptos(net), iptos(mask)))

    pcap.freealldevs(alldevs)

    return exit_status


def ifprint(d): # pcap_if_t*

    status = True  # success

    print("{!s}".format(d.name.decode("utf-8")))
    if d.description:
        print("\tDescription: {!s}".format(d.description.decode("utf-8")))

    flags = []
    if d.flags & pcap.PCAP_IF_UP:
        flags.append("UP")
    if d.flags & pcap.PCAP_IF_RUNNING:
        flags.append("RUNNING")
    if d.flags & pcap.PCAP_IF_LOOPBACK:
        flags.append("LOOPBACK")
    if d.flags & pcap.PCAP_IF_WIRELESS:
        flags.append("WIRELESS")
    conn_status = d.flags & pcap.PCAP_IF_CONNECTION_STATUS
    if d.flags & pcap.PCAP_IF_WIRELESS:
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

    a = d.addresses
    while a:
        a = a.contents

        addr      = a.addr
        netmask   = a.netmask
        broadaddr = a.broadaddr
        dstaddr   = a.dstaddr
        if not addr:
            print("\tWarning: a.addr is NULL, skipping this address.", file=sys.stderr)
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

        a = a.next

    print()
    return status


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
