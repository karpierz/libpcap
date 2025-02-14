#!/usr/bin/env python

# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os
import socket
from getpass import getpass
import ctypes as ct

import libpcap as pcap
from libpcap._platform import is_windows, is_linux, defined
from libpcap._platform import sockaddr_in, sockaddr_in6
from pcaptestutils import *  # noqa

if not is_windows:
    # Different OSes define ETHER_ADDR_LEN in different headers, if at all, so
    # it would take an amount of conditionals similar to that in nametoaddr.c
    # just to get the well-known constant from an OS (or not).  Keep it simple.
    ETHER_ADDR_LEN = socket.ETHER_ADDR_LEN if hasattr(socket, "ETHER_ADDR_LEN") else 6

    # Linux defines and uses AF_PACKET.
    # AIX, FreeBSD, Haiku, macOS, NetBSD and OpenBSD define and use AF_LINK.
    # illumos defines both AF_PACKET and AF_LINK, and uses AF_LINK.
    # Solaris 11 defines both AF_PACKET and AF_LINK, but uses neither.
    # GNU/Hurd defines neither AF_PACKET nor AF_LINK.
    #include <net/if.h>
    if is_linux:
        #include <netpacket/packet.h> // struct sockaddr_ll  # !!!
        #include <net/if_arp.h>       // ARPHRD_ETHER        # !!!
        pass
    if hasattr(socket, "AF_LINK"):
        #include <net/if_dl.h>    // struct sockaddr_dl and LLADDR()  # !!!
        #include <net/if_types.h> // IFT_ETHER                        # !!!
        pass


def main(argv=sys.argv[1:]):

    global program_name
    program_name = os.path.basename(sys.argv[0])

    source = argv[0].encode("utf-8") if len(argv) >= 1 else None

    exit_status = 0

    errbuf  = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
    alldevs = ct.POINTER(pcap.pcap_if_t)()

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


if not is_windows and (is_linux or hasattr(socket, "AF_LINK")):
   #def ether_ntop(const u_char addr[], bool mask): # !!!
    def ether_ntop(addr, mask: bool):
        buffer = "00:00:00:00:00:00"
        if mask:
            buffer = "%02x:%02x:%02x:xx:xx:xx" % (addr[0], addr[1], addr[2])
        else:
            buffer = "%02x:%02x:%02x:%02x:%02x:%02x" % (addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
        return buffer
# endif


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

    unmask = os.environ.get("UNMASK_MAC_ADDRESSES")
    unmask = bool(unmask and unmask.lower() == "yes")

    pa = dev.addresses
    while pa:
        a = pa.contents

        addr      = a.addr
        netmask   = a.netmask
        broadaddr = a.broadaddr
        dstaddr   = a.dstaddr

        if not addr:
            print("\tWarning: a.addr is NULL, skipping this address.", file=sys.stderr)
            status = False
        else:
            if addr.contents.sa_family == socket.AF_INET:
                print("\tAddress Family: AF_INET ({})".format(addr.contents.sa_family))
                print("\t\tAddress: {}".format(socket.inet_ntop(socket.AF_INET, ct.cast(addr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
                if netmask:
                    print("\t\tNetmask: {}".format(socket.inet_ntop(socket.AF_INET, ct.cast(netmask, ct.POINTER(sockaddr_in)).contents.sin_addr)))
                if broadaddr:
                    print("\t\tBroadcast Address: {}".format(socket.inet_ntop(socket.AF_INET, ct.cast(broadaddr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
                if dstaddr:
                    print("\t\tDestination Address: {}".format(socket.inet_ntop(socket.AF_INET, ct.cast(dstaddr, ct.POINTER(sockaddr_in)).contents.sin_addr)))
            elif not is_windows and is_linux and addr.contents.sa_family == socket.AF_PACKET:
                print("\tAddress Family: AF_PACKET ({})".format(addr.contents.sa_family))
                sll = ct.cast(addr, ct.POINTER(sockaddr_ll))
                # !!!
                # printf("\t\tInterface Index: %u\n", sll.contents.sll_ifindex);
                # printf("\t\tType: %d%s\n", sll.contents.sll_hatype, (" (ARPHRD_ETHER)" if sll.contents.sll_hatype == ARPHRD_ETHER else ""))
                # printf("\t\tLength: %u\n", sll.contents.sll_halen);
                # if sll.contents.sll_hatype == ARPHRD_ETHER and sll.contents.sll_halen == ETHER_ADDR_LEN:
                #     printf("\t\tAddress: %s\n", ether_ntop((const u_char *)sll.contents.sll_addr, not unmask))
            elif not is_windows and hasattr(socket, "AF_LINK") and addr.contents.sa_family == socket.AF_LINK:
                print("\tAddress Family: AF_LINK ({})".format(addr.contents.sa_family))
                sdl = ct.cast(addr, ct.POINTER(sockaddr_dl))
                # !!!
                # printf("\t\tInterface Index: %u\n", sdl.contents.sdl_index);
                # printf("\t\tType: %u%s\n", sdl.contents.sdl_type, (" (IFT_ETHER)" if sdl.contents.sdl_type == IFT_ETHER else ""))
                # printf("\t\tLength: %u\n", sdl.contents.sdl_alen);
                # # On illumos sdl_type can be 0, see https://www.illumos.org/issues/16383
                # if ((sdl.contents.sdl_type == IFT_ETHER or (defined("__illumos__") and sdl.contents.sdl_type == 0)) and
                #      sdl.contents.sdl_alen == ETHER_ADDR_LEN):
                #     printf("\t\tAddress: %s\n", ether_ntop((const u_char *)LLADDR(sdl), not unmask))
            elif hasattr(socket, "AF_INET6") and addr.contents.sa_family == socket.AF_INET6:
                print("\tAddress Family: AF_INET6 ({})".format(addr.contents.sa_family))
                print("\t\tAddress: {}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(addr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
                if netmask:
                    print("\t\tNetmask: {}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(netmask, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
                if broadaddr:
                    print("\t\tBroadcast Address: {}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(broadaddr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
                if dstaddr:
                    print("\t\tDestination Address: {}".format(socket.inet_ntop(socket.AF_INET6, ct.cast(dstaddr, ct.POINTER(sockaddr_in6)).contents.sin6_addr.s6_addr)))
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
