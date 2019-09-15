libpcap
=======

Python binding for the *libpcap* C library.

Overview
========

| Python *libpcap* module is a low-level binding for *libpcap* C library.
| It is an effort to allow python programs full access to the API provided
  by the well known *libpcap* Unix C library and by its implementations
  provided under Win32 systems by such packet capture systems as:
  `WinPcap <http://www.winpcap.org>`__,
  `Npcap <https://nmap.org/npcap/>`__
|
| *libpcap* is a lightweight Python package, based on the *ctypes* library.
| It is fully compliant implementation of the original C *libpcap* from
  1.0.0 up to 1.9.0 API and the *WinPcap*'s 4.1.3 libpcap (1.0.0rel0b) API
  by implementing whole its functionality in a clean Python instead of C.
|
| Useful *libpcap* API documentation can be found at:

  | `Main pcap man page <https://www.tcpdump.org/manpages/pcap.3pcap.html>`__,
  | `(MORE pcap man pages) <https://www.tcpdump.org/manpages/>`__

About original LIBPCAP:
-----------------------

| LIBPCAP 1.x.y
| Now maintained by "The Tcpdump Group":

  https://www.tcpdump.org

Anonymous Git is available via:

    git clone git://bpf.tcpdump.org/libpcap

formerly from:

  | Lawrence Berkeley National Laboratory
  | Network Research Group <libpcap@ee.lbl.gov>
  | ftp://ftp.ee.lbl.gov/old/libpcap-0.4a7.tar.Z

This directory contains source code for libpcap, a system-independent
interface for user-level packet capture.  libpcap provides a portable
framework for low-level network monitoring.  Applications include
network statistics collection, security monitoring, network debugging,
etc.  Since almost every system vendor provides a different interface
for packet capture, and since we've developed several tools that
require this functionality, we've created this system-independent API
to ease in porting and to alleviate the need for several
system-dependent packet capture modules in each application.

For some platforms there are README.{system} files that discuss issues
with the OS's interface for packet capture on those platforms, such as
how to enable support for that interface in the OS, if it's not built in
by default.

The libpcap interface supports a filtering mechanism based on the
architecture in the BSD packet filter.  BPF is described in the 1993
Winter Usenix paper "The BSD Packet Filter: A New Architecture for
User-level Packet Capture".  A compressed PostScript version can be
found at:

    ftp://ftp.ee.lbl.gov/papers/bpf-usenix93.ps.Z

or:

    https://www.tcpdump.org/papers/bpf-usenix93.ps.Z

and a gzipped version can be found at:

    https://www.tcpdump.org/papers/bpf-usenix93.ps.gz

A PDF version can be found at:

    https://www.tcpdump.org/papers/bpf-usenix93.pdf

Although most packet capture interfaces support in-kernel filtering,
libpcap utilizes in-kernel filtering only for the BPF interface.
On systems that don't have BPF, all packets are read into user-space
and the BPF filters are evaluated in the libpcap library, incurring
added overhead (especially, for selective filters).  Ideally, libpcap
would translate BPF filters into a filter program that is compatible
with the underlying kernel subsystem, but this is not yet implemented.

BPF is standard in 4.4BSD, BSD/OS, NetBSD, FreeBSD, OpenBSD, DragonFly
BSD, and Mac OS X; an older, modified and undocumented version is
standard in AIX.  DEC OSF/1, Digital UNIX, Tru64 UNIX uses the
packetfilter interface but has been extended to accept BPF filters
(which libpcap utilizes).  Also, you can add BPF filter support to
Ultrix using the kernel source and/or object patches available in:

    https://www.tcpdump.org/other/bpfext42.tar.Z

Linux, in the 2.2 kernel and later kernels, has a "Socket Filter"
mechanism that accepts BPF filters; see the README.linux file for
information on configuring that option.

Note to Linux distributions and \*BSD systems that include libpcap:

There's now a rule to make a shared library, which should work on Linux
and \*BSD, among other platforms.

It sets the soname of the library to "libpcap.so.1"; this is what it
should be, *NOT* libpcap.so.1.x or libpcap.so.1.x.y or something such as
that.

We've been maintaining binary compatibility between libpcap releases for
quite a while; there's no reason to tie a binary linked with libpcap to
a particular release of libpcap.

Current versions can be found at: https://www.tcpdump.org

\- The TCPdump group

Requirements
============

- | It is fully independent package.
  | All necessary things are installed during the normal installation process.
- ATTENTION: currently works and tested only for Windows.

Installation
============

Prerequisites:

+ Python 2.7 or Python 3.4 or later

  * http://www.python.org/
  * 2.7 and 3.7 with LIBPCAP 1.8.1 are primary test environments.

+ pip and setuptools

  * http://pypi.org/project/pip/
  * http://pypi.org/project/setuptools/

To install run::

    python -m pip install --upgrade libpcap

Development
===========

Visit `development page <https://github.com/karpierz/libpcap>`__

Installation from sources:

Clone the `sources <https://github.com/karpierz/libpcap>`__ and run::

    python -m pip install ./libpcap

or on development mode::

    python -m pip install --editable ./libpcap

Prerequisites:

+ Development is strictly based on *tox*. To install it run::

    python -m pip install tox

License
=======

  | Copyright (c) 2016-2019, Adam Karpierz
  |
  | Licensed under the BSD license
  | http://opensource.org/licenses/BSD-3-Clause
  | Please refer to the LICENSE file.

Authors
=======

* Adam Karpierz <adam@karpierz.net>
