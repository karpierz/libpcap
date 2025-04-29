libpcap
=======

Python binding for the *libpcap* C library.

Overview
========

| Python |package_bold| module is a low-level binding for *libpcap* C library.
| It is an effort to allow python programs full access to the API provided
  by the well known *libpcap* Unix C library and by its implementations
  provided under Win32 systems by such packet capture systems as:
  `Npcap <https://nmap.org/npcap/>`__,
  `WinPcap <https://www.winpcap.org/>`__

`PyPI record`_.

`Documentation`_.

| |package_bold| is a lightweight Python package, based on the *ctypes* library.
| It is fully compliant implementation of the original C *libpcap* from
  1.0.0 up to 1.9.0 API and the *WinPcap*'s 4.1.3 libpcap (1.0.0rel0b) API
  by implementing whole its functionality in a clean Python instead of C.
|
| Useful *libpcap* API documentation can be found at:

  | `Main pcap man page <https://www.tcpdump.org/manpages/pcap.3pcap.html>`__,
  | `(MORE pcap man pages) <https://www.tcpdump.org/manpages/>`__

|package_bold| uses the underlying *libpcap* C shared library as specified in
libpcap.cfg (system's libpcap shared library is the default), but there is also
ability to specify it programmatically by one of the following ways:

.. code:: python

  import libpcap
  libpcap.config(LIBPCAP=None)       # system's libpcap library will be used
  # or
  libpcap.config(LIBPCAP="npcap")
  # or
  libpcap.config(LIBPCAP="wpcap")    # included wpcap library will be used
  # or
  libpcap.config(LIBPCAP="tcpdump")  # included tcpdump library will be used
  # or                               # (currently works only for Linux x64)
  libpcap.config(LIBPCAP="libpcap shared library absolute path")

About original libpcap:
-----------------------

LIBPCAP 1.x.y by "The Tcpdump Group":

  https://www.tcpdump.org

Anonymous Git is available via:

    git clone https://github.com/the-tcpdump-group/libpcap.git

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

Support for particular platforms and BPF:

For some platforms there are README.{system} files that discuss issues
with the OS's interface for packet capture on those platforms, such as
how to enable support for that interface in the OS, if it's not built in
by default.

The libpcap interface supports a filtering mechanism based on the
architecture in the BSD packet filter.  BPF is described in the 1993
Winter Usenix paper "The BSD Packet Filter: A New Architecture for
User-level Packet Capture" (`compressed PostScript
<https://www.tcpdump.org/papers/bpf-usenix93.ps.Z>`__, `gzipped
PostScript <https://www.tcpdump.org/papers/bpf-usenix93.ps.gz>`__,
`PDF <https://www.tcpdump.org/papers/bpf-usenix93.pdf>`__).

Although most packet capture interfaces support in-kernel filtering,
libpcap utilizes in-kernel filtering only for the BPF interface.
On systems that don't have BPF, all packets are read into user-space
and the BPF filters are evaluated in the libpcap library, incurring
added overhead (especially, for selective filters).  Ideally, libpcap
would translate BPF filters into a filter program that is compatible
with the underlying kernel subsystem, but this is not yet implemented.

BPF is standard in 4.4BSD, BSD/OS, NetBSD, FreeBSD, OpenBSD, DragonFly
BSD, and macOS; an older, modified and undocumented version is
standard in AIX.  DEC OSF/1, Digital UNIX, Tru64 UNIX uses the
packetfilter interface but has been extended to accept BPF filters
(which libpcap utilizes).  Also, you can add BPF filter support to
Ultrix using the kernel source and/or object patches.

Linux has a number of BPF based systems, and libpcap does not support
any of the eBPF mechanisms as yet, although it supports many of the
memory mapped receive mechanisms. See the `Linux-specific README
<https://github.com/the-tcpdump-group/libpcap/blob/master/doc/README.linux>`__,
for more information.

Note to Linux distributions and \*BSD systems that include libpcap:

There's now a rule to make a shared library, which should work on Linux
and \*BSD, among other platforms.

It sets the soname of the library to "libpcap.so.1"; this is what it
should be, *NOT* "libpcap.so.1.x" or "libpcap.so.1.x.y" or something
such as that.

We've been maintaining binary compatibility between libpcap releases for
quite a while; there's no reason to tie a binary linked with libpcap to
a particular release of libpcap.

Requirements
============

- | It is a fully independent package.
  | All necessary things are installed during the normal installation process.
- ATTENTION: currently works and tested only for Windows.

Installation
============

Prerequisites:

+ Python 3.10 or higher

  * https://www.python.org/
  * with C libpcap 1.8.1 is a primary test environment.

+ pip and setuptools

  * https://pypi.org/project/pip/
  * https://pypi.org/project/setuptools/

To install run:

  .. parsed-literal::

    python -m pip install --upgrade |package|

Development
===========

Prerequisites:

+ Development is strictly based on *tox*. To install it run::

    python -m pip install --upgrade tox

Visit `Development page`_.

Installation from sources:

clone the sources:

  .. parsed-literal::

    git clone |respository| |package|

and run:

  .. parsed-literal::

    python -m pip install ./|package|

or on development mode:

  .. parsed-literal::

    python -m pip install --editable ./|package|

License
=======

  | |copyright|
  | Licensed under the BSD license
  | https://opensource.org/license/bsd-3-clause
  | Please refer to the accompanying LICENSE file.

Authors
=======

* Adam Karpierz <adam@karpierz.net>

.. |package| replace:: libpcap
.. |package_bold| replace:: **libpcap**
.. |copyright| replace:: Copyright (c) 2016-2025 Adam Karpierz
.. |respository| replace:: https://github.com/karpierz/libpcap.git
.. _Development page: https://github.com/karpierz/libpcap
.. _PyPI record: https://pypi.org/project/libpcap/
.. _Documentation: https://libpcap.readthedocs.io/
.. _Libpcap File Format: https://wiki.wireshark.org/Development/LibpcapFileFormat
