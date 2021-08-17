# freebsd-netlink


Design document is here
https://docs.google.com/document/d/1VGci3zucEhCphwLkCPVFjLkMudW2vdZUkgjTyqOSaCU/edit#


## Note:

### About headers:
As per common practice, I have seperated the userspace API from the kernel API (that has access to the userspace API). I kept it simple, and I kept the userspace api in linux/netlink.h and the kernel api in net/netlink.h


### About the files:
1. linux/netlink.h: userspace netlink header. To be added as part of include folder 
2. net/netlink.h: kernel netlink header. To be in the kernel source folder with the source files
3. nl_sock.c: source file implementation. Contains most of the netlink code.


### Existing major todo list
1. we currently assume the initial m_get to retreive a message of a sufficient size for a packet *which allows us to write straight into the buffer instead of using m_append*. The reason for this is because when "closing" a message, we call nlmsg_end or other functions to end the header, we use pointer artihmethic to determine the size of the message. Alternative is to call m_pullup before calling nlmsg_end on the message, or to continuously resize and transfer the message when more data is needed.

2. currently installing netlink as a module rather than as part of the kernel tree


FreeBSD Source:
---------------
This is the top level of the FreeBSD source directory.

FreeBSD is an operating system used to power modern servers, desktops, and embedded platforms.
A large community has continually developed it for more than thirty years.
Its advanced networking, security, and storage features have made FreeBSD the platform of choice for many of the busiest web sites and most pervasive embedded networking and storage devices.

For copyright information, please see [the file COPYRIGHT](COPYRIGHT) in this directory.
Additional copyright information also exists for some sources in this tree - please see the specific source directories for more information.

The Makefile in this directory supports a number of targets for building components (or all) of the FreeBSD source tree.
See build(7), config(8), [FreeBSD handbook on building userland](https://docs.freebsd.org/en/books/handbook/cutting-edge/#makeworld), and [Handbook for kernels](https://docs.freebsd.org/en/books/handbook/kernelconfig/) for more information, including setting make(1) variables.

Source Roadmap:
---------------
| Directory | Description |
| --------- | ----------- |
| bin | System/user commands. |
| cddl | Various commands and libraries under the Common Development and Distribution License. |
| contrib | Packages contributed by 3rd parties. |
| crypto | Cryptography stuff (see [crypto/README](crypto/README)). |
| etc | Template files for /etc. |
| gnu | Various commands and libraries under the GNU Public License. Please see [gnu/COPYING](gnu/COPYING) and [gnu/COPYING.LIB](gnu/COPYING.LIB) for more information. |
| include | System include files. |
| kerberos5 | Kerberos5 (Heimdal) package. |
| lib | System libraries. |
| libexec | System daemons. |
| release | Release building Makefile & associated tools. |
| rescue | Build system for statically linked /rescue utilities. |
| sbin | System commands. |
| secure | Cryptographic libraries and commands. |
| share | Shared resources. |
| stand | Boot loader sources. |
| sys | Kernel sources. |
| sys/`arch`/conf | Kernel configuration files. GENERIC is the configuration used in release builds. NOTES contains documentation of all possible entries. |
| tests | Regression tests which can be run by Kyua.  See [tests/README](tests/README) for additional information. |
| tools | Utilities for regression testing and miscellaneous tasks. |
| usr.bin | User commands. |
| usr.sbin | System administration commands. |

For information on synchronizing your source tree with one or more of the FreeBSD Project's development branches, please see [FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/cutting-edge/#current-stable).
