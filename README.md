# freebsd-netlink

Design document is here
https://docs.google.com/document/d/1VGci3zucEhCphwLkCPVFjLkMudW2vdZUkgjTyqOSaCU/edit#

## Set-up
The configuration is meant for netlink to be installed as a module. Instructions assume that the user is starting from a fresh FreeBSD instance. The instance can be obtained from AWS ec2 community marketplace. This repository was configured with FreeBSD14.0-current

1. Download this github as `/usr/src`
2. Build and install the kernel
3. In `/usr/src/sys/modules/netlink`, run `make`
4. Install module created using `make load`

## Files
1. linux/netlink.h: userspace netlink header. To be added as part of include folder 
2. net/netlink.h: kernel netlink header. To be in the kernel source folder with the source files
3. nl_sock.c: source file implementation. Contains most of the netlink code.

## Headers
As per common practice, I have seperated the userspace API from the kernel API (that has access to the userspace API). I kept it simple, and I kept the userspace api in linux/netlink.h and the kernel api in net/netlink.h




### Major TODOs:
1. we currently assume the initial m_get to retreive a message of a sufficient size for a packet *which allows us to write straight into the buffer instead of using m_append*. The reason for this is because when "closing" a message, we call nlmsg_end or other functions to end the header, we use pointer artihmethic to determine the size of the message. Alternative is to call m_pullup before calling nlmsg_end on the message, or to continuously resize and transfer the message when more data is needed.

2. currently installing netlink as a module rather than as part of the kernel tree


