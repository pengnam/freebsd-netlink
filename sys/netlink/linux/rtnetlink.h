/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Ng Peng Nam Sean
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _UAPI__LINUX_RTNETLINK_H
#define _UAPI__LINUX_RTNETLINK_H

#include <sys/types.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <linux/netlink.h>
#include <linux/if_link.h>
#include <net/route.h>
#include <netinet/in.h>

//TODO: Fix hack
enum rtattr_type_t {
	RTA_UNSPEC = 0x81,
	//RTA_DST,
	RTA_SRC,
	RTA_IIF,
	RTA_OIF,
	//RTA_GATEWAY,
	RTA_PRIORITY,
	RTA_PREFSRC,
	RTA_METRICS,
	RTA_MULTIPATH,
	RTA_FLOW,
	RTA_CACHEINFO,
	RTA_TABLE,
	RTA_MARK,
	RTA_MFC_STATS,
	RTA_VIA,
	RTA_NEWDST,
	RTA_PREF,
	RTA_ENCAP_TYPE,
	RTA_ENCAP,
	RTA_EXPIRES,
	RTA_PAD,
	RTA_UID,
	RTA_TTL_PROPAGATE,
	RTA_IP_PROTO,
	RTA_SPORT,
	RTA_DPORT,
	RTA_NH_ID,
	__RTA_MAX
};

#define RTA_MAX (__RTA_MAX - 1)
/****
 *		Routing/neighbour discovery messages.
 ****/

/* Types of messages */

//NOTE: predefined ones in route.h end at 12
enum {
	RTM_BASE	= 16,
#define RTM_BASE	RTM_BASE

	RTM_NEWLINK	= 16,
#define RTM_NEWLINK	RTM_NEWLINK
	RTM_DELLINK,
#define RTM_DELLINK	RTM_DELLINK
	RTM_GETLINK,
#define RTM_GETLINK	RTM_GETLINK
	RTM_SETLINK,
#define RTM_SETLINK	RTM_SETLINK

	
//	RTM_NEWADDR	= 20,
//#define RTM_NEWADDR	RTM_NEWADDR
//	RTM_DELADDR,
//#define RTM_DELADDR	RTM_DELADDR
	RTM_GETADDR = 22,
#define RTM_GETADDR	RTM_GETADDR

	RTM_NEWROUTE	= 24,
#define RTM_NEWROUTE	RTM_NEWROUTE
	RTM_DELROUTE,
#define RTM_DELROUTE	RTM_DELROUTE
	RTM_GETROUTE,
#define RTM_GETROUTE	RTM_GETROUTE


	__RTM_MAX,
#define RTM_MAX		(((__RTM_MAX + 3) & ~3) - 1)
};

#define RTM_NR_MSGTYPES	(RTM_MAX + 1 - RTM_BASE)
#define RTM_NR_FAMILIES	(RTM_NR_MSGTYPES >> 2)
#define RTM_FAM(cmd)	(((cmd) - RTM_BASE) >> 2)

/* 
   Generic structure for encapsulation of optional route information.
   It is reminiscent of sockaddr, but with sa_family replaced
   with attribute type.
 */

struct rtattr {
	unsigned short	rta_len;
	unsigned short	rta_type;
};

/* Macros to handle rtattributes */

#define RTA_ALIGNTO	4U
#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
#define RTA_OK(rta,len) ((len) >= (int)sizeof(struct rtattr) && \
			 (rta)->rta_len >= sizeof(struct rtattr) && \
			 (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen)	((attrlen) -= RTA_ALIGN((rta)->rta_len), \
				 (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_SPACE(len)	RTA_ALIGN(RTA_LENGTH(len))
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))




/******************************************************************************
 *		Definitions used in routing table administration.
 ****/

struct rtmsg {
	unsigned char		rtm_family;
	unsigned char		rtm_dst_len;
	unsigned char		rtm_src_len;
	unsigned char		rtm_tos;

	unsigned char		rtm_table;	/* Routing table id */
	unsigned char		rtm_protocol;	/* Routing protocol; see below	*/
	unsigned char		rtm_scope;	/* See below */	
	unsigned char		rtm_type;	/* See below	*/

	unsigned		rtm_flags;
};

/* rtm_type */

enum {
	RTN_UNSPEC,
	RTN_UNICAST,		/* Gateway or direct route	*/
	RTN_LOCAL,		/* Accept locally		*/
	RTN_BROADCAST,		/* Accept locally as broadcast,
				   send as broadcast */
	RTN_ANYCAST,		/* Accept locally as broadcast,
				   but send as unicast */
	RTN_MULTICAST,		/* Multicast route		*/
	RTN_BLACKHOLE,		/* Drop				*/
	RTN_UNREACHABLE,	/* Destination is unreachable   */
	RTN_PROHIBIT,		/* Administratively prohibited	*/
	RTN_THROW,		/* Not in this table		*/
	RTN_NAT,		/* Translate this address	*/
	RTN_XRESOLVE,		/* Use external resolver	*/
	__RTN_MAX
};

#define RTN_MAX (__RTN_MAX - 1)


/* rtm_protocol */

#define RTPROT_UNSPEC		0
#define RTPROT_REDIRECT		1	/* Route installed by ICMP redirects;
					   not used by current IPv4 */
#define RTPROT_KERNEL		2	/* Route installed by kernel		*/
#define RTPROT_BOOT		3	/* Route installed during boot		*/
#define RTPROT_STATIC		4	/* Route installed by administrator	*/

/* Values of protocol >= RTPROT_STATIC are not interpreted by kernel;
   they are just passed from user and back as is.
   It will be used by hypothetical multiple routing daemons.
   Note that protocol values should be standardized in order to
   avoid conflicts.
 */

#define RTPROT_GATED		8	/* Apparently, GateD */
#define RTPROT_RA		9	/* RDISC/ND router advertisements */
#define RTPROT_MRT		10	/* Merit MRT */
#define RTPROT_ZEBRA		11	/* Zebra */
#define RTPROT_BIRD		12	/* BIRD */
#define RTPROT_DNROUTED		13	/* DECnet routing daemon */
#define RTPROT_XORP		14	/* XORP */
#define RTPROT_NTK		15	/* Netsukuku */
#define RTPROT_DHCP		16	/* DHCP client */
#define RTPROT_MROUTED		17	/* Multicast daemon */
#define RTPROT_KEEPALIVED	18	/* Keepalived daemon */
#define RTPROT_BABEL		42	/* Babel daemon */
#define RTPROT_OPENR		99	/* Open Routing (Open/R) Routes */
#define RTPROT_BGP		186	/* BGP Routes */
#define RTPROT_ISIS		187	/* ISIS Routes */
#define RTPROT_OSPF		188	/* OSPF Routes */
#define RTPROT_RIP		189	/* RIP Routes */
#define RTPROT_EIGRP		192	/* EIGRP Routes */

/* rtm_scope

   Really it is not scope, but sort of distance to the destination.
   NOWHERE are reserved for not existing destinations, HOST is our
   local addresses, LINK are destinations, located on directly attached
   link and UNIVERSE is everywhere in the Universe.

   Intermediate values are also possible f.e. interior routes
   could be assigned a value between UNIVERSE and LINK.
*/

enum rt_scope_t {
	RT_SCOPE_UNIVERSE=0,
/* User defined values  */
	RT_SCOPE_SITE=200,
	RT_SCOPE_LINK=253,
	RT_SCOPE_HOST=254,
	RT_SCOPE_NOWHERE=255
};

/* rtm_flags */

#define RTM_F_NOTIFY		0x100	/* Notify user of route change	*/
#define RTM_F_CLONED		0x200	/* This route is cloned		*/
#define RTM_F_EQUALIZE		0x400	/* Multipath equalizer: NI	*/
#define RTM_F_PREFIX		0x800	/* Prefix addresses		*/
#define RTM_F_LOOKUP_TABLE	0x1000	/* set rtm_table to FIB lookup result */
#define RTM_F_FIB_MATCH	        0x2000	/* return full fib lookup match */
#define RTM_F_OFFLOAD		0x4000	/* route is offloaded */
#define RTM_F_TRAP		0x8000	/* route is trapping packets */
#define RTM_F_OFFLOAD_FAILED	0x20000000 /* route offload failed, this value
					    * is chosen to avoid conflicts with
					    * other flags defined in
					    * include/uapi/linux/ipv6_route.h
					    */

/* Reserved table identifiers */

enum rt_class_t {
	RT_TABLE_UNSPEC=0,
/* User defined values */
	RT_TABLE_COMPAT=252,
	RT_TABLE_DEFAULT=253,
	RT_TABLE_MAIN=254,
	RT_TABLE_LOCAL=255,
	RT_TABLE_MAX=0xFFFFFFFF
};


/* Routing message attributes */


#define RTM_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct rtmsg))))
#define RTM_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct rtmsg))



/* RTM_METRICS --- array of struct rtattr with types of RTAX_* */

//enum {
//	RTAX_UNSPEC,
//#define RTAX_UNSPEC RTAX_UNSPEC
//	RTAX_LOCK,
//#define RTAX_LOCK RTAX_LOCK
//	RTAX_MTU,
//#define RTAX_MTU RTAX_MTU
//	RTAX_WINDOW,
//#define RTAX_WINDOW RTAX_WINDOW
//	RTAX_RTT,
//#define RTAX_RTT RTAX_RTT
//	RTAX_RTTVAR,
//#define RTAX_RTTVAR RTAX_RTTVAR
//	RTAX_SSTHRESH,
//#define RTAX_SSTHRESH RTAX_SSTHRESH
//	RTAX_CWND,
//#define RTAX_CWND RTAX_CWND
//	RTAX_ADVMSS,
//#define RTAX_ADVMSS RTAX_ADVMSS
//	RTAX_REORDERING,
//#define RTAX_REORDERING RTAX_REORDERING
//	RTAX_HOPLIMIT,
//#define RTAX_HOPLIMIT RTAX_HOPLIMIT
//	RTAX_INITCWND,
//#define RTAX_INITCWND RTAX_INITCWND
//	RTAX_FEATURES,
//#define RTAX_FEATURES RTAX_FEATURES
//	RTAX_RTO_MIN,
//#define RTAX_RTO_MIN RTAX_RTO_MIN
//	RTAX_INITRWND,
//#define RTAX_INITRWND RTAX_INITRWND
//	RTAX_QUICKACK,
//#define RTAX_QUICKACK RTAX_QUICKACK
//	RTAX_CC_ALGO,
//#define RTAX_CC_ALGO RTAX_CC_ALGO
//	RTAX_FASTOPEN_NO_COOKIE,
//#define RTAX_FASTOPEN_NO_COOKIE RTAX_FASTOPEN_NO_COOKIE
//	__RTAX_MAX
//};
//
//#define RTAX_MAX (__RTAX_MAX - 1)

#define RTAX_FEATURE_ECN	(1 << 0)
#define RTAX_FEATURE_SACK	(1 << 1)
#define RTAX_FEATURE_TIMESTAMP	(1 << 2)
#define RTAX_FEATURE_ALLFRAG	(1 << 3)

#define RTAX_FEATURE_MASK	(RTAX_FEATURE_ECN | RTAX_FEATURE_SACK | \
				 RTAX_FEATURE_TIMESTAMP | RTAX_FEATURE_ALLFRAG)


struct rtgenmsg {
	unsigned char		rtgen_family;
};

/*****************************************************************
 *		Link layer specific messages.
 ****/

/* struct ifinfomsg
 * passes link level specific information, not dependent
 * on network protocol.
 */

struct ifinfomsg {
	unsigned char	ifi_family;
	unsigned char	__ifi_pad;
	unsigned short	ifi_type;		/* ARPHRD_* */
	int		ifi_index;		/* Link index	*/
	unsigned	ifi_flags;		/* IFF_* flags	*/
	unsigned	ifi_change;		/* IFF_* change mask */
};

/********************************************************************
 *		prefix information 
 ****/

struct prefixmsg {
	unsigned char	prefix_family;
	unsigned char	prefix_pad1;
	unsigned short	prefix_pad2;
	int		prefix_ifindex;
	unsigned char	prefix_type;
	unsigned char	prefix_len;
	unsigned char	prefix_flags;
	unsigned char	prefix_pad3;
};

enum 
{
	PREFIX_UNSPEC,
	PREFIX_ADDRESS,
	PREFIX_CACHEINFO,
	__PREFIX_MAX
};

#define PREFIX_MAX	(__PREFIX_MAX - 1)

struct prefix_cacheinfo {
	uint32_t	preferred_time;
	uint32_t	valid_time;
};


#ifndef __KERNEL__
/* RTnetlink multicast groups - backwards compatibility for userspace */
#define RTMGRP_LINK		1
#define RTMGRP_NOTIFY		2
#define RTMGRP_NEIGH		4
#define RTMGRP_TC		8

#define RTMGRP_IPV4_IFADDR	0x10
#define RTMGRP_IPV4_MROUTE	0x20
#define RTMGRP_IPV4_ROUTE	0x40
#define RTMGRP_IPV4_RULE	0x80

#define RTMGRP_IPV6_IFADDR	0x100
#define RTMGRP_IPV6_MROUTE	0x200
#define RTMGRP_IPV6_ROUTE	0x400
#define RTMGRP_IPV6_IFINFO	0x800

#define RTMGRP_DECnet_IFADDR    0x1000
#define RTMGRP_DECnet_ROUTE     0x4000

#define RTMGRP_IPV6_PREFIX	0x20000
#endif

/* RTnetlink multicast groups */
enum rtnetlink_groups {
	RTNLGRP_NONE,
#define RTNLGRP_NONE		RTNLGRP_NONE
	RTNLGRP_LINK,
#define RTNLGRP_LINK		RTNLGRP_LINK
	RTNLGRP_NOTIFY,
#define RTNLGRP_NOTIFY		RTNLGRP_NOTIFY
	RTNLGRP_NEIGH,
#define RTNLGRP_NEIGH		RTNLGRP_NEIGH
	RTNLGRP_TC,
#define RTNLGRP_TC		RTNLGRP_TC
	RTNLGRP_IPV4_IFADDR,
#define RTNLGRP_IPV4_IFADDR	RTNLGRP_IPV4_IFADDR
	RTNLGRP_IPV4_MROUTE,
#define	RTNLGRP_IPV4_MROUTE	RTNLGRP_IPV4_MROUTE
	RTNLGRP_IPV4_ROUTE,
#define RTNLGRP_IPV4_ROUTE	RTNLGRP_IPV4_ROUTE
	RTNLGRP_IPV4_RULE,
#define RTNLGRP_IPV4_RULE	RTNLGRP_IPV4_RULE
	RTNLGRP_IPV6_IFADDR,
#define RTNLGRP_IPV6_IFADDR	RTNLGRP_IPV6_IFADDR
	RTNLGRP_IPV6_MROUTE,
#define RTNLGRP_IPV6_MROUTE	RTNLGRP_IPV6_MROUTE
	RTNLGRP_IPV6_ROUTE,
#define RTNLGRP_IPV6_ROUTE	RTNLGRP_IPV6_ROUTE
	RTNLGRP_IPV6_IFINFO,
#define RTNLGRP_IPV6_IFINFO	RTNLGRP_IPV6_IFINFO
	RTNLGRP_DECnet_IFADDR,
#define RTNLGRP_DECnet_IFADDR	RTNLGRP_DECnet_IFADDR
	RTNLGRP_NOP2,
	RTNLGRP_DECnet_ROUTE,
#define RTNLGRP_DECnet_ROUTE	RTNLGRP_DECnet_ROUTE
	RTNLGRP_DECnet_RULE,
#define RTNLGRP_DECnet_RULE	RTNLGRP_DECnet_RULE
	RTNLGRP_NOP4,
	RTNLGRP_IPV6_PREFIX,
#define RTNLGRP_IPV6_PREFIX	RTNLGRP_IPV6_PREFIX
	RTNLGRP_IPV6_RULE,
#define RTNLGRP_IPV6_RULE	RTNLGRP_IPV6_RULE
	RTNLGRP_ND_USEROPT,
#define RTNLGRP_ND_USEROPT	RTNLGRP_ND_USEROPT
	RTNLGRP_PHONET_IFADDR,
#define RTNLGRP_PHONET_IFADDR	RTNLGRP_PHONET_IFADDR
	RTNLGRP_PHONET_ROUTE,
#define RTNLGRP_PHONET_ROUTE	RTNLGRP_PHONET_ROUTE
	RTNLGRP_DCB,
#define RTNLGRP_DCB		RTNLGRP_DCB
	RTNLGRP_IPV4_NETCONF,
#define RTNLGRP_IPV4_NETCONF	RTNLGRP_IPV4_NETCONF
	RTNLGRP_IPV6_NETCONF,
#define RTNLGRP_IPV6_NETCONF	RTNLGRP_IPV6_NETCONF
	RTNLGRP_MDB,
#define RTNLGRP_MDB		RTNLGRP_MDB
	RTNLGRP_MPLS_ROUTE,
#define RTNLGRP_MPLS_ROUTE	RTNLGRP_MPLS_ROUTE
	RTNLGRP_NSID,
#define RTNLGRP_NSID		RTNLGRP_NSID
	RTNLGRP_MPLS_NETCONF,
#define RTNLGRP_MPLS_NETCONF	RTNLGRP_MPLS_NETCONF
	RTNLGRP_IPV4_MROUTE_R,
#define RTNLGRP_IPV4_MROUTE_R	RTNLGRP_IPV4_MROUTE_R
	RTNLGRP_IPV6_MROUTE_R,
#define RTNLGRP_IPV6_MROUTE_R	RTNLGRP_IPV6_MROUTE_R
	RTNLGRP_NEXTHOP,
#define RTNLGRP_NEXTHOP		RTNLGRP_NEXTHOP
	RTNLGRP_BRVLAN,
#define RTNLGRP_BRVLAN		RTNLGRP_BRVLAN
	__RTNLGRP_MAX
};
#define RTNLGRP_MAX	(__RTNLGRP_MAX - 1)

//START OF IF_ADDR SECTION


struct ifaddrmsg {
	uint8_t		ifa_family;
	uint8_t		ifa_prefixlen;	/* The prefix length		*/
	uint8_t		ifa_flags;	/* Flags			*/
	uint8_t		ifa_scope;	/* Address scope		*/
	uint32_t		ifa_index;	/* Link index			*/
};

/*
 * Important comment:
 * IFA_ADDRESS is prefix address, rather than local interface address.
 * It makes no difference for normally configured broadcast interfaces,
 * but for point-to-point IFA_ADDRESS is DESTINATION address,
 * local address is supplied in IFA_LOCAL attribute.
 *
 * IFA_FLAGS is a u32 attribute that extends the u8 field ifa_flags.
 * If present, the value from struct ifaddrmsg will be ignored.
 */
enum {
	IFA_UNSPEC,
	IFA_ADDRESS,
	IFA_LOCAL,
	IFA_LABEL,
	IFA_BROADCAST,
	IFA_ANYCAST,
	IFA_CACHEINFO,
	IFA_MULTICAST,
	IFA_FLAGS,
	IFA_RT_PRIORITY,  /* u32, priority/metric for prefix route */
	IFA_TARGET_NETNSID,
	__IFA_MAX,
};

#define IFA_MAX (__IFA_MAX - 1)

/* ifa_flags */
#define IFA_F_SECONDARY		0x01
#define IFA_F_TEMPORARY		IFA_F_SECONDARY

#define	IFA_F_NODAD		0x02
#define IFA_F_OPTIMISTIC	0x04
#define IFA_F_DADFAILED		0x08
#define	IFA_F_HOMEADDRESS	0x10
#define IFA_F_DEPRECATED	0x20
#define IFA_F_TENTATIVE		0x40
#define IFA_F_PERMANENT		0x80
#define IFA_F_MANAGETEMPADDR	0x100
#define IFA_F_NOPREFIXROUTE	0x200
#define IFA_F_MCAUTOJOIN	0x400
#define IFA_F_STABLE_PRIVACY	0x800

struct ifa_cacheinfo {
	uint32_t	ifa_prefered;
	uint32_t	ifa_valid;
	uint32_t	cstamp; /* created timestamp, hundredths of seconds */
	uint32_t	tstamp; /* updated timestamp, hundredths of seconds */
};

//END OF IF_ADDR SECTION


#endif /* _UAPI__LINUX_RTNETLINK_H */
