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
// TODO: Hack needed for rt_get_inet_prefix_pmask
#define INET 1
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/rmlock.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/route/route_ctl.h>
#include <net/route/route_var.h>
#include <net/rtnetlink.h>

MALLOC_DEFINE(M_RTNETLINK, "rtnetlink", "Memory used for rtnetlink packets");
#define D(format, ...)                                                        \
	do {                                                                  \
		printf("%-10s " format "\n", __FUNCTION__, ##__VA_ARGS__);    \
	} while (0)


static struct nhop_object *
select_nhop(struct nhop_object *nh, const struct sockaddr *gw)
{
	if (!NH_IS_NHGRP(nh))
		return (nh);
	return (NULL);
}

static int
handle_rtm_getroute(struct rt_addrinfo *info, u_int fibnum, int addrs,
    int flags, struct rib_cmd_info *rc)
{
	RIB_RLOCK_TRACKER;
	struct rib_head *rnh;
	struct nhop_object *nh;
	sa_family_t saf;

	saf = info->rti_info[RTAX_DST]->sa_family;

	rnh = rt_tables_get_rnh(fibnum, saf);
	if (rnh == NULL)
		return (EAFNOSUPPORT);

	RIB_RLOCK(rnh);

	if ((addrs & RTA_NETMASK) == 0) {
		rc->rc_rt = (struct rtentry *)rnh->rnh_matchaddr(
		    info->rti_info[RTAX_DST], &rnh->head);
	} else
		rc->rc_rt = (struct rtentry *)rnh->rnh_lookup(
		    info->rti_info[RTAX_DST], info->rti_info[RTAX_NETMASK],
		    &rnh->head);

	if (rc->rc_rt == NULL) {
		RIB_RUNLOCK(rnh);
		return (ESRCH);
	}

	nh = select_nhop(
	    rt_get_raw_nhop(rc->rc_rt), info->rti_info[RTAX_GATEWAY]);
	if (nh == NULL) {
		RIB_RUNLOCK(rnh);
		return (ESRCH);
	}
	rc->rc_nh_new = nh;
	rc->rc_nh_weight = rc->rc_rt->rt_weight;
	RIB_RUNLOCK(rnh);

	return (0);
}

static int
get_rtax_from_nla_type(int nla_type, int *rtax_type)
{
	// TODO:Consider doing validation here
	switch (nla_type) {
	case RTA_DST:
		*rtax_type = RTAX_DST;
		return 0;
	case RTA_GATEWAY:
		*rtax_type = RTAX_GATEWAY;
		return 0;
	default:
		return EINVAL;
	}
}

static int
get_rtflag_from_nla_type(int nla_type)
{
	switch (nla_type) {
	case RTF_GATEWAY:
		return RTA_GATEWAY;
	default:
		return 0;
	}
}

/*
 * Parses the netlink attributes into an rtinfo object.
 */
static int
parse_rtmsg_nlattr(struct nlattr *head, int len, struct rt_addrinfo *rtinfo)
{
	struct sockaddr *sa;
	struct sockaddr_in *sai;
	int rem;
	int rtax_type;
	int error;
	int type;
	int l;
	int flag;
	struct nlattr *nla;
	nla_for_each_attribute(nla, head, len, rem)
	{
		type = nla_type(nla);
		l = nla->nla_len;

		// TODO: do I need to validate?
		if ((error = get_rtax_from_nla_type(type, &rtax_type))) {
			printf("Retrieved invalid type: %d\n", type);
			continue;
		}
		flag = get_rtflag_from_nla_type(type);
		printf("flag: %d\n", flag);
		rtinfo->rti_flags |= flag;
		printf("rti_flag:%d\n", rtinfo->rti_flags);
		printf("rtax_type: %d\n", rtax_type);
		switch (type) {
		case RTA_DST:
		case RTA_GATEWAY:
			// TODO: look at fill_sockaddr_in
			sa = malloc(sizeof(struct sockaddr), M_RTNETLINK,
			    M_NOWAIT | M_ZERO);
			if (sa == NULL) {
				return (ENOBUFS);
			}
			sa->sa_len = sizeof(struct sockaddr);
			sa->sa_family = AF_INET;
			sai = (struct sockaddr_in *)sa;
			memcpy(
			    &(sai->sin_addr), nla_data(nla), sizeof(uint32_t));
			rtinfo->rti_info[rtax_type] = sa;

			rtinfo->rti_addrs |= type;
			break;
		default:

			break;
		}
	}

	// TODO: Handle netmask (corresponds to rtm_dst_len) for now assume
	// everything host

	return (0);
}

// TODO: Fix parse_netmask
static int
parse_netmask(struct rtmsg *rtm, struct rt_addrinfo *info)
{

	struct sockaddr_in *mask_sa;
	uint32_t num_digits = rtm->rtm_dst_len;
	D("num_digits: %d", num_digits);
	if (num_digits < 0 || num_digits > 32) {
		return (EINVAL);
	}
	if (num_digits < 32) {
		mask_sa = malloc(
		    sizeof(struct sockaddr), M_RTNETLINK, M_NOWAIT | M_ZERO);
		/*Find the equivalent mask*/
		num_digits = 32 - num_digits;
		uint32_t mask = ~((1 << (num_digits)) - 1);
		mask_sa->sin_addr.s_addr = mask;
		// TODO: Revert back
		// info->rti_info[RTAX_NETMASK] = (struct sockaddr * ) mask_sa;
		// info->rti_addrs |= RTA_NETMASK;
		info->rti_flags |= RTF_HOST;

	} else {
		D("set flag");
		info->rti_flags |= RTF_HOST;
	}
	return 0;
}

/*
 * Populates an addrinfo struct from an rtmsg.
 * Parses the nl_attributes and parses the netmask.
 */
static int
fill_addrinfo(struct rtmsg *rtm, int len, struct rt_addrinfo *info)
{

	if (parse_rtmsg_nlattr(
		(struct nlattr *)(rtm + 1), len - sizeof(struct rtmsg), info))
		return (EINVAL);
	if (parse_netmask(rtm, info))
		return (EINVAL);

	return (0);
}

static void
init_sockaddrs(const struct rtentry *rt, struct sockaddr_in *dst, struct sockaddr_in *mask)
{
	uint32_t scopeid = 0;
	bzero(dst, sizeof(struct sockaddr_in));
	bzero(mask, sizeof(struct sockaddr_in));

	dst->sin_family = AF_INET;
	dst->sin_len = sizeof(struct sockaddr_in);
	mask->sin_family = AF_INET;
	mask->sin_len = sizeof(struct sockaddr_in);

	rt_get_inet_prefix_pmask(rt, &dst->sin_addr, &mask->sin_addr, &scopeid);
}

/*
 * Dumps output from a rib command into an rtmsg
 */
static struct mbuf *
dump_rc(uint32_t tableid, uint32_t portid, uint32_t seq,
    struct rt_addrinfo *info, struct rib_cmd_info *rc, struct nhop_object *nh)
{

	struct nlmsghdr *nlm;
	struct rtmsg *rtm;
	struct sockaddr_in sa_dst, sa_mask;
	struct ifnet *ifp;
	struct nlattr *metrics_nla;
	// NOTE: Flag setting logic at
	// https://elixir.bootlin.com/linux/v5.13-rc4/source/net/ipv4/fib_trie.c#L2248
	// Assumed to always be a dump filter
	uint32_t flags = NLM_F_MULTI | NLM_F_DUMP_FILTERED;
	int payload = sizeof(struct rtmsg);
	struct mbuf *m = nlmsg_new(payload, M_NOWAIT);
	if (m == NULL) {
		D("Error initializing mbuf");
		return NULL;
	}

	init_sockaddrs(rc->rc_rt, &sa_dst, &sa_mask);

	// 1. nlmsg
	// TODO: Assumed to always be NEWROUTE
	// https://elixir.bootlin.com/linux/v5.13-rc4/source/net/ipv4/fib_frontend.c#L965
	nlm = nlmsg_put(m, portid, seq, RTM_NEWROUTE, payload, flags);
	rtm = nlmsg_data(nlm);
	// 2. rtmsg
	rtm->rtm_family = AF_INET;
	// TODO: Concert mask to dst_len
	rtm->rtm_dst_len = 32;
	rtm->rtm_src_len = 0;
	rtm->rtm_table = tableid;
	// TODO: Figure out flags
	//
	// TODO: Handle put errors
	nla_put(m, RTA_DST, 4, &sa_dst.sin_addr);

	nla_put(m, RTA_NETMASK, 4, &sa_mask.sin_addr);

	nla_put(m, RTA_GATEWAY, 4, &nh->gw4_sa.sin_addr);

	ifp = nh->nh_ifp;
	if (ifp) {
		nla_put_u32(m, RTA_OIF, ifp->if_index);
	}

	metrics_nla = nla_nest_start(m, RTA_METRICS);
	// TODO: Change back to RTAX_MTU after comments included
	nla_put_u32(m, 2, nh->nh_mtu);

	nla_nest_end(m, metrics_nla);

	nlmsg_end(m, nlm);

	return m;
}

/*
 * Handler called by netlink subsystem when matching netlink message is received
 */
static int
rtnl_receive_message(void *data, struct socket *so)
{
	struct rt_addrinfo info;
	struct epoch_tracker et;
	// TODO: INET6
	int len, error = 0, fibnum;
	struct rib_cmd_info rc;
	struct nhop_object *nh = NULL;
	struct nlpcb * rp;
	struct rtmsg * rtm;
	struct nlmsghdr * hdr;
	struct mbuf *m;

	fibnum = so->so_fibnum;

#define senderr(e)          \
	{                   \
		error = e;  \
		goto flush; \
	}
	NET_EPOCH_ENTER(et);
	bzero(&info, sizeof(info));

	hdr = (struct nlmsghdr *)data;
	len = hdr->nlmsg_len - NLMSG_HDRLEN;

	rtm = (struct rtmsg *)nlmsg_data(hdr);

	rp = sotonlpcb(so);

	if ((error = fill_addrinfo(rtm, len, &info)) != 0) {
		senderr(error);
	}

	D("Received msg type: %d", hdr->nlmsg_type);
	switch (hdr->nlmsg_type) {
	case RTM_NEWROUTE:

		if (info.rti_info[RTAX_GATEWAY] == NULL)
			senderr(EINVAL);

		error = rib_action(fibnum, RTM_ADD, &info, &rc);
		D("Error:%d", error);
		break;

	case RTM_DELROUTE:
		error = rib_action(fibnum, RTM_DELETE, &info, &rc);
		if (error == 0) {
			nh = rc.rc_nh_old;
			goto report;
		}
		break;

	case RTM_GETROUTE:
		error = handle_rtm_getroute(
		    &info, fibnum, info.rti_addrs, info.rti_flags, &rc);
		if (error != 0)
			senderr(error);
		nh = rc.rc_nh_new;
		m = dump_rc(fibnum, rp->portid, hdr->nlmsg_seq, &info, &rc, nh);
		nl_send_msg(m, rp->rp.rcb_proto.sp_protocol);

	report:

		if (error != 0)
			senderr(error);
		break;

	default:
		senderr(EOPNOTSUPP);
	}

flush:
	NET_EPOCH_EXIT(et);

	// TODO: INET6 stuff

	return (error);
}

static void
rtnl_load(void *u __unused)
{
	// TODO: initialize
	D("rtnl loading");
	nl_register_or_replace_handler(NETLINK_ROUTE, rtnl_receive_message);
	// TODO: initialize bsd nl
}

static void
rtnl_unload(void *u __unused)
{
}

SYSINIT(rtnl_load, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, rtnl_load, NULL);
SYSINIT(rtnl_unload, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, rtnl_unload, NULL);
