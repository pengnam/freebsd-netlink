
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/rmlock.h>
#include <sys/rwlock.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_llatbl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/netisr.h>
#include <net/raw_cb.h>
#include <net/route.h>
#include <net/route/route_ctl.h>
#include <net/route/route_var.h>
#include <net/rtnetlink.h>
#include <net/vnet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip_carp.h>
MALLOC_DEFINE(M_RTNETLINK, "rtnetlink", "Memory used for rtnetlink packets");
/*---- start debugging macros --luigi */
// TODO: remove debugging macros
#define ND(format, ...)
#define D(format, ...)                                                        \
	do {                                                                  \
		struct timeval __xxts;                                        \
		microtime(&__xxts);                                           \
		printf("%03d.%06d [%4d] %-25s " format "\n",                  \
		    (int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec, __LINE__, \
		    __FUNCTION__, ##__VA_ARGS__);                             \
	} while (0)

#ifndef _SOCKADDR_UNION_DEFINED
#define _SOCKADDR_UNION_DEFINED
/*
 * The union of all possible address formats we handle.
 */
union sockaddr_union {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};
#endif /* _SOCKADDR_UNION_DEFINED */

struct walkarg {
	int family;
	int w_tmemsize;
	int w_op, w_arg;
	caddr_t w_tmem;
	struct sysctl_req *w_req;
	struct sockaddr *dst;
	struct sockaddr *mask;
};

struct linear_buffer {
	char *base;	 /* Base allocated memory pointer */
	uint32_t offset; /* Currently used offset */
	uint32_t size;	 /* Total buffer size */
};
/* NB: these are not modified */
// static struct   sockaddr route_src = { 2, PF_ROUTE, };
static struct sockaddr sa_zero = {
	sizeof(sa_zero),
	AF_INET,
};

// 346 struct rt_addrinfo {
// 347     int rti_addrs;          /* Route RTF_ flags */
// 348     int rti_flags;          /* Route RTF_ flags */
// 349     struct  sockaddr *rti_info[RTAX_MAX];   /* Sockaddr data */
// 350     struct  ifaddr *rti_ifa;        /* value of rt_ifa addr */
// 351     struct  ifnet *rti_ifp;         /* route interface */
// 352     rib_filter_f_t  *rti_filter;        /* filter function */
// 353     void    *rti_filterdata;        /* filter paramenters */
// 354     u_long  rti_mflags;         /* metrics RTV_ flags */
// 355     u_long  rti_spare;          /* Will be used for fib */
// 356     struct  rt_metrics *rti_rmx;        /* Pointer to route metrics */
// 357 };
//
static int cleanup_xaddrs(struct rt_addrinfo *info, struct linear_buffer *lb);

static struct nhop_object *
select_nhop(struct nhop_object *nh, const struct sockaddr *gw)
{
	if (!NH_IS_NHGRP(nh))
		return (nh);
	return (NULL);
}

static int
handle_rtm_get(struct rt_addrinfo *info, u_int fibnum, int addrs /*rtm_addrs*/,
    int flags /*rtm_flags*/, struct rib_cmd_info *rc)
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

	/*
	 * By (implicit) convention host route (one without netmask)
	 * means longest-prefix-match request and the route with netmask
	 * means exact-match lookup.
	 * As cleanup_xaddrs() cleans up info flags&addrs for the /32,/128
	 * prefixes, use original data to check for the netmask presence.
	 */
	if ((addrs & RTA_NETMASK) == 0) {
		/*
		 * Provide longest prefix match for
		 * address lookup (no mask).
		 * 'route -n get addr'
		 */
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
	// Consider doing validation here
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
	// Consider doing validation here
	switch (nla_type) {
	case RTA_GATEWAY:
		return RTF_GATEWAY;
	default:
		return 0;
	}
}

static int
rt_xaddrs(struct nlattr *head, int len, struct rt_addrinfo *rtinfo)
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
	printf("in x_addrs\n");

	printf("CHECK: %d\n", rtinfo->rti_flags);
	printf("len: %d\n", len);
	nla_for_each_attribute(nla, head, len, rem)
	{
		type = nla_type(nla);
		l = nla->nla_len;

		printf("nla_type: %d nla_len: %d ", type, l);
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
	rtinfo->rti_flags |= RTF_HOST;

	return (0);
}

static int
fill_addrinfo(struct rtmsg *rtm, int len, struct rt_addrinfo *info)
{

	printf("FIRST CHECK: %d\n", info->rti_flags);
	if (rt_xaddrs(
		(struct nlattr *)(rtm + 1), len - sizeof(struct rtmsg), info))
		return (EINVAL);
	printf("NEXT CHECK: %d\n", info->rti_flags);

	return (0);
}

static void
init_sockaddrs_family(int family, struct sockaddr *dst, struct sockaddr *mask)
{
	if (family == AF_INET) {
		struct sockaddr_in *dst4 = (struct sockaddr_in *)dst;
		struct sockaddr_in *mask4 = (struct sockaddr_in *)mask;

		bzero(dst4, sizeof(struct sockaddr_in));
		bzero(mask4, sizeof(struct sockaddr_in));

		dst4->sin_family = AF_INET;
		dst4->sin_len = sizeof(struct sockaddr_in);
		mask4->sin_family = AF_INET;
		mask4->sin_len = sizeof(struct sockaddr_in);
	}
}
static void
export_rtaddrs(
    const struct rtentry *rt, struct sockaddr *dst, struct sockaddr *mask)
{
	if (dst->sa_family == AF_INET) {
		struct sockaddr_in *dst4 = (struct sockaddr_in *)dst;
		struct sockaddr_in *mask4 = (struct sockaddr_in *)mask;
		uint32_t scopeid = 0;
		rt_get_inet_prefix_pmask(
		    rt, &dst4->sin_addr, &mask4->sin_addr, &scopeid);
		return;
	}
}
static int
dump_rc(struct mbuf *m, struct rib_cmd_info *rc, struct nhop_object *nh)
{

	struct nlmsg *nlm;
	struct rtmsg *rtm;
	union sockaddr_union sa_dst, sa_mask;
	init_sockaddrs_family(family, &sa_dst.sa, &sa_mask.sa);
	export_rtaddrs(rc->rc_rt, &sa_dst.sa, &sa_mask.sa);

	// 1. nlmsg
	nlm = nlmsg_put(struct mbuf * m, int portid, int seq, int type,
	    int payload, int flags) rtm = nlmsg_data(nlm);
	// 2. rtmsg
	rtm->rtm_family = AF_INET;
	// TODO: Concert mask to dst_len
	rtm->rtm_dst_len = 32;
	rtm->rtm_src_len = 0;
	// TODO: Figure out tos
	// rtm->rtm_tos = fri->tos;
	// TODO: Figure out table id
	// rtm->rtm_table = tb_id;
	// if (nla_put_u32(skb, RTA_TABLE, tb_id))
	//	goto nla_put_failure;
	rtm->rtm_type = fri->type;
	rtm->rtm_flags = fi->fib_flags;
	rtm->rtm_scope = fi->fib_scope;
	rtm->rtm_protocol = fi->fib_protocol;
}

static int
rtnl_receive_message(void *data, struct socket *so)
{
	struct rtentry *rt = NULL;
	struct rt_addrinfo info;
	struct epoch_tracker et;
	// TODO: INET6
	int len, error = 0, fibnum;
	struct walkarg w;
	struct rib_cmd_info rc;
	struct nhop_object *nh;

	fibnum = so->so_fibnum;

#define senderr(e)          \
	{                   \
		error = e;  \
		goto flush; \
	}
	NET_EPOCH_ENTER(et);
	bzero(&info, sizeof(info));
	bzero(&w, sizeof(w));
	nh = NULL;
	struct nlmsghdr *hdr = (struct nlmsghdr *)data;
	len = hdr->nlmsg_len - NLMSG_HDRLEN;

	struct rtmsg *rtm = (struct rtmsg *)nlmsg_data(hdr);

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
		D("Check: %p", (info.rti_info[RTAX_DST]));
		error = handle_rtm_get(
		    &info, fibnum, info.rti_addrs, info.rti_flags, &rc);
		if (error != 0)
			senderr(error);
		D("rib_cmd_info- cmd: %d, rt: %p, rc_nh_new: %p", rc.rc_cmd,
		    rc.rc_rt, rc.rc_nh_new);
		if (rc.rc_nh_new != NULL) {
			D("flags:%d mtu:%d nh_ifp:%p nh_ifa: %p",
			    rc.rc_nh_new->nh_flags, rc.rc_nh_new->nh_mtu,
			    rc.rc_nh_new->nh_ifp, rc.rc_nh_new->nh_ifa);
		}

		// nh = rc.rc_nh_new;
		D("here");
		// senderr(EOPNOTSUPP);

	report:

		if (error != 0)
			senderr(error);
		break;

	default:
		senderr(EOPNOTSUPP);
	}

flush:
	NET_EPOCH_EXIT(et);
	rt = NULL;

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
