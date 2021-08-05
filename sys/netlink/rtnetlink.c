
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/domain.h>
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
#include <sys/systm.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_llatbl.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/raw_cb.h>
#include <net/route.h>
#include <net/route/route_ctl.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip_carp.h>
#include <net/route/route_var.h>


#include <net/rtnetlink.h>
MALLOC_DEFINE(M_RTNETLINK, "rtnetlink", "Memory used for rtnetlink packets");
/*---- start debugging macros --luigi */
//TODO: remove debugging macros
#define ND(format, ...)
#define D(format, ...)                                          \
	do {                                                    \
		struct timeval __xxts;                          \
		microtime(&__xxts);                             \
		printf("%03d.%06d [%4d] %-25s " format "\n",    \
				(int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec, \
				__LINE__, __FUNCTION__, ##__VA_ARGS__);         \
	} while (0)




 #ifndef _SOCKADDR_UNION_DEFINED
 #define _SOCKADDR_UNION_DEFINED
 /*
  * The union of all possible address formats we handle.
  */
 union sockaddr_union {
     struct sockaddr     sa;
     struct sockaddr_in  sin;
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
    char        *base;  /* Base allocated memory pointer */
    uint32_t    offset; /* Currently used offset */
    uint32_t    size;   /* Total buffer size */
};
/* NB: these are not modified */
//static struct   sockaddr route_src = { 2, PF_ROUTE, };
static struct   sockaddr sa_zero   = { sizeof(sa_zero), AF_INET, };



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
static int  cleanup_xaddrs(struct rt_addrinfo *info, struct linear_buffer *lb);

static struct nhop_object *
select_nhop(struct nhop_object *nh, const struct sockaddr *gw)
{
    if (!NH_IS_NHGRP(nh))
        return (nh);
    return (NULL);
}


static int
handle_rtm_get(struct rt_addrinfo *info, u_int fibnum,
    int addrs /*rtm_addrs*/, int flags /*rtm_flags*/, struct rib_cmd_info *rc)
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
        rc->rc_rt = (struct rtentry *) rnh->rnh_matchaddr(
            info->rti_info[RTAX_DST], &rnh->head);
    } else
        rc->rc_rt = (struct rtentry *) rnh->rnh_lookup(
            info->rti_info[RTAX_DST],
            info->rti_info[RTAX_NETMASK], &rnh->head);

    if (rc->rc_rt == NULL) {
        RIB_RUNLOCK(rnh);
        return (ESRCH);
    }

    nh = select_nhop(rt_get_raw_nhop(rc->rc_rt), info->rti_info[RTAX_GATEWAY]);
    if (nh == NULL) {
        RIB_RUNLOCK(rnh);
        return (ESRCH);
    }
    /*
     * If performing proxied L2 entry insertion, and
     * the actual PPP host entry is found, perform
     * another search to retrieve the prefix route of
     * the local end point of the PPP link.
     * TODO: move this logic to userland.
     */
    if (flags & RTF_ANNOUNCE) {
        struct sockaddr laddr;

        if (nh->nh_ifp != NULL &&
            nh->nh_ifp->if_type == IFT_PROPVIRTUAL) {
            struct ifaddr *ifa;

            ifa = ifa_ifwithnet(info->rti_info[RTAX_DST], 1,
                    RT_ALL_FIBS);
            if (ifa != NULL)
                rt_maskedcopy(ifa->ifa_addr,
                          &laddr,
                          ifa->ifa_netmask);
        } else
            rt_maskedcopy(nh->nh_ifa->ifa_addr,
                      &laddr,
                      nh->nh_ifa->ifa_netmask);
        /*
         * refactor rt and no lock operation necessary
         */
        rc->rc_rt = (struct rtentry *)rnh->rnh_matchaddr(&laddr,
            &rnh->head);
        if (rc->rc_rt == NULL) {
            RIB_RUNLOCK(rnh);
            return (ESRCH);
        }
        nh = select_nhop(rt_get_raw_nhop(rc->rc_rt), info->rti_info[RTAX_GATEWAY]);
        if (nh == NULL) {
            RIB_RUNLOCK(rnh);
            return (ESRCH);
        }
    }
    rc->rc_nh_new = nh;
    rc->rc_nh_weight = rc->rc_rt->rt_weight;
    RIB_RUNLOCK(rnh);

    return (0);

}

static int
get_rtax_from_nla_type(int nla_type, int* rtax_type) {
	//Consider doing validation here
	switch (nla_type) {
    case RTA_TABLE:
    case RTA_SRC:
    case RTA_OIF:
    case RTA_FLOW:
    case RTA_PREFSRC:
    case RTA_PRIORITY:
	    return EINVAL;
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
 test_create_rtentry( struct rt_addrinfo *info)
 {
     struct sockaddr *dst,  *gateway, *netmask;
     int  flags;

     dst = info->rti_info[RTAX_DST];
     gateway = info->rti_info[RTAX_GATEWAY];
     netmask = info->rti_info[RTAX_NETMASK];
     flags = info->rti_flags;
    if (info->rti_flags & RTF_HOST)
	 info->rti_info[RTAX_NETMASK] = NULL;
     else if (info->rti_info[RTAX_NETMASK] == NULL) {
	    D("oh no");
	 return (EINVAL);
     }

     if ((flags & RTF_GATEWAY) && !gateway) {
	     D("A");
         return (EINVAL);
     }
     if (dst && gateway && (dst->sa_family != gateway->sa_family) &&
         (gateway->sa_family != AF_UNSPEC) && (gateway->sa_family != AF_LINK)) {
	     D("B");
         return (EINVAL);
     }

     if (dst->sa_len > sizeof(((struct rtentry *)NULL)->rt_dstb)) {
	     D("C");
         return (EINVAL);
     }
     return 0;
}

static int
rt_xaddrs(struct nlattr *head, int len, struct rt_addrinfo *rtinfo)
{
	struct sockaddr * sa;
    struct sockaddr_in *sai;
    int rem;
    int rtax_type;
    int error;
    int type;
    int l;
    struct nlattr * nla;
    printf("in x_addrs\n");
    
    printf("CHECK: %d\n", rtinfo->rti_flags);
    printf("len: %d\n", len);
    nla_for_each_attribute(nla, head, len, rem) {
        type = nla_type(nla);
	l = nla->nla_len;

        printf("nla_type: %d nla_len: %d ", type, l);
        //TODO: do I need to validate?
        if ((error = get_rtax_from_nla_type(type, &rtax_type))) {
        	printf("Retrieved invalid type: %d\n", type);
        	continue;
        }
        printf("rtax_type: %d\n", rtax_type);
        switch (type) {
        	case RTA_DST:
		case RTA_GATEWAY:
        		    //TODO: look at fill_sockaddr_in
			sa = malloc(sizeof(struct sockaddr),M_RTNETLINK, M_NOWAIT | M_ZERO);
			if (sa == NULL) {
				return (ENOBUFS);
			}
        		sa->sa_len = sizeof(struct sockaddr);
        		sa->sa_family = AF_INET;
        		sai = (struct sockaddr_in *) sa;
        		memcpy(&(sai->sin_addr), nla_data(nla), sizeof(uint32_t));
        		rtinfo->rti_info[rtax_type] = sa;

			rtinfo->rti_addrs |= type;
        		break;
        	default:

        		break;
        }

    }

    //TODO: Handle netmask (corresponds to rtm_dst_len) for now assume everything host
    rtinfo->rti_flags|= RTF_HOST;


    return (0);
}

static int
fill_addrinfo(struct rtmsg *rtm, int len, struct rt_addrinfo *info)
{
    //int error;
    sa_family_t saf;

    //TODO

    /*
     * rt_xaddrs() performs s6_addr[2] := sin6_scope_id for AF_INET6
     * link-local address because rtrequest requires addresses with
     * embedded scope id.
     */
    printf("FIRST CHECK: %d\n", info->rti_flags);
    info->rti_flags = rtm->rtm_flags;
    if (rt_xaddrs((struct nlattr *)(rtm + 1), len - sizeof(struct rtmsg), info))
        return (EINVAL);

    printf("NEXT CHECK: %d\n",info->rti_flags);
    //error = cleanup_xaddrs(info, lb);
    //if (error != 0)
    //    return (error);
    saf = info->rti_info[RTAX_DST]->sa_family;
    D("hmm seems okay");


    return (0);
}


	static int
rtnl_receive_message(void* data, struct socket *so)
{
	struct rtentry *rt = NULL;
	struct rt_addrinfo info;
	struct epoch_tracker et;
	//TODO: INET6
	int  len, error = 0, fibnum;
	//sa_family_t saf = AF_UNSPEC;
	struct walkarg w;
	struct rib_cmd_info rc;
	struct nhop_object *nh;

	fibnum = so->so_fibnum;

#define senderr(e) { error = e; goto flush;}
	//if (m == NULL || ((m->m_len < sizeof(long)) &&
	//	       (m = m_pullup(m, sizeof(long))) == NULL))
	//	return (ENOBUFS);
	//if ((m->m_flags & M_PKTHDR) == 0)
	//	panic("route_output");
	NET_EPOCH_ENTER(et);
	//len = m->m_pkthdr.len;
	//if (len < sizeof(*rtm) ||
	//    len != mtod(m, struct rt_msghdr *)->rtm_msglen)
	//	senderr(EINVAL);

	///*
	// * Most of current messages are in range 200-240 bytes,
	// * minimize possible re-allocation on reply using larger size
	// * buffer aligned on 1k boundaty.
	// */
	//alloc_len = roundup2(len, 1024);
	//if ((rtm = malloc(alloc_len, M_TEMP, M_NOWAIT)) == NULL)
	//	senderr(ENOBUFS);

	//m_copydata(m, 0, len, (caddr_t)rtm);
	bzero(&info, sizeof(info));
	bzero(&w, sizeof(w));
	nh = NULL;
	struct nlmsghdr * hdr = (struct nlmsghdr*) data;
	len = hdr->nlmsg_len - NLMSG_HDRLEN;

	struct rtmsg *rtm = (struct rtmsg*) nlmsg_data(hdr);


	if ((error = fill_addrinfo(rtm, len,  &info)) != 0) {
		senderr(error);
	}

	//saf = info.rti_info[RTAX_DST]->sa_family;

	//TODO: lldata flag handling
	int test;
	D("Received msg type: %d", hdr->nlmsg_type);

	switch (hdr->nlmsg_type) {
	case RTM_NEWROUTE:

		//TODO: Fix header
		D("RTAX_GATEWAY: %p", info.rti_info[RTAX_DST]);
		if (info.rti_info[RTAX_GATEWAY] == NULL)
			senderr(EINVAL);
		
		test = test_create_rtentry(&info);
		D("TEST RESULT: %d:", test);
		error = rib_action(fibnum, RTM_ADD, &info, &rc);
		D("Error:%d", error);
		//if (error == 0) {
		//	nh = rc.rc_nh_new;
		//	//rtm->rtm_index = nh->nh_ifp->if_index;
		//	//rtm->rtm_flags = rc.rc_rt->rte_flags | nhop_get_rtflags(nh);
		//}
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
		//error = handle_rtm_get(&info, fibnum, 0, 0, &rc);
		if (error != 0)
			senderr(error);
		//nh = rc.rc_nh_new;
		D("here");
		//senderr(EOPNOTSUPP);

report:
		//if (!can_export_rte(curthread->td_ucred,
		//    info.rti_info[RTAX_NETMASK] == NULL,
		//    info.rti_info[RTAX_DST])) {
		//	senderr(ESRCH);
		//}

		//TODO:
		//error = update_rtm_from_rc(&info, &rtm, alloc_len, &rc, nh);
		/*
		 * Note that some sockaddr pointers may have changed to
		 * point to memory outsize @rtm. Some may be pointing
		 * to the on-stack variables.
		 * Given that, any pointer in @info CANNOT BE USED.
		 */

		/*
		 * scopeid deembedding has been performed while
		 * writing updated rtm in rtsock_msg_buffer().
		 * With that in mind, skip deembedding procedure below.
		 */
		if (error != 0)
			senderr(error);
		break;

	default:
		senderr(EOPNOTSUPP);
	}

flush:
	NET_EPOCH_EXIT(et);
	rt = NULL;

	//TODO: INET6 stuff
	//TODO: Reply
	//send_rtm_reply(so, rtm, m, saf, fibnum, error);

	return (error);
}

	static void
rtnl_load(void *u __unused)
{
	//TODO: initialize
	D("rtnl loading");
	nl_register_or_replace_handler(NETLINK_ROUTE, rtnl_receive_message);
	//TODO: initialize bsd nl
}

	static void
rtnl_unload(void *u __unused)
{

}

SYSINIT(rtnl_load, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, rtnl_load, NULL);
SYSINIT(rtnl_unload, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, rtnl_unload, NULL);


#ifdef INET
static int
cleanup_xaddrs_inet(struct rt_addrinfo *info, struct linear_buffer *lb)
{
    struct sockaddr_in *dst_sa, *mask_sa;
    const int sa_len = sizeof(struct sockaddr_in);
    struct in_addr dst, mask;

    /* Check & fixup dst/netmask combination first */
    dst_sa = (struct sockaddr_in *)info->rti_info[RTAX_DST];
    mask_sa = (struct sockaddr_in *)info->rti_info[RTAX_NETMASK];

    /* Ensure reads do not go beyound the buffer size */
    if (SA_SIZE(dst_sa) < offsetof(struct sockaddr_in, sin_zero))
        return (EINVAL);

    if ((mask_sa != NULL) && mask_sa->sin_len < sizeof(struct sockaddr_in)) {
        /*
         * Some older routing software encode mask length into the
         * sin_len, thus resulting in "truncated" sockaddr.
         */
        int len = mask_sa->sin_len - offsetof(struct sockaddr_in, sin_addr);
        if (len >= 0) {
            mask.s_addr = 0;
            if (len > sizeof(struct in_addr))
                len = sizeof(struct in_addr);
            memcpy(&mask, &mask_sa->sin_addr, len);
        } else {
            RTS_PID_PRINTF("prefix mask sin_len too small: %d", mask_sa->sin_len);
            return (EINVAL);
        }
    } else
        mask.s_addr = mask_sa ? mask_sa->sin_addr.s_addr : INADDR_BROADCAST;

    dst.s_addr = htonl(ntohl(dst_sa->sin_addr.s_addr) & ntohl(mask.s_addr));

    /* Construct new "clean" dst/mask sockaddresses */
    if ((dst_sa = (struct sockaddr_in *)alloc_sockaddr_aligned(lb, sa_len)) == NULL)
        return (ENOBUFS);
    fill_sockaddr_inet(dst_sa, dst);
    info->rti_info[RTAX_DST] = (struct sockaddr *)dst_sa;

    if (mask.s_addr != INADDR_BROADCAST) {
        if ((mask_sa = (struct sockaddr_in *)alloc_sockaddr_aligned(lb, sa_len)) == NULL)
            return (ENOBUFS);
        fill_sockaddr_inet(mask_sa, mask);
        info->rti_info[RTAX_NETMASK] = (struct sockaddr *)mask_sa;
        info->rti_flags &= ~RTF_HOST;
    } else
        remove_netmask(info);

    /* Check gateway */
    if (info->rti_info[RTAX_GATEWAY] != NULL)
        return (cleanup_xaddrs_gateway(info, lb));

    return (0);
}
#endif

#ifdef INET6
static int
cleanup_xaddrs_inet6(struct rt_addrinfo *info, struct linear_buffer *lb)
{
    struct sockaddr *sa;
    struct sockaddr_in6 *dst_sa, *mask_sa;
    struct in6_addr mask, *dst;
    const int sa_len = sizeof(struct sockaddr_in6);

    /* Check & fixup dst/netmask combination first */
    dst_sa = (struct sockaddr_in6 *)info->rti_info[RTAX_DST];
    mask_sa = (struct sockaddr_in6 *)info->rti_info[RTAX_NETMASK];

    if (dst_sa->sin6_len < sizeof(struct sockaddr_in6)) {
        RTS_PID_PRINTF("prefix dst sin6_len too small: %d", dst_sa->sin6_len);
        return (EINVAL);
    }

    if (mask_sa && mask_sa->sin6_len < sizeof(struct sockaddr_in6)) {
        /*
         * Some older routing software encode mask length into the
         * sin6_len, thus resulting in "truncated" sockaddr.
         */
        int len = mask_sa->sin6_len - offsetof(struct sockaddr_in6, sin6_addr);
        if (len >= 0) {
            bzero(&mask, sizeof(mask));
            if (len > sizeof(struct in6_addr))
                len = sizeof(struct in6_addr);
            memcpy(&mask, &mask_sa->sin6_addr, len);
        } else {
            RTS_PID_PRINTF("rtsock: prefix mask sin6_len too small: %d", mask_sa->sin6_len);
            return (EINVAL);
        }
    } else
}
#endif

#ifdef INET6
static int
cleanup_xaddrs_inet6(struct rt_addrinfo *info, struct linear_buffer *lb)
{
    struct sockaddr *sa;
    struct sockaddr_in6 *dst_sa, *mask_sa;
    struct in6_addr mask, *dst;
    const int sa_len = sizeof(struct sockaddr_in6);

    /* Check & fixup dst/netmask combination first */
    dst_sa = (struct sockaddr_in6 *)info->rti_info[RTAX_DST];
    mask_sa = (struct sockaddr_in6 *)info->rti_info[RTAX_NETMASK];

    if (dst_sa->sin6_len < sizeof(struct sockaddr_in6)) {
            const struct sockaddr_dl_short sdl = {
                .sdl_family = AF_LINK,
                .sdl_len = sizeof(struct sockaddr_dl_short),
                .sdl_index = gw_sdl->sdl_index,
            };
            *((struct sockaddr_dl_short *)sa) = sdl;
            info->rti_info[RTAX_GATEWAY] = sa;
            break;
        }
    }

    return (0);
}
#endif

static void
remove_netmask(struct rt_addrinfo *info)
{
    info->rti_info[RTAX_NETMASK] = NULL;
    info->rti_flags |= RTF_HOST;
    info->rti_addrs &= ~RTA_NETMASK;
}

#ifdef INET
static int
cleanup_xaddrs_inet(struct rt_addrinfo *info, struct linear_buffer *lb)
{
    struct sockaddr_in *dst_sa, *mask_sa;
    const int sa_len = sizeof(struct sockaddr_in);
    struct in_addr dst, mask;

    /* Check & fixup dst/netmask combination first */
    dst_sa = (struct sockaddr_in *)info->rti_info[RTAX_DST];
    mask_sa = (struct sockaddr_in *)info->rti_info[RTAX_NETMASK];

    /* Ensure reads do not go beyound the buffer size */
    if (SA_SIZE(dst_sa) < offsetof(struct sockaddr_in, sin_zero))
        return (EINVAL);

    if ((mask_sa != NULL) && mask_sa->sin_len < sizeof(struct sockaddr_in)) {
        /*
         * Some older routing software encode mask length into the
         * sin_len, thus resulting in "truncated" sockaddr.
         */
        int len = mask_sa->sin_len - offsetof(struct sockaddr_in, sin_addr);
        if (len >= 0) {
            mask.s_addr = 0;
            if (len > sizeof(struct in_addr))
                len = sizeof(struct in_addr);
            memcpy(&mask, &mask_sa->sin_addr, len);
        } else {
            RTS_PID_PRINTF("prefix mask sin_len too small: %d", mask_sa->sin_len);
            return (EINVAL);
        }
    } else
        mask.s_addr = mask_sa ? mask_sa->sin_addr.s_addr : INADDR_BROADCAST;

    dst.s_addr = htonl(ntohl(dst_sa->sin_addr.s_addr) & ntohl(mask.s_addr));

    /* Construct new "clean" dst/mask sockaddresses */
    if ((dst_sa = (struct sockaddr_in *)alloc_sockaddr_aligned(lb, sa_len)) == NULL)
        return (ENOBUFS);
    fill_sockaddr_inet(dst_sa, dst);
    info->rti_info[RTAX_DST] = (struct sockaddr *)dst_sa;

    if (mask.s_addr != INADDR_BROADCAST) {
        if ((mask_sa = (struct sockaddr_in *)alloc_sockaddr_aligned(lb, sa_len)) == NULL)
            return (ENOBUFS);
        fill_sockaddr_inet(mask_sa, mask);
            RTS_PID_PRINTF("prefix mask sin_len too small: %d", mask_sa->sin_len);
            return (EINVAL);
        }
    } else
        mask.s_addr = mask_sa ? mask_sa->sin_addr.s_addr : INADDR_BROADCAST;

    dst.s_addr = htonl(ntohl(dst_sa->sin_addr.s_addr) & ntohl(mask.s_addr));

    /* Construct new "clean" dst/mask sockaddresses */
    return (0);
}
#endif


#ifdef INET
static int
cleanup_xaddrs_inet(struct rt_addrinfo *info, struct linear_buffer *lb)
{
    struct sockaddr_in *dst_sa, *mask_sa;
    const int sa_len = sizeof(struct sockaddr_in);
    struct in_addr dst, mask;

    /* Check & fixup dst/netmask combination first */
    dst_sa = (struct sockaddr_in *)info->rti_info[RTAX_DST];
    mask_sa = (struct sockaddr_in *)info->rti_info[RTAX_NETMASK];

    /* Ensure reads do not go beyound the buffer size */
    if (SA_SIZE(dst_sa) < offsetof(struct sockaddr_in, sin_zero))
        return (EINVAL);

    if ((mask_sa != NULL) && mask_sa->sin_len < sizeof(struct sockaddr_in)) {
        /*
         * Some older routing software encode mask length into the
         * sin_len, thus resulting in "truncated" sockaddr.
         */
        int len = mask_sa->sin_len - offsetof(struct sockaddr_in, sin_addr);
        if (len >= 0) {
            mask.s_addr = 0;
            if (len > sizeof(struct in_addr))
                len = sizeof(struct in_addr);
            memcpy(&mask, &mask_sa->sin_addr, len);
        } else {
            RTS_PID_PRINTF("prefix mask sin_len too small: %d", mask_sa->sin_len);
    if (info->rti_info[RTAX_GATEWAY] != NULL)
        return (cleanup_xaddrs_gateway(info, lb));

    return (0);
}
#endif

static int
cleanup_xaddrs(struct rt_addrinfo *info, struct linear_buffer *lb)
{
    int error = EAFNOSUPPORT;

    if (info->rti_info[RTAX_DST] == NULL)
        return (EINVAL);

    if (info->rti_flags & RTF_LLDATA) {
        /*
         * arp(8)/ndp(8) sends RTA_NETMASK for the associated
         * prefix along with the actual address in RTA_DST.
         * Remove netmask to avoid unnecessary address masking.
         */
        remove_netmask(info);
    }

    switch (info->rti_info[RTAX_DST]->sa_family) {
#ifdef INET
    case AF_INET:
        error = cleanup_xaddrs_inet(info, lb);
        break;
#endif
#ifdef INET6
    case AF_INET6:
        error = cleanup_xaddrs_inet6(info, lb);
        break;
#endif
    }

    return (error);
}
