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
#ifndef _NET_GENETLINK_H
#define _NET_GENETLINK_H

#include <linux/genetlink.h>
#include <net/netlink.h>

#define GENLMSG_DEFAULT_SIZE (NLMSG_DEFAULT_SIZE - GENL_HDRLEN)


struct genl_ops;
struct genl_info;
struct netlink_callback;

struct genl_family {
	LIST_ENTRY(genl_family)  next;
	unsigned int		id;/* private*/
	unsigned int		hdrsize;
	char			name[GENL_NAMSIZ];
	unsigned int            version;
	unsigned int		maxattr;
	const struct nla_policy *policy;
	struct genl_ops *	ops;
	unsigned int		n_ops;
};

struct genl_info {
	uint32_t			snd_seq;
	uint32_t			snd_portid;
	struct nlmsghdr *	nlhdr;
	struct genlmsghdr *	genlhdr;
	void *			userhdr;
	struct nlattr **	attrs;
};



struct genl_ops {
	int		       (*doit)(struct mbuf *m,
				       struct genl_info *info);
	int		       (*start)(struct netlink_callback *cb);
	int		       (*dumpit)(struct mbuf *m,
					 struct netlink_callback *cb);
	int		       (*done)(struct netlink_callback *cb);
	const struct nla_policy *policy;
	unsigned int		maxattr;
	uint8_t			cmd;
	uint8_t			internal_flags;
	uint8_t			flags;
	uint8_t			validate;
};


struct netlink_callback {
	struct mbuf          *m; /* linux calls this this way */
	const struct nlmsghdr   *nlh;
	long                    args[6];
};



int genl_register_family(struct genl_family *family);
int genl_unregister_family(const struct genl_family *family);

void *genlmsg_put(struct mbuf *m, uint32_t portid, uint32_t seq,
		  const struct genl_family *family, int flags, uint8_t cmd);

static inline struct nlmsghdr *genlmsg_nlhdr(void *user_hdr)
{
	return (struct nlmsghdr *)((char *)user_hdr -
				   GENL_HDRLEN -
				   NLMSG_HDRLEN);
}

static inline int genlmsg_parse(const struct nlmsghdr *nlh,
				const struct genl_family *family,
				struct nlattr *tb[], int maxtype,
				const struct nla_policy *policy)
{
	//TODO:
	return 0;
}

static inline void *genlmsg_put_reply(struct mbuf *m,
				      struct genl_info *info,
				      const struct genl_family *family,
				      int flags, uint8_t cmd)
{
	return genlmsg_put(m, info->snd_portid, info->snd_seq, family,
			   flags, cmd);
}

static inline void genlmsg_end(struct mbuf *m, void *hdr)
{
	nlmsg_end(m,  (struct nlmsghdr *)((char*)hdr - GENL_HDRLEN - NLMSG_HDRLEN));
}

static inline int genlmsg_send_msg(struct mbuf *m, uint32_t portid, uint32_t proto)
{
 	struct nlmsghdr * nlmsg = mtod(m, struct nlmsghdr *);
 	nlmsg->nlmsg_pid = portid;
 	return nl_send_msg(m, proto);
}


static inline void *genlmsg_data(struct genlmsghdr *gnlh)
{
	return ((unsigned char *) gnlh + GENL_HDRLEN);
}

static inline int genlmsg_len(struct genlmsghdr *gnlh)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)((unsigned char *)gnlh -
							NLMSG_HDRLEN);
	return (nlh->nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN);
}

static inline int genlmsg_msg_size(int payload)
{
	return GENL_HDRLEN + payload;
}

static inline int genlmsg_total_size(int payload)
{
	return NLMSG_ALIGN(genlmsg_msg_size(payload));
}

static inline struct mbuf *genlmsg_new(size_t payload, int flags)
{
	return nlmsg_new(genlmsg_total_size(payload), flags);
}

//TODO: Learn how genetlink set errors
//static inline int genl_set_err(const struct genl_family *family,
//			       struct net *net, uint32_t portid,
//			       uint32_t group, int code)
//{
//	if (WARN_ON_ONCE(group >= family->n_mcgrps))
//		return -EINVAL;
//	group = family->mcgrp_offset + group;
//	return netlink_set_err(net->genl_sock, portid, group, code);
//}


#endif /* _NET_GENETLINK_H */

