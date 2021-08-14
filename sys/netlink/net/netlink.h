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
#ifndef _NET_NETLINK_H
#define _NET_NETLINK_H

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/rwlock.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/vnet.h>
#include <net/raw_cb.h>
#include <sys/types.h>
#include <sys/systm.h>

#include <linux/netlink.h>


/* Modified from: https://elixir.bootlin.com/linux/latest/source/include/net/netlink.h
 * ========================================================================
 *         Netlink Messages and Attributes Interface 
 * ------------------------------------------------------------------------
 *                          Messages Interface
 * ------------------------------------------------------------------------
 *
 * Message Format:
 *    <--- nlmsg_total_size(payload)  --->
 *    <-- nlmsg_msg_size(payload) ->
 *   +----------+- - -+-------------+- - -+-------- - -
 *   | nlmsghdr | Pad |   Payload   | Pad | nlmsghdr
 *   +----------+- - -+-------------+- - -+-------- - -
 *   nlmsg_data(nlh)---^            ^
 *   nl_data_end_ptr(m)-------------+
 *   ^------nl_nlmsghdr(m)       
 *   <-nl_message_length(offset, m)-> 
 * Payload Format:
 *    <---------------------- nlmsg_len(nlh) --------------------->
 *    <------ hdrlen ------>       <- nlmsg_attrlen(nlh, hdrlen) ->
 *   +----------------------+- - -+--------------------------------+
 *   |     Family Header    | Pad |           Attributes           |
 *   +----------------------+- - -+--------------------------------+
 *   nlmsg_attrdata(nlh, hdrlen)---^
 */
/*
 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |   (struct nlattr)   | ing |                   | ing |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <-------------- nlattr->nla_len -------------->
 */

//TODO: Change to max netlink number
#define NL_MAX_HANDLERS 100
typedef int (*nl_handler)(void *data, struct socket *so);

int 
nl_register_or_replace_handler(int proto, nl_handler handle);

/*---- nlmsg helpers ----*/
static inline int
nlmsg_msg_size(int payload) {
	return NLMSG_HDRLEN + payload;
}

static inline int
nlmsg_aligned_msg_size(int payload) {
	return NLMSG_ALIGN(nlmsg_msg_size(payload));
}
static inline void *
nlmsg_data(struct nlmsghdr *nlh)
{
	return (unsigned char *) nlh + NLMSG_HDRLEN;
}


static inline int
nlmsg_len(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len - NLMSG_HDRLEN;
}

void *
nl_data_end_ptr(struct mbuf * m);

static inline struct mbuf *
nlmsg_new(int payload, int flags)
{
	int size = nlmsg_aligned_msg_size(payload);
	struct mbuf * m = m_getm(NULL, size, flags, MT_DATA);
	//flags specify M_WAITOK or M_WAITNOTOK
	bzero(mtod(m, caddr_t), size);
	return m;
}

static inline int
nlmsg_end(struct mbuf *m, struct nlmsghdr *nlh) {
	nlh->nlmsg_len = (char*)nl_data_end_ptr(m) - (char*) nlh;
	printf("nlmsg_len at end: %d\n", nlh->nlmsg_len);
	return nlh->nlmsg_len;
}



/*TODO: Put inline back*/

// Places fields in nlmsghdr at the start of buffer 
static struct nlmsghdr *
nlmsg_put(struct mbuf* m, int portid, int seq, int type, int payload, int flags)
{
	struct nlmsghdr *nlh;
	int size = nlmsg_msg_size(payload);
	nlh = mtod(m, struct nlmsghdr *);
	if (nlh == NULL) {
		printf("Error at mtod");
		return NULL;
	}
	nlh->nlmsg_type = type;
	nlh->nlmsg_len = size;
	nlh->nlmsg_pid = portid;
	nlh->nlmsg_seq = seq;
	
	m->m_len += NLMSG_ALIGN(size);
	m->m_pkthdr.len += NLMSG_ALIGN(size);

	if (NLMSG_ALIGN(size) - size != 0)
		memset((char*)nlmsg_data(nlh) + payload, 0, NLMSG_ALIGN(size) - size);
	return nlh;
}




/*---- end nlmsg helpers ----*/
struct nlpcb {
	struct rawcb rp; /*rawcb*/
	uint32_t			portid;
	uint32_t			dst_portid;
	uint32_t			dst_group;
	uint32_t			flags;
};
#define sotonlpcb(so)       ((struct nlpcb *)(so)->so_pcb)

#define _M_NLPROTO(m)  ((m)->m_pkthdr.rsstype)  /* netlink proto, 8 bit */
#define NETISR_NETLINK  15  // XXX hack, must be unused and < 16

 /**
  * Standard attribute types to specify validation policy
  */
enum {
	NLA_UNSPEC,
	NLA_U8,
	NLA_U16,
	NLA_U32,
	NLA_U64,
	NLA_S8,
	NLA_S16,
	NLA_S32,
	NLA_S64,
	NLA_STRING,
	NLA_FLAG,
	NLA_REJECT,
	NLA_NESTED,
	NLA_NESTED_ARRAY,
	NLA_NUL_STRING,
	__NLA_TYPE_MAX,
};
#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)
struct nla_policy {
    uint16_t        type;
    uint16_t        len;
    struct nla_policy *nested_policy;

};

static const uint8_t nla_attr_len[NLA_TYPE_MAX+1] = {
	[NLA_U8]	= sizeof(uint8_t),
	[NLA_U16]	= sizeof(uint16_t),
	[NLA_U32]	= sizeof(uint32_t),
	[NLA_U64]	= sizeof(uint64_t),
	[NLA_S8]	= sizeof(int8_t),
	[NLA_S16]	= sizeof(int16_t),
	[NLA_S32]	= sizeof(int32_t),
	[NLA_S64]	= sizeof(int64_t),
};

static const uint8_t nla_attr_minlen[NLA_TYPE_MAX+1] = {
	[NLA_U8]	= sizeof(uint8_t),
	[NLA_U16]	= sizeof(uint16_t),
	[NLA_U32]	= sizeof(uint32_t),
	[NLA_U64]	= sizeof(uint64_t),
	//[NLA_MSECS]	= sizeof(uint64_t),
	[NLA_S8]	= sizeof(int8_t),
	[NLA_S16]	= sizeof(int16_t),
	[NLA_S32]	= sizeof(int32_t),
	[NLA_S64]	= sizeof(int64_t),
};



int nla_ok(const struct nlattr *nla, int remaining);
struct nlattr *nla_next(struct nlattr *nla, int *remaining);
int nla_type(const struct nlattr *nla);
void *nla_data(struct nlattr *nla);

/**
 * nla_for_each_attr - iterate over a stream of attributes
 * @pos: loop counter, set to current attribute
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_attribute(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nla_ok(pos, rem); \
	     pos = nla_next(pos, &(rem)))

/**
 * nla_for_each_nested - iterate over nested attributes
 * @pos: loop counter, set to current attribute
 * @nla: attribute containing the nested attributes
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define nla_for_each_nested(pos, nla, rem) \
	nla_for_each_attr(pos, nla_data(nla), nla_len(nla), rem)


#define MAX_POLICY_RECURSION_DEPTH 10

	int nl_send_msg(struct mbuf *m);
int
nla_put_u8(struct mbuf *m, int attrtype, uint8_t value);

int
nla_put_u16(struct mbuf *m, int attrtype, uint16_t value);

int
nla_put_u32(struct mbuf *m, int attrtype, uint32_t value);

int
nla_put_u64(struct mbuf *m, int attrtype, uint64_t value);

int
nla_put_s8(struct mbuf *m, int attrtype, int8_t value);

int
nla_put_s16(struct mbuf *m, int attrtype, int16_t value);
int
nla_put_s32(struct mbuf *m, int attrtype, int32_t value);
int
nla_put_s64(struct mbuf *m, int attrtype, int64_t value);
int
nla_put_flag(struct mbuf *m, int attrtype);
int
nla_put_string(struct mbuf *m, int attrtype, const char *str);

int
nla_put(struct mbuf *m, int attrtype, int attrlen, const void *data);

struct nlattr*
nla_nest_start(struct mbuf *m, int attrtype);

int
nla_nest_end(struct mbuf *m, struct nlattr *nla);

#endif
