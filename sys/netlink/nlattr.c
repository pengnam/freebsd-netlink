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

#include <net/netlink.h>

#define D(format, ...)                                                        \
	do {                                                                  \
		printf("%-10s " format "\n", __FUNCTION__, ##__VA_ARGS__);    \
	} while (0)
int
nla_type(const struct nlattr *nla)
{
	return nla->nla_type;
}
static int
nla_len(const struct nlattr *nla)
{
	return nla->nla_len;
}
void *
nla_data(struct nlattr *nla)
{
	return (char *)nla + NLA_HDRLEN;
}
/**
 * Check if netlink attribute fits into remaining bytes
 */
int
nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= (int)sizeof(*nla) && nla->nla_len >= sizeof(*nla) &&
	    nla->nla_len <= remaining;
}

struct nlattr *
nla_next(struct nlattr *nla, int *remaining)
{
	unsigned int totlen = NLA_ALIGN(nla->nla_len);

	*remaining -= totlen;
	return (struct nlattr *)((char *)nla + totlen);
}

static int
nla_validate(struct nlattr *nla, int maxtype, struct nla_policy *policy,
    unsigned int depth)
{
	const struct nla_policy *pt;
	int attribute_type, attribute_length, minlen, error;

	if (depth >= MAX_POLICY_RECURSION_DEPTH) {
		return EINVAL;
	}

	attribute_type = nla_type(nla);
	attribute_length = nla_len(nla);
	// TODO: Both use types which are confusing :(
	if (attribute_type < 0 || attribute_type > maxtype) {
		return 0;
	}
	pt = &policy[attribute_type];
	KASSERT(pt < NLA_TYPE_MAX, "type value not in range");

	// Match datatypes with exact length
	if (nla_attr_len[pt->type] &&
	    attribute_length != nla_attr_len[pt->type]) {
		// NOTE: In linux, warning is returned
		return EINVAL;
	}
	// There are some policy types that do not immediately follow the
	// attribute_length >= pt->len rule
	switch (pt->type) {

	case NLA_REJECT:
		// Reject all attributes with the tag
		return EINVAL;
	case NLA_FLAG:
		// Should not have any data
		if (attribute_length > 0)
			return ERANGE;
		break;
	case NLA_STRING:
		if (pt->len) {
			// get data
			if (attribute_length < 1) {
				return ERANGE;
			}
			char *buf = nla_data(nla);

			if (buf[attribute_length - 1] == '\0')
				attribute_length--;

			if (attribute_length > pt->len)
				return ERANGE;
		}
		break;
	case NLA_NESTED:
		if (attribute_length == 0)
			break;
		if (attribute_length < NLA_HDRLEN)
			return ERANGE;
		if (pt->nested_policy) {
			error = nla_validate(nla_data(nla), maxtype,
			    pt->nested_policy, depth + 1);
			if (error) {
				return error;
			}
		}
		break;

	default:
		// Refer to policy minimum length, else use pre-defined minimum
		// length
		if (pt->len)
			minlen = pt->len;
		else
			minlen = nla_attr_minlen[pt->type];

		if (attribute_length < minlen)
			return ERANGE;
	}
	// TODO: Further validation
	return 0;
}

static int
nla_validate_parse(struct nlattr *head, int maxtype, int len,
    struct nla_policy *policy, struct nlattr **tb, unsigned int depth)
{
	int error;
	uint16_t type;
	struct nlattr *nla;
	int rem;

	if (depth >= MAX_POLICY_RECURSION_DEPTH) {
		// Max recursion depth exceeded
		return EINVAL;
	}

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));
	nla_for_each_attribute(nla, head, len, rem)
	{
		type = nla_type(nla);
		if (type > maxtype) {
			return EINVAL;
		}
		if (policy) {
			error = nla_validate(nla, maxtype, policy, depth);
			if (error < 0)
				return error;
		}

		tb[type] = (struct nlattr *)nla;
	}
	return 0;
}

int
nla_put(struct mbuf *m, int attrtype, int attrlen, const void *data)
{
	struct nlattr *nla;
	size_t totlen = NLMSG_ALIGN(NLA_HDRLEN) + NLMSG_ALIGN(attrlen);
	struct nlmsghdr *hdr = mtod(m, struct nlmsghdr *);

	// TODO: Check size limit or change to append
	if (m->m_pkthdr.len < NLMSG_HDRLEN) {
		return ENOBUFS;
	}
	nla = (struct nlattr *)(nl_data_end_ptr(m));
	nla->nla_len = totlen;
	nla->nla_type = attrtype;
	if (attrlen > 0) {
		bcopy(data,
		    (unsigned char *)nl_data_end_ptr(m) +
			NLMSG_ALIGN(NLA_HDRLEN),
		    attrlen);
	}
	// TODO: check sizes
	m->m_pkthdr.len += totlen;
	m->m_len += totlen;
	D("type: %d  len: %d", nla->nla_type, m->m_len);
	hdr->nlmsg_len += totlen;

	return 0;
}

struct nlattr *
nla_nest_start(struct mbuf *m, int attrtype)
{
	struct nlattr *nla = (struct nlattr *)nl_data_end_ptr(m);
	if (nla_put(m, attrtype, 0, NULL) > 0) {
		return NULL;
	}
	return nla;
}

int
nla_nest_end(struct mbuf *m, struct nlattr *nla)
{
	nla->nla_len = (unsigned char *)nl_data_end_ptr(m) -
	    (unsigned char *)nla;
	return nla->nla_len;
}

int
nla_put_u8(struct mbuf *m, int attrtype, uint8_t value)
{
	return nla_put(m, attrtype, sizeof(uint8_t), &value);
}

int
nla_put_u16(struct mbuf *m, int attrtype, uint16_t value)
{
	return nla_put(m, attrtype, sizeof(uint16_t), &value);
}

int
nla_put_u32(struct mbuf *m, int attrtype, uint32_t value)
{
	return nla_put(m, attrtype, sizeof(uint32_t), &value);
}

int
nla_put_u64(struct mbuf *m, int attrtype, uint64_t value)
{
	return nla_put(m, attrtype, sizeof(uint64_t), &value);
}

int
nla_put_s8(struct mbuf *m, int attrtype, int8_t value)
{
	return nla_put(m, attrtype, sizeof(int8_t), &value);
}

int
nla_put_s16(struct mbuf *m, int attrtype, int16_t value)
{
	return nla_put(m, attrtype, sizeof(int16_t), &value);
}

int
nla_put_s32(struct mbuf *m, int attrtype, int32_t value)
{
	return nla_put(m, attrtype, sizeof(int32_t), &value);
}

int
nla_put_s64(struct mbuf *m, int attrtype, int64_t value)
{
	return nla_put(m, attrtype, sizeof(int64_t), &value);
}
int
nla_put_flag(struct mbuf *m, int attrtype)
{
	return nla_put(m, attrtype, 0, NULL);
}

int
nla_put_string(struct mbuf *m, int attrtype, const char *str)
{
	return nla_put(m, attrtype, strlen(str) + 1, str);
}
