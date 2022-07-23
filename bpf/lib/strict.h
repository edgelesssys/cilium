/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __WIREGUARD_H_
#define __WIREGUARD_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "common.h"
#include "dbg.h"
#include "overloadable.h"

static __always_inline int
dst_IP_and_src_IP_in_strict_mode_CIDR(struct __ctx_buff *ctx)
{
    __u8 __maybe_unused found = 0;
    if (ctx->sk)
    {
        found |= ipv4_is_in_subnet(ctx->sk->dst_ip4, STRICT_IPV4_NET, STRICT_IPV4_NET_SIZE);
        found &= ipv4_is_in_subnet(ctx->sk->src_ip4, STRICT_IPV4_NET, STRICT_IPV4_NET_SIZE);
    }

    return found;
}

#endif /* __WIREGUARD_H_ */
