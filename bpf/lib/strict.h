/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __STRICT_H_
#define __STRICT_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "common.h"
#include "dbg.h"
#include "overloadable.h"

// strict_allow checks whether the packet is allowed to pass through the strict mode.
static __always_inline bool
strict_allow(struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u16 proto = 0;
    bool __maybe_unused in_strict_cidr = false;
#ifdef ENABLE_IPV4
    struct iphdr *ip4;
#endif
    if (!validate_ethertype(ctx, &proto))
        return true;

    switch (proto)
    {
#ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data(ctx, &data, &data_end, &ip4))
            return true;

        
        switch (ip4->protocol)
        {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            in_strict_cidr = ipv4_is_in_subnet(ip4->daddr, STRICT_IPV4_NET, STRICT_IPV4_NET_SIZE);
            in_strict_cidr &= ipv4_is_in_subnet(ip4->saddr, STRICT_IPV4_NET, STRICT_IPV4_NET_SIZE);
            return !in_strict_cidr;
        case IPPROTO_ICMP:
            return true;
        case IPPROTO_ICMPV6:
            return true;
        default:
            return false;
        }

        break;
#endif
    default:
        return true;
    }
}
#endif /* __STRICT_H_ */