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

// firewall_check checks whether the packet is whitelisted
static __always_inline bool
strict_allow(struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u16 proto = 0;
    __u64 length = 0, offset = 0;
    bool __maybe_unused in_strict_cidr = false;
    struct tcphdr *tcph;
#ifdef ENABLE_IPV6
    struct ipv6hdr *ip6;
#endif
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

        in_strict_cidr = ipv4_is_in_subnet(ip4->daddr, STRICT_IPV4_NET, STRICT_IPV4_NET_SIZE);
        in_strict_cidr &= ipv4_is_in_subnet(ip4->saddr, STRICT_IPV4_NET, STRICT_IPV4_NET_SIZE);
        
        switch (ip4->protocol)
        {
        case IPPROTO_TCP:
            if (in_strict_cidr)
            {
                length = bpf_htons(ip4->tot_len) - sizeof(struct iphdr);
                offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
                if ((data + offset + sizeof(struct tcphdr)) > data_end)
                    return !in_strict_cidr;
                tcph = (struct tcphdr *)(data + offset);
                length -= (tcph->doff << 2);

                printk("TCP TCP TCP source %pI4, dest %pI4\n", &ip4->saddr, &ip4->daddr);
                printk("tcp length %llx, source %d, dest %d\n", length, bpf_htons(tcph->source), bpf_htons(tcph->dest));
            }

            return !in_strict_cidr;
        case IPPROTO_UDP:
            if (in_strict_cidr)
            {
                printk("UDP UDP UDP source %pI4, dest %pI4\n", &ip4->saddr, &ip4->daddr);
            }
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
    return !in_strict_cidr;
}

#endif /* __WIREGUARD_H_ */
