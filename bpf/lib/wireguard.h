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
firewall_check(struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u16 proto = 0;
    __u64 length = 0, offset = 0;
    // __u32 result;
    // __u8 l7_byte_1, l7_byte_2;
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
#ifdef ENABLE_IPV6
    case bpf_htons(ETH_P_IPV6):
        if (!revalidate_data(ctx, &data, &data_end, &ip6))
            return true;
        switch (ip6->nexthdr)
        {
        case IPPROTO_TCP:
            break;
        case IPPROTO_ICMP:
            return true;
        case IPPROTO_ICMPV6:
            return true;
        default:
            return false;
        }
        length = bpf_htons(ip6->payload_len) - sizeof(struct ipv6hdr);
        offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        break;
#endif
#ifdef ENABLE_IPV4
    case bpf_htons(ETH_P_IP):
        if (!revalidate_data(ctx, &data, &data_end, &ip4))
            return true;
        switch (ip4->protocol)
        {
        case IPPROTO_TCP:
            break;
        case IPPROTO_ICMP:
            return true;
        case IPPROTO_ICMPV6:
            return true;
        default:
            return false;
        }
        length = bpf_htons(ip4->tot_len) - sizeof(struct iphdr);
        offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
        break;
#endif
    default:
        return true;
    }

    if ((data + offset + sizeof(struct tcphdr)) > data_end)
        return true;

    tcph = (struct tcphdr *)(data + offset);
    offset += (tcph->doff << 2);
    length -= (tcph->doff << 2);
    // l4 layer packages are allowed
    if (length == 0)
        return true;

    // Port 4240:  cilium health check
    // Port 4000:  debugd 
    // Port 30090: Constellation activation server
    // Port 6443:  Kubernetes 'kubeadm join'
    // Port 10250  cilium health check
    if (tcph->source == bpf_htons(4240) || tcph->dest == bpf_htons(4240) ||
        tcph->source == bpf_htons(4000) ||
        tcph->source == bpf_htons(30090) ||
        tcph->source == bpf_htons(6443) || tcph->dest == bpf_htons(6443) ||
        tcph->source == bpf_htons(10250) || tcph->dest == bpf_htons(10250))
    {
        return true;
    }

#ifdef DEBUG
    printk("tcp length %llx, dest %d, source %d", length, bpf_htons(tcph->dest), bpf_htons(tcph->source));
#endif

    return false;
}

static __always_inline int
dst_IP_in_strict_mode_CIDR(struct __ctx_buff *ctx)
{
    __u8 __maybe_unused found = 0;
    if (ctx->sk)
    {
#if IPV4_COUNT > 0
        found |= ipv4_is_in_subnet(ctx->sk->dst_ip4, IPV4_NET_0, IPV4_NET_0_SIZE);
#endif
#if IPV4_COUNT > 1
        found |= ipv4_is_in_subnet(ctx->sk->dst_ip4, IPV4_NET_1, IPV4_NET_1_SIZE);
#endif
    }

    return found;
}

#endif /* __WIREGUARD_H_ */
