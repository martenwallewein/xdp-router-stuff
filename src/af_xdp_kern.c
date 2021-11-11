/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <bpf/bpf_helpers.h>
#include "scion.h"


#define TARGET_PORT 31041

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

struct bpf_map_def SEC("maps") listen_ports = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 64,
        .map_flags = 0,
};


struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(__u32),
	.max_entries = 64,
};

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ensure ETHERNET
    struct ether_header *eth = data;
    if ((void*)eth + sizeof(*eth) <= data_end && eth->ether_type == _htons(ETHERTYPE_IP)) {
        // Ensure IP
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) {
            // Ensure UDP
            if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void*)ip + sizeof(*ip);
                int *port_found = bpf_map_lookup_elem(&listen_ports, &udp->dest);
                if ( port_found && *port_found == 1 && (void*)udp + sizeof(*udp) <= data_end &&  udp->dest == _htons(TARGET_PORT)) {
                    // We got it, check for queue and socket
                    int index = ctx->rx_queue_index;
                    // This map is unused, so we can ignore it for now
                    /*__u32 *pkt_count;
                    pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
                    if (pkt_count) {

                        if ((*pkt_count)++ & 1)
                            return XDP_PASS;
                    }*/
                    // Ensure SCION and SCION nextheader udp
                    const struct scion_hdr *scion_h = (const struct scion_hdr *)(udp + 1);
                    // We forward only nextheader == UDP && pathType SCION
                    if(scion_h->next_hdr == IPPROTO_UDP && (scion_h->path_type == (__u8)_htons(1))) {
                        /* A set entry here means that the correspnding queue_id
                        * has an active AF_XDP socket bound to it. */
                        if (bpf_map_lookup_elem(&xsks_map, &index))
                            return bpf_redirect_map(&xsks_map, index, 0);
                    }

                    
                }
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";