/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <bpf/bpf_helpers.h>

#if BYTE_ORDER == BIG_ENDIAN

#define HTONS(n) (n)
#define NTOHS(n) (n)
#define HTONL(n) (n)
#define NTOHL(n) (n)

#else

#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))
#endif

#define _htons(n) HTONS(n)
#define _ntohs(n) NTOHS(n)

#define _htonl(n) HTONL(n)
#define _ntohl(n) NTOHL(n)

#define TARGET_PORT 31041

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
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
                if ((void*)udp + sizeof(*udp) <= data_end &&  udp->dest == _htons(TARGET_PORT)) {
                    // We got it, check for queue and socket
                    int index = ctx->rx_queue_index;
                    // This map is unused, so we can ignore it for now
                    /*__u32 *pkt_count;
                    pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
                    if (pkt_count) {

                        if ((*pkt_count)++ & 1)
                            return XDP_PASS;
                    }*/

                    /* A set entry here means that the correspnding queue_id
                    * has an active AF_XDP socket bound to it. */
                    if (bpf_map_lookup_elem(&xsks_map, &index))
                        return bpf_redirect_map(&xsks_map, index, 0);
                }
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";