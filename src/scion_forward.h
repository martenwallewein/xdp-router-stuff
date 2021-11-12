#include "scion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SCION_FORWARD_IGNORE 0
#define SCION_FORWARD_SUCCESS 1

void int64ToChar(char a[], __u64 n) {
  memcpy(a, &n, 8);
}

void print_ip(__u32 ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

void print_AS(__u64 as)
{
    __u16 parts[3];
    parts[0] = (as >> 0) & 0xFFFF;
    parts[1] = (as >> 16) & 0xFFFF;
    parts[2] = (as >> 32) & 0xFFFF;
    printf("%x:%x:%x\n", _ntohs(parts[0]), _ntohs(parts[1]), _ntohs(parts[2]));        
}

static inline void print_packet_info(
    const struct scion_hdr *scion_h,
    const struct scion_addr_hdr_v4 *scion_v4_h,
    const struct scion_path_meta_hdr *scion_path_meta
    ) {
    char* dstAS = (char*)malloc(sizeof(__u64));
    int64ToChar(dstAS, scion_v4_h->dst_ia);
    print_ip(scion_v4_h->dst_host_addr);
    print_ip(scion_v4_h->src_host_addr);
    print_AS(scion_v4_h->src_ia);
    print_AS(scion_v4_h->dst_ia);
    
    printf("----------- BEGIN SCION Packet --------- \n");
    printf("Common Header \n NextHdr: %u, HdrLen %u, PayloadLen %u, PathType %u, DT %u, Dl %u, ST %u, Sl %u\n", scion_h->next_hdr, scion_h->hdr_len, _ntohs(scion_h->payload_len), scion_h->path_type, scion_h->dt, _ntohs(scion_h->dl), scion_h->st, scion_h->sl);
    printf("Address Header \n DstIds: %u, DstAS: %s, SrcISD %u, SrcAS: %llu, DstHostAddr: %pI4, SrcHostAddr: %pI4\n", _ntohs(scion_v4_h->dst_isd), dstAS, scion_v4_h->src_isd, scion_v4_h->src_ia, scion_v4_h->dst_host_addr, scion_v4_h->src_host_addr);
    printf("Path meta \n CurrInf: %u, CurrHF: %u, Seg0Len: %u, Seg1Len: %u, Seg2Len: %u\n", scion_path_meta->cur_inf, scion_path_meta->cur_hf, scion_path_meta->seg_0_len, scion_path_meta->seg_1_len, scion_path_meta->seg_2_len); 
    printf("----------- END SCION Packet --------- \n");
}

static inline int handle_forward(void* data) {
    // We got the stripped version of the packet starting with the SCION header here
    // This simplifies things because we can test this function within a normal udp socket
    // implementation. 
    const struct scion_hdr *scion_h = (const struct scion_hdr *)(data);

    // Things we already know:
    // - It's definetly a SCION packet
    // - SCION path_type matches, next_hdr is set to UDP
    // - The packet arrived at a configured port for one of the interfaces in the topology

    // Parse addr header, lets limit it to IPv4 at the moment (since the ebpf code also supports only v4 now)
    if (scion_h->dl != (__u8)_htons(4) || scion_h->sl != (__u8)_htons(4)) {
        return SCION_FORWARD_IGNORE;
    }

    const struct scion_addr_hdr_v4 *scion_v4_h = (const struct scion_addr_hdr_v4 *)(scion_h + 1);
    // TODO: Check local and remote AS/ISD, handle error if this does not match

    // Get the path meta information
     const struct scion_path_meta_hdr *scion_path_meta = (const struct scion_path_meta_hdr *)(scion_v4_h + 1);

    print_packet_info(scion_h, scion_v4_h, scion_path_meta);
    
    return 0;
}