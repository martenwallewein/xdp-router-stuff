#ifndef SCION_DEBUG_H
#define SCION_DEBUG_H

#include "scion.h"
#include "scion_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_ip(char** target, __u32 ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    asprintf(target, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);        
}

void print_AS(char** target, __u64 as)
{
    __u16 parts[3];
    parts[0] = (as >> 0) & 0xFFFF;
    parts[1] = (as >> 16) & 0xFFFF;
    parts[2] = (as >> 32) & 0xFFFF;
    asprintf(target, "%x:%x:%x", be16toh(parts[0]), be16toh(parts[1]), be16toh(parts[2]));        
}


static inline void print_inf(struct scion_info_field* cur_inf_field) {
    printf("IF: SegId: %u, consDir: %u\n", be16toh(cur_inf_field->seg_id), cur_inf_field->constr_dir);
}

static inline void print_hf(struct scion_hop_field* cur_hop_field) {
    printf("HF: MAC: %lu, Ingress: %u, Egress: %u\n", be64toh(cur_hop_field->mac), be16toh(cur_hop_field->cons_ingr_interface), be16toh(cur_hop_field->cons_egr_interface)); 
    __u8 parts[6];
    __u64* mac = get_fixed_mac(cur_hop_field);
    parts[0] = ((*mac) >> 0) & 0xFF;
    parts[1] = ((*mac) >> 8) & 0xFF;
    parts[2] = ((*mac) >> 16) & 0xFF;
    parts[3] = ((*mac) >> 24) & 0xFF;
    parts[4] = ((*mac) >> 32) & 0xFF;
    parts[5] = ((*mac) >> 40) & 0xFF;
    // __u8* macParts = (__u8*)(cur_hop_field->mac);
    printf("MAC in detail: %u, %u, %u, %u, %u, %u\n", parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
}


static inline void print_packet_info(
    const struct scion_hdr *scion_h,
    const struct scion_addr_hdr_v4 *scion_v4_h,
    struct scion_path_meta_hdr *scion_path_meta
    ) {
    char *dstAS;
    char *srcAS;
    char *dstIP;
    char *srcIP;
    
    // int64ToChar(dstAS, scion_v4_h->dst_ia);
    print_ip(&dstIP, scion_v4_h->dst_host_addr);
    print_ip(&srcIP, scion_v4_h->src_host_addr);
    print_AS(&srcAS, scion_v4_h->src_ia);
    print_AS(&dstAS, scion_v4_h->dst_ia);

    // 00 000000 000000 000101 010010 000101
    printf("----------- BEGIN SCION Packet --------- \n");
    printf("Common Header \n \tNextHdr: %u, HdrLen %u, PayloadLen %u, PathType %u, DT %u, Dl %u, ST %u, Sl %u\n", scion_h->next_hdr, scion_h->hdr_len, be16toh(scion_h->payload_len), scion_h->path_type, scion_h->dt, be16toh(scion_h->dl), scion_h->st, scion_h->sl);
    printf("Address Header \n \tDstIds: %u, DstAS: %s, SrcISD %u, SrcAS: %s, DstHostAddr: %s, SrcHostAddr: %s\n", be16toh(scion_v4_h->dst_isd), dstAS, be16toh(scion_v4_h->src_isd), srcAS, dstIP, srcIP);
    printf("Path meta \n \tCurrInf: %u, CurrHF: %u, NumInf: %u, NumHf %u, Seg0Len: %u, Seg1Len: %u, Seg2Len: %u\n", scion_path_meta->cur_inf, scion_path_meta->cur_hf, scion_path_meta->num_inf, scion_path_meta->num_hf, scion_path_meta->seg_0_len, scion_path_meta->seg_1_len, scion_path_meta->seg_2_len); 
    printf("INF fields:\n");
    __u8 i = 0;
    __u32* path_meta_start = (__u32*)(scion_v4_h + 1);
    for (i = 0; i < scion_path_meta->num_inf; i++) {
        printf("\t");
        print_inf(get_inf_field(((void*)path_meta_start), i));
    }

    printf("HOP fields:\n");
    for (i = 0; i < scion_path_meta->num_hf; i++) {
        printf("\t");
        print_hf(get_hop_field(((void*)path_meta_start), scion_path_meta->num_inf, i));
    }
    printf("----------- END SCION Packet --------- \n");

    free(dstAS);
    free(srcAS);
    free(dstIP);
    free(srcIP);
}


#endif // SCION_DEBUG_H
