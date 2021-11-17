#ifndef SCION_UTILS_H
#define SCION_UTILS_H

#include "scion.h"
#include <stdio.h>
#include <stdlib.h>

// Writes the pathmeta header into the 32bit buffer, ignoring extra fields like num_hf etc
static inline void path_meta_hdr_to_raw(struct scion_path_meta_hdr* path_meta_header, __u32* raw) {
    *raw = htobe32(((__u32)path_meta_header->cur_inf) <<30 | ((__u32)(path_meta_header->cur_hf & 0x3F))<<24);
    *raw |= htobe32(((__u32)path_meta_header->seg_0_len&0x3F) << 12);
	*raw |= htobe32(((__u32)path_meta_header->seg_1_len&0x3F) << 6);
    *raw |= htobe32(((__u32)path_meta_header->seg_2_len&0x3F));
}

// Reads the pathmeta header from a raw representation in the packet
static inline struct scion_path_meta_hdr* path_meta_hdr_from_raw(__u32 raw) {
    struct scion_path_meta_hdr* pmh = (struct scion_path_meta_hdr*)malloc(sizeof(struct scion_path_meta_hdr));
    pmh->cur_inf = (__u8)(raw >> 30);
	pmh->cur_hf = (__u8)(raw>>24) & 0x3F;
	pmh->seg_0_len = (__u8)(raw>>12) & 0x3F;
	pmh->seg_1_len = (__u8)(raw>>6) & 0x3F;
	pmh->seg_2_len = (__u8)(raw) & 0x3F;

    pmh->num_hf = 0;
    pmh->num_inf = 0;
    if(pmh->seg_0_len > 0) {
        pmh->num_inf += 1;
        pmh->num_hf += pmh->seg_0_len;
    }
    if(pmh->seg_1_len > 0) {
        pmh->num_inf += 1;
        pmh->num_hf += pmh->seg_1_len;
    }
    if(pmh->seg_2_len > 0) {
        pmh->num_inf += 1;
        pmh->num_hf += pmh->seg_2_len;
    }
    return pmh;
}

// Gets the info field at the given index
static inline struct scion_info_field* get_inf_field(void* data, __u8 index) {
    // offset: 4𝐵+8𝐵⋅CurrINF
    void* new_off = (void*)(((char*)data) + 4 + 8 * index);
    return (struct scion_info_field*)new_off;
}

// Gets the hop field at the given index
static inline struct scion_hop_field* get_hop_field(void* data, __u8 num_inf, __u8 hf_index) {
    // offset: 4𝐵+8𝐵⋅NumINF+12𝐵⋅CurrHF
    void* new_off = (void*)(((char*)data) + 4 + 8 * num_inf + 12 * hf_index);
    return (struct scion_hop_field*)(new_off);
}

// Gets the inf index (seg0|seg1|seg2) for the given hop field
static inline __u8 inf_index_for_hf(struct scion_path_meta_hdr *scion_path_meta, __u8 hf) {
    __u8 left = 0;
    __u8 i = 0;
	for (i = 0; i < scion_path_meta->num_inf; i++) {
        __u8 seglen = scion_path_meta->seg_0_len;
        if (i == 1) {
            seglen = scion_path_meta->seg_1_len;
        }
        if (i == 2) {
            seglen = scion_path_meta->seg_2_len;
        }

		if (hf >= left) {
			if (hf < left+seglen) {
				return i;
			}
		}
		left += seglen;
	}
	// at the end we just return the last index.
	return scion_path_meta->num_inf - 1;
}

// Cheks if we have a transition between segments in the current hop field
static inline int is_xover(struct scion_path_meta_hdr* scion_path_meta) {
    return scion_path_meta->cur_inf != inf_index_for_hf(scion_path_meta, scion_path_meta->cur_hf + 1);
}

// Fetches the egress interface ip by the given ergress_id
static inline __u32 egr_intf_ip_by_id(struct scion_br_info* br_info, __u16 egr_int_id) {
    __u16 i = 0;
    for (i = 0; i < br_info->num_links; i++) {
        if (*(br_info->link_egr_ids + i) == egr_int_id) {
            return *(br_info->link_egr_ips + i);
        }
    }

    return 0;
}

#endif // SCION_UTILS_H 