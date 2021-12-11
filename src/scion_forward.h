#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scion.h"
#include "scion_utils.h"


//#ifdef DEBUG
// #include "./scion_debug.h"
//#endif

#define SCION_FORWARD_IGNORE 0
#define SCION_FORWARD_SUCCESS 1

#define SCION_ENDHOST_PORT 30041

struct scion_forward_result {
    __u32 dst_addr_v4;
    __u16 dst_port;
    __u8 state; // See SCION_FORWARD_*
};


// Updates current hop and info field counter
static inline void update_cur_inf_hf(struct scion_path_meta_hdr *scion_path_meta) {
    scion_path_meta->cur_inf = inf_index_for_hf(scion_path_meta, scion_path_meta->cur_hf);
    scion_path_meta->cur_hf += 1;   
}

// UpdateSegID updates the SegID field by XORing the SegID field with the 2
// first bytes of the MAC. It is the beta calculation according to
// https://scion.docs.anapaya.net/en/latest/protocols/scion-header.html#hop-field-mac-computation
// Should look like this: inf.SegID = inf.SegID ^ binary.BigEndian.Uint16(hfMac[:2])
static inline void update_seg_id(struct scion_info_field* cur_inf_field, __u64 mac) {
    __u16* fmac = (__u16*)(&mac);
    cur_inf_field->seg_id = htobe16(be16toh(cur_inf_field->seg_id) ^ (be16toh(*fmac))); // && 0xFFFF
}
 
// Checks if we are ingress router and need to update hop/inf fields
static inline int update_non_cons_dir_ingress_seg_id(
    struct scion_info_field* cur_inf_field,
    struct scion_hop_field* cur_hop_field
) {
    // against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// TODO(lukedirtwalker): For packets destined to peer links this shouldn't
	// be updated.
    if (cur_inf_field->constr_dir == 0 && be16toh(cur_hop_field->cons_ingr_interface) != 0) {
        // printf("update_non_cons_dir_ingress_seg_id\n");
        // update segId in info filed
        update_seg_id(cur_inf_field, cur_hop_field->mac);
        return 1;

    }
    return 0;
}

// Checks if we are egress router and need to update hop/inf field
static inline int update_cons_dir_egress_seg_id(
    struct scion_info_field* cur_inf_field,
    struct scion_hop_field* cur_hop_field
) {
    // against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// TODO(lukedirtwalker): For packets destined to peer links this shouldn't
	// be updated.
    if (cur_inf_field->constr_dir != 0) {
        // update segId in info filed
        __u64* mac = get_fixed_mac(cur_hop_field);
        update_seg_id(cur_inf_field, *mac);
        return 1;

    }
    return 0;
}

// Magic MAC verification
// This does not seem to set any new value, double check this...
static inline int verify_current_mac(
    struct scion_info_field* cur_inf_field,
    struct scion_hop_field* cur_hop_field,
    __u64* key,
    __u64* full_mac
) {
    // 16 bytes, AES 128
    // MACInput returns the MAC input data block with the following layout:
    //
    //    0                   1                   2                   3
    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |               0               |             SegID             |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |                           Timestamp                           |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |       0       |    ExpTime    |          ConsIngress          |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //   |          ConsEgress           |               0               |
    //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    return 1;
}


// Performs the required forwarding and verification actions for the given
// SCION payload
// Should be called in the mock router and the ebpf/XDP program
// In any case, the calling program needs to parse the result and send the packet
// to the next hop, accordingly.
static inline struct scion_forward_result* handle_forward(void* data, struct scion_br_info* br_info) {
    // We got the stripped version of the packet starting with the SCION header here
    // This simplifies things because we can test this function within a normal udp socket
    // implementation. 
    const struct scion_hdr *scion_h = (const struct scion_hdr *)(data);
    const struct scion_addr_hdr_v4 *scion_v4_h = (const struct scion_addr_hdr_v4 *)(scion_h + 1);
    struct scion_forward_result* result = malloc(sizeof(struct scion_forward_result));

    // Things we already know:
    // - It's definetly a SCION packet
    // - Local AS and ISD match
    // - SCION path_type matches, next_hdr is set to UDP
    // - The packet arrived at a configured port for one of the interfaces in the topology

    // With those information available, we can focus on the actual forwarding here
    
    // For whatever reason we can not cast the data as it is to the path_meta_struct. But this is fine
    // Since we want to add other fields for easier processing here
    __u32* path_meta_start = (__u32*)(scion_v4_h + 1);
    struct scion_path_meta_hdr *scion_path_meta = path_meta_hdr_from_raw(be32toh(*path_meta_start));
    //#ifdef DEBUG
    // print_packet_info(scion_h, scion_v4_h, scion_path_meta);
    //#endif

    // Get current INF/HF
    struct scion_info_field* cur_inf_field = get_inf_field(((void*)path_meta_start), scion_path_meta->cur_inf);
    struct scion_hop_field* cur_hop_field = get_hop_field(((void*)path_meta_start), scion_path_meta->num_inf, scion_path_meta->cur_hf);
    // print_hf(cur_hop_field);
    // int ret = 0;

    // Check if ingress and consDir
    /*ret = */update_non_cons_dir_ingress_seg_id(cur_inf_field, cur_hop_field);

    __u64* full_mac = malloc(2 * sizeof(__u64)); // 16 bytes
    /*ret = */verify_current_mac(cur_inf_field, cur_hop_field, br_info->mac_key, full_mac); // Handle result here...

    // TODO: Handle egress/ingress alerts!!
    // printf("DEBUG: dst_isd = %u, localAS: %lu\n\n",scion_v4_h->dst_isd, be64toh(scion_v4_h->dst_ia));

    // Inbound: pkts destined to the local IA.
    // TODO: We need to make sure that its not a svc address...
    if (br_info->local_isd == scion_v4_h->dst_isd && br_info->local_ia == be64toh(scion_v4_h->dst_ia)) {
        result->state = SCION_FORWARD_SUCCESS;
        result->dst_port = SCION_ENDHOST_PORT;
        result->dst_addr_v4 = be32toh(scion_v4_h->dst_host_addr);
        return result;
    }

	// Outbound: pkts leaving the local IA.
	// BRTransit: pkts leaving from the same BR different interface.
    if(is_xover(scion_path_meta)) {

        // This is interesting, in xover we go over two hop fields, incrementing the counter twice
        // I hope this is intended...
        update_cur_inf_hf(scion_path_meta);

        // Get new cur_inf_field
        cur_inf_field = get_inf_field(((void*)path_meta_start), scion_path_meta->cur_inf);
        cur_hop_field = get_hop_field(((void*)path_meta_start), scion_path_meta->num_inf, scion_path_meta->cur_hf);


        // TODO: calculate hop expiry
        // Verify again
        /*ret = */verify_current_mac(cur_inf_field, cur_hop_field, br_info->mac_key, full_mac);
    } 

    // Validate egress id, basically we need to lookup egress id here...
    // But for now, I have no idea where these numbers come from
    // The point is: a packet from my local AS (ISD19) to another ISD 19 AS (connected to AP Magdeburg)
    // Has this output
    // Path meta 
    //    CurrInf: 0, CurrHF: 0, NumInf: 2, NumHf 4, Seg0Len: 2, Seg1Len: 2, Seg2Len: 0
    // INF fields:
    //    IF: SegId: 36424, consDir: 0
    //    IF: SegId: 34178, consDir: 0
    // HOP fields:
    //    HF: MAC: 18089872865972125696, Ingress: 1, Egress: 0
    //    HF: MAC: 8725836136162721792, Ingress: 286, Egress: 257 <- what is this
    //    HF: MAC: 9205584056140365824, Ingress: 286, Egress: 247 <- what is this
    //    HF: MAC: 12947491872978829312, Ingress: 1, Egress: 0
    // Funny side note: Ingress of HF #3 is not always the same for the same packet sent multiple times...
    // TODO: Combine these two
    // TODO: Put this back in for prod usage
    // __u32 egr_int_ip = egr_intf_ip_by_id(br_info, cur_hop_field->cons_egr_interface);
    // __u16 egr_int_port = egr_intf_port_by_id(br_info, cur_hop_field->cons_egr_interface);

    // We update the segId before updating HF 
    /*ret = */update_cons_dir_egress_seg_id(cur_inf_field, cur_hop_field);

    // INF field is not changed here anymore, we did this in xover
    update_cur_inf_hf(scion_path_meta);
    result->state = SCION_FORWARD_SUCCESS;
    // result->dst_port = egr_int_port;
    // result->dst_addr_v4 = egr_int_ip;

    // Write path meta back to packet
    __u32 raw = 0;
    path_meta_hdr_to_raw(scion_path_meta, &raw);
    *path_meta_start = htobe32(raw);

    free(scion_path_meta);
    free(full_mac);
    return result;
}
