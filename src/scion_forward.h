#include "scion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SCION_FORWARD_IGNORE 0
#define SCION_FORWARD_SUCCESS 1

#define SCION_ENDHOST_PORT 30041

struct scion_forward_result {
    __u32 dst_addr_v4;
    __u16 dst_port;
    __u8 state; // See SCION_FORWARD_*
};

void int64ToChar(char a[], __u64 n) {
  memcpy(a, &n, 8);
}


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
    asprintf(target, "%x:%x:%x", _ntohs(parts[0]), _ntohs(parts[1]), _ntohs(parts[2]));        
}

// 0 0 32 128
static inline struct scion_path_meta_hdr* path_meta_hdr_from_raw(__u32 raw) {
    struct scion_path_meta_hdr* pmh = (struct scion_path_meta_hdr*)malloc(sizeof(struct scion_path_meta_hdr));
    printf("RAW BUF %u\n\n", raw);
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

static inline struct scion_info_field* get_inf_field(void* data, __u8 index) {
    // offset: 4𝐵+8𝐵⋅CurrINF
    char* new_off = (void*)(((char*)data) + 4 + 8 * index);
    // printf("Got data %p and new off %p\n", data, new_off);
    return (struct scion_info_field*)new_off;
}

static inline struct scion_hop_field* get_hop_field(void* data, __u8 num_inf, __u8 hf_index) {
    // offset: 4𝐵+8𝐵⋅NumINF+12𝐵⋅CurrHF
    char* new_off = (void*)(((char*)data) + 4 + 8 * num_inf + 12 * hf_index);
    // printf("Got data %p and new off %p with num_inf %u and hf %u\n", data, new_off, num_inf, hf_index);
    return (struct scion_hop_field*)(new_off);
}

static inline void print_inf(struct scion_info_field* cur_inf_field) {
    printf("IF: SegId: %u, consDir: %u\n", _ntohs(cur_inf_field->seg_id), cur_inf_field->constr_dir);
}

static inline void print_hf(struct scion_hop_field* cur_hop_field) {
    printf("HF: MAC: %lu, Ingress: %u, Egress: %u\n", _ntohl(cur_hop_field->mac), _ntohs(cur_hop_field->cons_ingr_interface), _ntohs(cur_hop_field->cons_egr_interface)); 
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
    printf("Common Header \n \tNextHdr: %u, HdrLen %u, PayloadLen %u, PathType %u, DT %u, Dl %u, ST %u, Sl %u\n", scion_h->next_hdr, scion_h->hdr_len, _ntohs(scion_h->payload_len), scion_h->path_type, scion_h->dt, _ntohs(scion_h->dl), scion_h->st, scion_h->sl);
    printf("Address Header \n \tDstIds: %u, DstAS: %s, SrcISD %u, SrcAS: %s, DstHostAddr: %s, SrcHostAddr: %s\n", _ntohs(scion_v4_h->dst_isd), dstAS, _ntohs(scion_v4_h->src_isd), srcAS, dstIP, srcIP);
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


static inline void update_cur_inf_hf(struct scion_path_meta_hdr *scion_path_meta) {
    /*__u8 hf_len = scion_path_meta->seg_0_len;
    if(scion_path_meta->cur_hf == (hf_len - 1) && scion_path_meta->seg_1_len > 0) {
        scion_path_meta->cur_inf = 1;
    }
    hf_len += scion_path_meta->seg_1_len;
    if(scion_path_meta->cur_hf == (hf_len - 1) && scion_path_meta->seg_2_len > 0) {
        scion_path_meta->cur_inf = 2;
    }*/
    scion_path_meta->cur_inf = inf_index_for_hf(scion_path_meta, scion_path_meta->cur_hf);
    scion_path_meta->cur_hf += 1;   
}



/*
func (p *scionPacketProcessor) updateNonConsDirIngressSegID() error {
	// against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// TODO(lukedirtwalker): For packets destined to peer links this shouldn't
	// be updated.
	if !p.infoField.ConsDir && p.ingressID != 0 {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
			return serrors.WrapStr("update info field", err)
		}
	}
	return nil
}
*/


// func (inf *InfoField) UpdateSegID(hfMac []byte) {
//	inf.SegID = inf.SegID ^ binary.BigEndian.Uint16(hfMac[:2])
//}

// UpdateSegID updates the SegID field by XORing the SegID field with the 2
// first bytes of the MAC. It is the beta calculation according to
// https://scion.docs.anapaya.net/en/latest/protocols/scion-header.html#hop-field-mac-computation
static inline void update_seg_id(struct scion_info_field* cur_inf_field, __u64 mac) {
    cur_inf_field->seg_id = _htonl(cur_inf_field->seg_id ^ be64toh(mac) >> 32 && 0x11);
}
 

static inline int update_non_cons_dir_ingress_seg_id(
    struct scion_info_field* cur_inf_field,
    struct scion_hop_field* cur_hop_field
) {
    // against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// TODO(lukedirtwalker): For packets destined to peer links this shouldn't
	// be updated.
    if (cur_inf_field->constr_dir == 0 && _ntohs(cur_hop_field->cons_ingr_interface) != 0) {
        // update segId in info filed
        update_seg_id(cur_inf_field, cur_hop_field->mac);
        return 1;

    }
    return 0;
}

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
        update_seg_id(cur_inf_field, cur_hop_field->mac);
        return 1;

    }
    return 0;
}

//func (p *scionPacketProcessor) verifyCurrentMAC() (processResult, error) {
//	fullMac := path.FullMAC(p.mac, p.infoField, p.hopField, p.macBuffers.scionInput)
//	if subtle.ConstantTimeCompare(p.hopField.Mac[:path.MacLen], fullMac[:path.MacLen]) == 0 {

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

    return 0;
}

static inline int is_xover(struct scion_path_meta_hdr* scion_path_meta) {
    return scion_path_meta->cur_inf != inf_index_for_hf(scion_path_meta, scion_path_meta->cur_hf + 1);
}

static inline __u32 egr_intf_ip_by_id(struct scion_br_info* br_info, __u16 egr_int_id) {
    __u16 i = 0;
    for (i = 0; i < br_info->num_links; i++) {
        if (*(br_info->link_egr_ids + i) == egr_int_id) {
            return *(br_info->link_egr_ips + i);
        }
    }

    return 0;
}

static inline struct scion_forward_result* handle_forward(void* data, struct scion_br_info* br_info) {
    // We got the stripped version of the packet starting with the SCION header here
    // This simplifies things because we can test this function within a normal udp socket
    // implementation. 
    const struct scion_hdr *scion_h = (const struct scion_hdr *)(data);
    struct scion_forward_result* result = malloc(sizeof(struct scion_forward_result));

    // Things we already know:
    // - It's definetly a SCION packet
    // - SCION path_type matches, next_hdr is set to UDP
    // - The packet arrived at a configured port for one of the interfaces in the topology

    // Parse addr header, lets limit it to IPv4 at the moment (since the ebpf code also supports only v4 now)
    // TODO: Parsing not correct here...
    //if (scion_h->dl != (__u8)_htons(4) || scion_h->sl != (__u8)_htons(4)) {
    //    return SCION_FORWARD_IGNORE;
    //}

    const struct scion_addr_hdr_v4 *scion_v4_h = (const struct scion_addr_hdr_v4 *)(scion_h + 1);
    // TODO: Check local and remote AS/ISD, handle error if this does not match
    printf("OFFSET %ld\n", sizeof(*scion_v4_h) + sizeof(*scion_h));
    // Get the path meta informationconst struct scion_addr_hdr_v4
    
    // const struct scion_path_meta_hdr *scion_path_meta = (const struct scion_path_meta_hdr *)(scion_v4_h + 1);
    __u32* path_meta_start = (__u32*)(scion_v4_h + 1);// (((char*)data) + 36);
    printf("Data starts %p, path_meta_starts %p, val %u, nthos %lu\n", data, path_meta_start, *path_meta_start, _ntohl(*path_meta_start));
    struct scion_path_meta_hdr *scion_path_meta = path_meta_hdr_from_raw(_ntohl(*path_meta_start));
    print_packet_info(scion_h, scion_v4_h, scion_path_meta);
    

    // Get current INF/HF
    struct scion_info_field* cur_inf_field = get_inf_field(((void*)path_meta_start), scion_path_meta->cur_inf);
    struct scion_hop_field* cur_hop_field = get_hop_field(((void*)path_meta_start), scion_path_meta->num_inf, scion_path_meta->cur_hf);

    // printf("Data starts %p, inf %p\n", (scion_v4_h + 1), cur_inf_field);
    
    
    // print_hf(cur_hop_field);
    int ret = 0;
    // Check if ingress and consDir
    ret = update_non_cons_dir_ingress_seg_id(cur_inf_field, cur_hop_field);

    __u64* full_mac = malloc(2 * sizeof(__u64)); // 16 bytes
    ret = verify_current_mac(cur_inf_field, cur_hop_field, br_info->mac_key, full_mac);

    // TODO: Handle alerts!!
    //__u64 new_mac = calc_mac(cur_inf_field, cur_hop_field);
    //__u16 new_seg_id = calc_seg_id(cur_inf_field, new_mac);

    // Inbound: pkts destined to the local IA.
	//if p.scionLayer.DstIA.Equal(p.d.localIA) && int(p.path.PathMeta.CurrHF)+1 == p.path.NumHops 
    // TODO: We need to make sure that its not a svc address...
    if (br_info->local_isd == scion_v4_h->dst_isd && br_info->local_ia == _ntohl(scion_v4_h->dst_ia)) {
        result->state = SCION_FORWARD_SUCCESS;
        result->dst_port = SCION_ENDHOST_PORT;
        result->dst_addr_v4 = scion_v4_h->dst_host_addr;
        return result;
    }

	// Outbound: pkts leaving the local IA.
	// BRTransit: pkts leaving from the same BR different interface.
    if(is_xover(scion_path_meta)) {
        update_cur_inf_hf(scion_path_meta);
        // TODO: Get new cur_inf_field
        cur_inf_field = get_inf_field(((void*)path_meta_start), scion_path_meta->cur_inf);
        cur_hop_field = get_hop_field(((void*)path_meta_start), scion_path_meta->num_inf, scion_path_meta->cur_hf);


        // TODO: calculate hop expiry
        ret = verify_current_mac(cur_inf_field, cur_hop_field, br_info->mac_key, full_mac);
    } else {
        update_cur_inf_hf(scion_path_meta);
    }

    // Validate egress id, basically we need to lookup egress id here...
    __u16 egr_int_ip = egr_intf_ip_by_id(br_info, cur_hop_field->cons_egr_interface);

    ret = update_cons_dir_egress_seg_id(cur_inf_field, cur_hop_field);

    result->state = SCION_FORWARD_SUCCESS;
    result->dst_port = SCION_ENDHOST_PORT;
    result->dst_addr_v4 = egr_int_ip;

    // TODO: Write path meta to packet

    // Update curHF/curINF
    // update_cur_inf_hf(scion_path_meta);
    free(scion_path_meta);
    return result;
}

/*
func (p *scionPacketProcessor) process() (processResult, error) {

	if r, err := p.parsePath(); err != nil {
		return r, err
	}
	if r, err := p.validatePktLen(); err != nil {
		return r, err
	}
	if err := p.updateNonConsDirIngressSegID(); err != nil {
		return processResult{}, err
	}
	if r, err := p.verifyCurrentMAC(); err != nil {
		return r, err
	}
	if r, err := p.handleIngressRouterAlert(); err != nil {
		return r, err
	}

	// Inbound: pkts destined to the local IA.
	if p.scionLayer.DstIA.Equal(p.d.localIA) && int(p.path.PathMeta.CurrHF)+1 == p.path.NumHops {
		a, r, err := p.resolveInbound()
		if err != nil {
			return r, err
		}
		return processResult{OutConn: p.d.internal, OutAddr: a, OutPkt: p.rawPkt}, nil
	}

	// Outbound: pkts leaving the local IA.
	// BRTransit: pkts leaving from the same BR different interface.

	if p.path.IsXover() {
		if r, err := p.doXover(); err != nil {
			return r, err
		}
	}
	if r, err := p.validateEgressID(); err != nil {
		return r, err
	}
	// handle egress router alert before we check if it's up because we want to
	// send the reply anyway, so that trace route can pinpoint the exact link
	// that failed.
	if r, err := p.handleEgressRouterAlert(); err != nil {
		return r, err
	}
	if r, err := p.validateEgressUp(); err != nil {
		return r, err
	}

	egressID := p.egressInterface()
	if c, ok := p.d.external[egressID]; ok {
		if err := p.processEgress(); err != nil {
			return processResult{}, err
		}
		return processResult{EgressID: egressID, OutConn: c, OutPkt: p.rawPkt}, nil
	}

	// ASTransit: pkts leaving from another AS BR.
	if a, ok := p.d.internalNextHops[egressID]; ok {
		return processResult{OutConn: p.d.internal, OutAddr: a, OutPkt: p.rawPkt}, nil
	}
	errCode := slayers.SCMPCodeUnknownHopFieldEgress
	if !p.infoField.ConsDir {
		errCode = slayers.SCMPCodeUnknownHopFieldIngress
	}
	return p.packSCMP(
		&slayers.SCMP{
			TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem, errCode),
		},
		&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
		cannotRoute,
	)
}
*/