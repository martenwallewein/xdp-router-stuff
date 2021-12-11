#ifndef SCION_H
#define SCION_H


#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <endian.h>


// See SCION header specification: 
struct scion_hdr {
    __u32 info; // version, qos, flow_id, add later if requried
    __u8 next_hdr;
    __u8 hdr_len;
    __u16 payload_len;
    __u8 path_type;
    __u8 dt: 2;
    __u8 dl: 2;
    __u8 st: 2;
    __u8 sl: 2;
    __u16 reserved;
};

struct scion_addr_hdr_v4 {
    __u16 dst_isd;
    __u64 dst_ia: 48;
    __u16 src_isd;
    __u64 src_ia: 48;
    __u32 dst_host_addr;
    __u32 src_host_addr;
};

struct scion_addr_hdr_v6 {
    __u16 dst_isd;
    __u64 dst_ia: 48;
    __u16 src_isd;
    __u64 src_ia: 48;
    /* TODO: Find a matching type for 16byte int */
    __u32  dst_host_addr[4];
    __u32 src_host_addr[4];
};

struct scion_path_meta_hdr {
    __u8 cur_inf: 2;
    __u8 cur_hf: 6;
    __u8 rsv: 6;
    __u8 seg_0_len: 6;
    __u8 seg_1_len: 6;
    __u8 seg_2_len: 6;

    // additional fields
    __u8 num_hf;
    __u8 num_inf;
};

struct scion_info_field {
    __u8 rsv: 6;
    __u8 peering: 1; // Peering flag. If set to true, then the forwarding path is built as a peering path, which requires special processing on the dataplane.
    __u8 constr_dir: 1; // Construction direction flag. If set to true then the hop fields are arranged in the direction they have been constructed during beaconing.
    __u8 rsv2: 8;
    __u16 seg_id: 16;
    __u32 timestamp: 32;
};

struct scion_hop_field {
    __u8 rsv: 8;
    //__u8 cons_ingr_alert: 1;
    //__u8 cons_egr_alert: 1;
    __u16 cons_ingr_interface: 16;
    __u16 cons_egr_interface: 16;
    __u64 mac; // :48 TODO: This is not aligned correctly, plase do not use sizeof(scion_hop_field) to calculate further offsets...
};


struct scion_br_info {
    __u64* mac_key;
    __u16 local_isd;
    __u64 local_ia;
    __u16* link_ingr_ids;
    __u16* link_egr_ids;
    __u32* link_ingr_ips;
    __u32* link_egr_ips;
    __u32* link_egr_ports;
    __u32* link_ingr_ports;
    __u32 num_links;
    uint8_t src_mac[ETH_ALEN];
    uint8_t dst_mac[ETH_ALEN];
    __u32 src_ip;
    __u32 dst_ip;

};

#define MIN_PACKET_SIZE 62 // 14 (eth) + 20 (IP) + 8 (UDP) + 12 (SCION) + 8 (UDP)

#endif /* SCION_H */
