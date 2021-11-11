#ifndef SCION_H
#define SCION_H


#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

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
};

struct scion_info_field {
    __u8 rsv: 6;
    __u8 peering: 1; // Peering flag. If set to true, then the forwarding path is built as a peering path, which requires special processing on the dataplane.
    __u8 constr_dir: 1; // Construction direction flag. If set to true then the hop fields are arranged in the direction they have been constructed during beaconing.
    __u8 rsv2;
    __u16 seg_id;
    __u32 timestamp;
};

struct scion_hop_field {
    __u8 rsv: 6;
    __u8 cons_ingr_alert: 1;
    __u8 cons_egr_alert: 1;
    __u16 cons_ingr_interface;
    __u16 cons_egr_interface;
    __u64 mac: 48;
};

#define MIN_PACKET_SIZE 62 // 14 (eth) + 20 (IP) + 8 (UDP) + 12 (SCION) + 8 (UDP)
#define DISPATCHER_PORT 30041

#endif /* SCION_H */
