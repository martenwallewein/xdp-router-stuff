#include "scion.h"
#include <stdio.h>

#define SCION_FORWARD_IGNORE 0
#define SCION_FORWARD_SUCCESS 1

static inline void print_packet_info(
    const struct scion_hdr *scion_h,
    const scion_addr_hdr_v4 *scion_v4_h,
    const struct scion_path_meta_hdr *scion_path_meta
    ) {
        printf("----------- BEGIN SCION Packet --------- ");
        printf("----------- END SCION Packet --------- ");
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


    
    return 0;
}