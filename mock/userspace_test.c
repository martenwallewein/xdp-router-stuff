#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../src/scion_forward.h"
  
#define PORT      50011// 30001
#define MAXLINE 1500

__u32 to_u32_ip(__u8 block1, __u8 block2, __u8 block3, __u8 block4) {
    unsigned char bytes[4];
    __u32 ip = 0;
    ip |= (((__u32)block1) << 24) & 0xFF000000;
    ip |= (((__u32)block2) << 16) & 0xFF0000;
    ip |= (((__u32)block3) << 8) & 0xFF00;
    ip |= (((__u32)block4)) & 0xFF;
    return ip;
}
   
// Driver code
int main() {
    int sockfd;
    char buffer[MAXLINE];
    char *hello = "Hello from server";
    struct sockaddr_in servaddr, cliaddr;
       
    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }
       
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
       
    // Filling server information
    servaddr.sin_family    = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);
       
    // Bind the socket with the server address
    if ( bind(sockfd, (const struct sockaddr *)&servaddr, 
            sizeof(servaddr)) < 0 )
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
       
    int len, n;
   
    struct scion_br_info br_info;
    br_info.num_links = 1;
    br_info.link_egr_ids = malloc(sizeof(__u16));
    br_info.link_ingr_ids = malloc(sizeof(__u16));
    br_info.link_egr_ips = malloc(sizeof(__u32));
    br_info.link_ingr_ips = malloc(sizeof(__u32));
    br_info.link_egr_ports = malloc(sizeof(__u16));
    *(br_info.link_egr_ids) = 0;
    *(br_info.link_ingr_ids) = 1;
    *(br_info.link_ingr_ips) = to_u32_ip(192, 168, 178, 67);
    *(br_info.link_egr_ips) = to_u32_ip(192, 168, 178, 20);
    *(br_info.link_egr_ports) = 50011;// 8080;
    br_info.local_isd = 4864;
    br_info.local_ia = 18422537230224523264u;

   while(1) {
        n = recvfrom(sockfd, (char *)buffer, MAXLINE, 
                MSG_WAITALL, ( struct sockaddr *) &cliaddr,
                &len);
        printf("Received %u bytes\n", n);
                if (n!= 1380) {
                    continue;
                }

        // buffer[n] = '\0';
        // printf("Client : %d\n", n);
        struct scion_forward_result* ret = handle_forward(buffer, &br_info);
        if (ret->state == SCION_FORWARD_SUCCESS) {
            struct sockaddr_in cliaddr;
            len = sizeof(cliaddr);
            cliaddr.sin_family    = AF_INET; 
            cliaddr.sin_addr.s_addr = htonl(ret->dst_addr_v4);
            cliaddr.sin_port = htons(ret->dst_port);
            char* targetIp;
            print_ip(&targetIp, htonl(ret->dst_addr_v4));
            printf("Sending packet to %s:%u\n", targetIp, ret->dst_port);
            n = sendto(sockfd, (const char *)buffer, n,  MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);
            printf("Sent %d bytes\n", n);
            
            if (n < 0) {
                printf("Err sending packet\n");
                continue;
            }
        } else {
            printf("Packet not forwarded %u\n", ret->state);
        }
   }
   

    return 0;
}