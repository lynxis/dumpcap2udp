#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#include <pcap.h>

static struct sockaddr_in servaddr;
static int sockfd = -1;

#define HEADER_SIZE 16
#define MAX_PACKET_SIZE 4096

int init_udp(char *ip, int port) {
    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr= inet_addr(ip);
    servaddr.sin_port =  htons(port);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    return sockfd;
}


int send_udp(struct pcap_pkthdr *pkghdr, u_char *rawpacket) {
    char netpkg[MAX_PACKET_SIZE];
    int netpkg_size = 0;
    if(sockfd < 0)
        return sockfd;

    if((pkghdr->len + HEADER_SIZE) > MAX_PACKET_SIZE) {
        netpkg_size = MAX_PACKET_SIZE - HEADER_SIZE;
    } else {
        netpkg_size = pkghdr->len;
    }

    // clear header
    memset(netpkg, 0, HEADER_SIZE);
    memcpy((netpkg + HEADER_SIZE + sizeof(struct pcap_pkthdr)), pkghdr, sizeof(struct pcap_pkthdr));
    // copy raw packet
    memcpy((netpkg + HEADER_SIZE + sizeof(struct pcap_pkthdr)), rawpacket, netpkg_size);
    // save 64 or 32 bit stuff
    strncpy(netpkg, "UDP2PCAP", HEADER_SIZE);
    return sendto(sockfd, netpkg, netpkg_size, 0,(struct sockaddr *) &servaddr, sizeof(struct sockaddr_in));
}
