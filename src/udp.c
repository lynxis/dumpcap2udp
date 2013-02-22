#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#include <pcap.h>

// 30 seconds
#define RETRY_INTERVAL 30

static struct sockaddr_in remote_addr;
static int sockfd = -1;
static time_t reconnect_timeout = 0;

#define HEADER_SIZE 16
#define MAX_PACKET_SIZE 4096

int reconnect_udp() {
    if(reconnect_timeout > time(NULL)) {
        return -EBUSY;
    }
    reconnect_timeout = time(NULL) + RETRY_INTERVAL;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    connect(sockfd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in));

    return sockfd;
}

int init_udp(char *ip, int port) {
    memset(&remote_addr, 0, sizeof(struct sockaddr_in));

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr= inet_addr(ip);
    remote_addr.sin_port =  htons(port);

    return reconnect_udp();
}

int send_udp(struct pcap_pkthdr *pkghdr, u_char *rawpacket) {
    char netpkg[MAX_PACKET_SIZE];
    int netpkg_size = 0;
    int ret;
    if(sockfd < 0) {
        ret = reconnect_udp();
        if(ret < 0) {
            return ret;
        }
    }
    if(rawpacket == NULL) {
        fprintf(stderr, "error rawpacket is null");
        return -1;
    } else if(pkghdr == NULL) {
        fprintf(stderr, "error pkghdr is null");
        return -1;
    }

    if((pkghdr->caplen + HEADER_SIZE) > MAX_PACKET_SIZE) {
        netpkg_size = MAX_PACKET_SIZE - HEADER_SIZE;
    } else {
        netpkg_size = pkghdr->caplen + HEADER_SIZE;
    }

    // clear header
    memset(netpkg, 0, HEADER_SIZE);
    memcpy((netpkg + HEADER_SIZE + sizeof(struct pcap_pkthdr)), pkghdr, sizeof(struct pcap_pkthdr));
    // copy raw packet
    memcpy((netpkg + HEADER_SIZE + sizeof(struct pcap_pkthdr)), rawpacket, netpkg_size - (HEADER_SIZE + sizeof(struct pcap_pkthdr)) );
    // save 64 or 32 bit stuff
    strncpy(netpkg, "UDP2PCAP", HEADER_SIZE);
    ret = send(sockfd, netpkg, netpkg_size, 0);
    if(ret < 0) {

    }

    return ret;
}
