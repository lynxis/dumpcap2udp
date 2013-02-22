#include <pcap.h>

int init_udp(char *ip, int port);
int send_udp(struct pcap_pkthdr *pkghdr, const u_char *rawpacket);
