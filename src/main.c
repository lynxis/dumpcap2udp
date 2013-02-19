#include <pcap.h>
#include <pcap-bpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>

#include <sys/epoll.h>



#define MAX_EVENTS 16

/**
- repr(tcpdump -i any udp port 53 or icmp or arp)
- udp writeto(192.168.2.1:9986, packet)
- eloop()
 */
int main(int argv, char *argc[]) {
    char given_dev[] = "wlan1";
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    int snaplen = 64 * 1024;
    int read_timeout_ms = 1000;
    int file_handle;
    pcap_t *handle;
    struct bpf_program compiled_filter;
    bpf_u_int32 mask;
    bpf_u_int32 netip;
    char filter[] = "udp";
    struct epoll_event events[MAX_EVENTS];

    dev = pcap_lookupdev(given_dev);
    if(dev == NULL) {
        printf("pcap lookupdev failed: %s\n", errbuf);
        exit(1);
    }

    ret = pcap_lookupnet(dev, &netip, &mask, errbuf);
    if(dev == NULL) {
        printf("pcap lookupnet failed: %s\n", errbuf);
        exit(1);
    }
    printf("Using dev %s\n", dev);
    int prmisc = 1;
    handle =  pcap_open_live(dev, snaplen, prmisc, read_timeout_ms, errbuf);
    if(handle == NULL) {
        printf("pcap open failed: %s\n", errbuf);
        exit(1);
    }
    mask = 0;
    // don't optimize
    ret = pcap_compile(handle, &compiled_filter, filter, 0, mask);
    printf("pcap compile returns %i \n", ret);
    if(ret == -1) {
        printf("pcap compilefilter failed: %s\n", pcap_geterr(handle));
        exit(1);
    }

    ret = pcap_setfilter(handle, &compiled_filter);
    if(ret == -1) {
        printf("pcap setfilter failed: %s", errbuf);
        exit(1);
    }

    file_handle = pcap_get_selectable_fd(handle);
    if(file_handle < 0) {
        printf("pcap can not get selectable filehandler");
        exit(1);
    }

    int epollfd, nfds;

    epollfd = epoll_create(MAX_EVENTS);
    if(epollfd < 0) {
        perror("while epoll ");
        printf("Can not setup epoll");
        exit(6);
    }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = file_handle;
    ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, file_handle, &ev);
    if (ret < 0) {
        printf("error while adding eloop");
        exit(1);
    }

    while(1) {
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        printf("socket nfds:  %i\n", nfds);
    }
    printf("Exit 0");
}
