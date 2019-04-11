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
#include <unistd.h>
#include <sys/epoll.h>

#include "udp.h"


#define MAX_EVENTS 16

void handle_pcap(pcap_t *handle) {
    struct pcap_pkthdr pkghdr;
    const u_char *rawpacket = pcap_next(handle, &pkghdr);
    int ret = 0;
    while (rawpacket != NULL) {
        ret = send_udp(&pkghdr, rawpacket);
        if(ret <0) {
            fprintf(stderr, "error while sending udp packet\n");
        }
        printf("pkglen %i - pkgcap %i\n", pkghdr.len, pkghdr.caplen);
        rawpacket = pcap_next(handle, &pkghdr);
    }
}

void usage(char *progname, char *filter) {
    fprintf(stderr,
            "%s [-i dev][-P port] -T ip [filter]\n"
            "\n"
            "most options are also found in tcpdump - see man tcpdump for further help."
            "-i dev - set capture device - default any\n"
            "-T ip  - set target ip\n"
            "-P port - set target port - default 3999\n"
            "-s snaplen - set snaplen\n"
            "-B buffersize\n"
            "filter - default filter is %s\n"
     , progname, filter);
    exit(1);
}

/**
- repr(tcpdump -i any udp port 53 or icmp or arp)
 */
int main(int argc, char *argv[]) {
    char default_filter[] = "(udp port 53) or icmp or arp";
    char default_device[] = "any";
    int snaplen = 64 * 1024;
    int read_timeout_ms = 1;
    int buffersize = 0;
    int port = 3999;

    char *ip = NULL;
    char *dev = NULL;
    char *filter = NULL;

    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    int file_handle;
    pcap_t *handle;
    struct bpf_program compiled_filter;
    bpf_u_int32 mask;

    struct epoll_event events[MAX_EVENTS];

    char ch;

    while ((ch = getopt(argc, argv, "s:T:P:i:B:")) != -1) {
        switch (ch) {
        case 's':
            snaplen = atoi(optarg);
            break;
        case 'T':
            ip = calloc(strlen(optarg), 1);
            strncpy(ip, optarg, strlen(optarg));
            break;
        case 'P':
            port = atoi(optarg);
            break;
        case 'i':
            dev = calloc(strlen(optarg) + 1, 1);
            strncpy(dev, optarg, strlen(optarg));
            break;
        default:
            usage(argv[0], default_filter);
        }
    }
    if(optind >= argc) {
        filter = default_filter;
    } else {
        // TODO: implement filter option
        //    printf("name argument = %s\n", argv[optind]);
    }
    if(ip == NULL) {
        usage(argv[0], default_filter);
    }
    if(dev == NULL) {
        dev = default_device;
    }

    // init pcap stuff
    printf("Using dev %s\n", dev);
    int prmisc = 1;
    handle =  pcap_create(dev, errbuf);
    if(handle == NULL) {
        printf("pcap create failed: %s\n", errbuf);
        exit(1);
    }

    pcap_set_promisc(handle, prmisc);
    pcap_set_snaplen(handle, snaplen);
    pcap_set_timeout(handle, read_timeout_ms);
    pcap_setnonblock(handle, 1, errbuf);
    if(buffersize > 0) {
        pcap_set_buffer_size(handle, buffersize);
    }

    // snaplen, prmisc, read_timeout_ms,
    ret = pcap_activate(handle);
    if(ret < 0) {
        fprintf(stderr, "pcap activate failed: %s\n", pcap_geterr(handle));
        exit(1);
    }

    mask = 0;
    ret = pcap_compile(handle, &compiled_filter, filter, 0, mask);
    printf("pcap compile returns %i \n", ret);
    if(ret == -1) {
        fprintf(stderr, "pcap compilefilter failed: %s\n", pcap_geterr(handle));
        exit(1);
    }

    ret = pcap_setfilter(handle, &compiled_filter);
    if(ret == -1) {
        fprintf(stderr, "pcap setfilter failed: %s", errbuf);
        exit(1);
    }
    file_handle = pcap_get_selectable_fd(handle);
    if(file_handle < 0) {
        fprintf(stderr, "pcap can not get selectable filehandler");
        exit(1);
    }


    int epollfd, nfds, n;

    epollfd = epoll_create(MAX_EVENTS);
    if(epollfd < 0) {
        perror("while epoll ");
        fprintf(stderr, "Can not setup epoll");
        exit(6);
    }

    init_udp(ip, port);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = file_handle;
    ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, file_handle, &ev);
    if (ret < 0) {
        fprintf(stderr, "error while adding eloop");
        exit(1);
    }

    while(1) {
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        printf("socket nfds: %i\n", nfds);

        for(n = 0; n < nfds; ++n) {
            if(events[n].data.fd == file_handle) {
                handle_pcap(handle);
            } else if(n == EINTR) {
                fprintf(stderr, "SIGNAL caugth\n");
                exit(1);
            }
            else {
                printf("unknown filehandle\n");
            }
        }
    }
}
