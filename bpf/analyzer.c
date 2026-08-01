// +build ignore

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#include "bpf_helpers.h"
#include "bpf_endian.h"

/* ==========================================================================
 * NETWORK HEADERS for L1 / L2 / L3
 * ========================================================================== */

struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __u16 h_proto;
} __attribute__((packed));

struct arphdr_custom {
    __u16 ar_hrd;
    __u16 ar_pro;
    __u8  ar_hln;
    __u8  ar_pln;
    __u16 ar_op;
    __u8  ar_sha[6];
    __u32 ar_sip;
    __u8  ar_tha[6];
    __u32 ar_tip;
} __attribute__((packed));

struct iphdr {
    __u8  ihl:4, version:4;
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

struct ipv6hdr {
    __u8  priority:4, version:4;
    __u8  flow_lbl[3];
    __u16 payload_len;
    __u8  nexthdr;
    __u8  hop_limit;
    __u8  saddr[16];
    __u8  daddr[16];
} __attribute__((packed));

struct icmp6hdr {
    __u8  icmp6_type;
    __u8  icmp6_code;
    __u16 icmp6_cksum;
} __attribute__((packed));

struct udphdr {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
} __attribute__((packed));

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

/* Network const */
#define ETH_P_IP    0x0800
#define ETH_P_ARP   0x0806
#define ETH_P_IPV6  0x86DD

#define IPPROTO_UDP    17
#define IPPROTO_ICMPV6 58

#define NDISC_ROUTER_ADVERTISEMENT 134

#define PROTO_UNKNOWN   0
#define PROTO_ARP_REQ   1
#define PROTO_IPV6_RA   2
#define PROTO_MDNS      3
#define PROTO_LLMNR     4
#define PROTO_CDP_LLDP  5

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

#define XDP_PASS 2

/* ==========================================================================
 * MAPS and EVENTS structs
 * ========================================================================== */

struct stats_key_t {
    __u16 proto_type;   // 2 byte
    __u8  src_mac[6];    // 6 byte
} __attribute__((packed));

struct stats_val_t {
    __u64 packets;       // 8 byte
    __u64 bytes;         // 8 byte
} __attribute__((packed));

struct broadcast_event_t {
    __u64 timestamp_ns;   // 8 byte
    __u32 src_ip_v4;      // 4 byte
    __u32 target_ip_v4;   // 4 byte
    __u8  src_ip_v6[16];  // 16 byte
    __u16 proto_type;     // 2 byte
    __u16 pkt_len;        // 2 byte
    __u8  src_mac[6];     // 6 byte
} __attribute__((packed));

/* ==========================================================================
 * MAPPE eBPF
 * ========================================================================== */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct stats_key_t);
    __type(value, struct stats_val_t);
} broadcast_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* ==========================================================================
 * HELPER FUNCTIONS
 * ========================================================================== */

static __always_inline void update_stats(__u8 src_mac[6], __u16 proto_type, __u64 bytes) {
    struct stats_key_t key = {};
    __builtin_memcpy(key.src_mac, src_mac, 6);
    key.proto_type = proto_type;

    struct stats_val_t *val = bpf_map_lookup_elem(&broadcast_stats, &key);
    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, bytes);
    } else {
        struct stats_val_t new_val = { .packets = 1, .bytes = bytes };
        bpf_map_update_elem(&broadcast_stats, &key, &new_val, BPF_ANY);
    }
}

static __always_inline void send_event(struct broadcast_event_t *event) {
    struct broadcast_event_t *ring_event;

    ring_event = bpf_ringbuf_reserve(&events, sizeof(*ring_event), 0);
    if (!ring_event)
        return;

    __builtin_memcpy(ring_event, event, sizeof(*ring_event));
    ring_event->timestamp_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(ring_event, 0);
}

/* ==========================================================================
 * XDP PROGRAM MAIN ENTRYPOINT
 * ========================================================================== */

SEC("xdp")
int filter_broadcast(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (!(eth->h_dest[0] & 1))
        return XDP_PASS;

    //
    // Use this if you want to just analyze pure broadcast traffic
    //
    //  if (eth->h_dest[0] != 0xFF || eth->h_dest[1] != 0xFF || eth->h_dest[2] != 0xFF ||
    //      eth->h_dest[3] != 0xFF || eth->h_dest[4] != 0xFF || eth->h_dest[5] != 0xFF)
    //      return XDP_PASS;
    //

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    __u64 pkt_len = (unsigned long)data_end - (unsigned long)data;
    __u16 proto_type = PROTO_UNKNOWN;

    struct broadcast_event_t event = {};
    __builtin_memcpy(event.src_mac, eth->h_source, 6);
    event.pkt_len = (__u16)pkt_len;

    if (h_proto == ETH_P_ARP) {
        struct arphdr_custom *arp = (void *)(eth + 1);
        if ((void *)(arp + 1) > data_end)
            return XDP_PASS;

        if (bpf_ntohs(arp->ar_op) == 1) {
            proto_type = PROTO_ARP_REQ;
            event.proto_type = PROTO_ARP_REQ;
            event.src_ip_v4 = arp->ar_sip;
            event.target_ip_v4 = arp->ar_tip;
            send_event(&event);
        }
    }
    else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        __builtin_memcpy(event.src_ip_v6, &ip6->saddr, 16);

        if (ip6->nexthdr == IPPROTO_ICMPV6) {
            struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
            if ((void *)(icmp6 + 1) > data_end)
                return XDP_PASS;

            if (icmp6->icmp6_type == NDISC_ROUTER_ADVERTISEMENT) {
                proto_type = PROTO_IPV6_RA;
                event.proto_type = PROTO_IPV6_RA;
                send_event(&event);
            }
        }
        else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;

            __u16 dport = bpf_ntohs(udp->dest);
            if (dport == 5353) {
                proto_type = PROTO_MDNS;
                event.proto_type = PROTO_MDNS;
                send_event(&event);
            } else if (dport == 5355) {
                proto_type = PROTO_LLMNR;
                event.proto_type = PROTO_LLMNR;
                send_event(&event);
            }
        }
    }
    else if (h_proto == ETH_P_IP) {
        struct iphdr *ip4 = (void *)(eth + 1);
        if ((void *)(ip4 + 1) > data_end)
            return XDP_PASS;

        event.src_ip_v4 = ip4->saddr;

        if (ip4->protocol == IPPROTO_UDP) {
            /* 1. Estrai l'IHL e applica un mascheramento bit a bit.
             * Questo dice al Verifier che il valore non può superare 15. */
            __u32 ihl = ip4->ihl & 0x0f;
            __u32 ip_hlen = ihl * 4;

            /* 2. Controllo di sicurezza stringente per il Verifier.
             * L'header IP standard va da 20 a 60 byte. */
            if (ip_hlen < sizeof(struct iphdr) || ip_hlen > 60)
                return XDP_PASS;

            /* 3. Calcola la posizione dell'header UDP usando l'offset verificato */
            struct udphdr *udp = (void *)((unsigned char *)ip4 + ip_hlen);

            /* 4. Verifica di sicurezza obbligatoria sui limiti del pacchetto */
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;

            __u16 dport = bpf_ntohs(udp->dest);
            if (dport == 5353) {
                proto_type = PROTO_MDNS;
                event.proto_type = PROTO_MDNS;
                send_event(&event);
            } else if (dport == 5355) {
                proto_type = PROTO_LLMNR;
                event.proto_type = PROTO_LLMNR;
                send_event(&event);
            }
        }
    }
    else if (h_proto == 0x2000 || h_proto == 0x88CC) {
        proto_type = PROTO_CDP_LLDP;
        event.proto_type = PROTO_CDP_LLDP;
        send_event(&event);
    }

    if (proto_type != PROTO_UNKNOWN) {
        update_stats(eth->h_source, proto_type, pkt_len);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";