/*
   Packet processing time (ppt) as tcp option:
   new VNF info is inserted in the front
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      TCP header (w/o option)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | PPT_H_KIND    | PPT_H_LEN     |          PPT_H_EXID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | VNF_ID_1      |                      TSTAMP                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | VNF_ID_0      |                      TSTAMP                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Original Options               |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define KBUILD_MODNAME "pptmon"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <net/checksum.h>
#include <linux/version.h>

/* BCC does not accept separated custom header file,
   so we need to put everything in one file
 */

#define TCP_W_OPT_LEN_WORD_MAX 15
#define TCP_W_OPT_LEN_WORD_MIN 5
/* use experimental tcp option kind */
#define PPT_H_KIND 254
/* ppt header with one timestamp */
/* network byte order */
#define PPT_H_EXID 0x0000
#define MAX_VNF_ID 256

#define offset_of(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#define IP_CSUM_OFF (ETH_H_SIZE + \
                     offset_of(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_H_SIZE + IP_H_SIZE + \
                      offset_of(struct tcphdr, check))
#define TCP_OFFSET_OFF (ETH_H_SIZE + IP_H_SIZE + 12)
#define PPT_OFF (ETH_H_SIZE + IP_H_SIZE + TCP_H_SIZE)


#define CURSOR_ADVANCE(_target, _cursor, _len,_data_end) \
    ({  _target = _cursor; _cursor += _len; \
        if(_cursor > _data_end) return TC_ACT_OK; })


#if defined(__LITTLE_ENDIAN_BITFIELD)
# define htonll(x)	___constant_swab64(x)
# define ntohll(x)	___constant_swab64(x)
#elif defined(__BIG_ENDIAN_BITFIELD)
# define htonll(x) (x)
# define ntohll(x) (x)
#else
#error  "Please fix <asm/byteorder.h>"
#endif

#define ABS(a, b) ((a>b)? (a-b):(b-a))


/* structs */

struct ppt_hdr_t
{
    // u32 header;
    u8 kind;
    u8 hlen;
    u16 exid;
} __attribute__((packed));

struct ppt_data_t {
    u8 vnf_id;
    u32 tstamp:24;
} __attribute__((packed));


#define ETH_H_SIZE sizeof(struct ethhdr)
#define IP_H_SIZE sizeof(struct iphdr)
#define TCP_H_SIZE sizeof(struct tcphdr)
#define PPT_H_SIZE sizeof(struct ppt_hdr_t)
#define PPT_DAT_SIZE sizeof(struct ppt_data_t)

/* functions */

static __always_inline u16 incr_csum_replace16(u16 old_csum,
                                      u16 old_val,
                                      u16 new_val){
    u32 sum;
    old_csum = ~old_csum;
    old_val = ~old_val;
    sum = (u32)old_csum + old_val + new_val;
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return (u16)(~sum & 0xffff);
}

static __always_inline u16 incr_csum_replace32(u16 old_csum,
                                      u32 old_val,
                                      u32 new_val){
    u32 sum;
    old_csum = ~(old_csum);
    old_val = ~(old_val);
    sum = (u32)old_csum + (old_val >> 16) + (old_val & 0xffff)
          + (new_val >> 16) + (new_val & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return (u16)(~sum & 0xffff);
}

static __always_inline u16 incr_csum_add32(u16 old_csum, u32 add_val)
{
    u32 sum;
    old_csum = ~old_csum;
    sum = (u32)old_csum + (add_val >> 16) + (add_val & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return (u16)(~sum & 0xffff);
}

static __always_inline u16 incr_csum_remove32(u16 old_csum, u32 rem_val)
{
    return incr_csum_add32(old_csum, ~rem_val);
}

static __always_inline u64 get_now_ns(struct __sk_buff *skb)
{
    /* skb->tstamp only available after kernel 5.0. Thus for lower kernel
       version, we use bpf_ktime_get_ns(), which is relative time from boot,
       and may be more expensive call
     */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
    return bpf_ktime_get_ns();
#else
    return skb->tstamp;
#endif
}

static __always_inline u64 get_pptime(u32 old_ktime)
{
    u32 ktime_now = bpf_ktime_get_ns()/1000 & 0xffffff;
    /* because ktime count from the os booted, and ppt tstamp is only 24 bit,
       it can be overflowed. Assume that packet processing time
       will not > 2^24 us ~= 16s, if tstamp_now < tstamp, then it
       is atually overflowed 1 time
    */
    if (ktime_now < old_ktime)
        ktime_now += 0x1000000;
    return ktime_now - old_ktime;
}

static __always_inline u8 tcp_doff_csum_update(struct __sk_buff *skb,
                                               u16 *csum, u8 doff,
                                               u8 doff_added)
{
    /* update TCP header len & checksum */
    /* because offset is only 4 bits, we need to expand to 2 bytes
       for checksum calculation, which include offset, reseved, flags
     */
    u16 old_off2flag, new_off2flag;
    bpf_skb_load_bytes(skb,
                       TCP_OFFSET_OFF,
                       &old_off2flag,
                       sizeof(old_off2flag));

    doff = doff + doff_added;
    new_off2flag = htons((ntohs(old_off2flag) & 0xfff) | (doff << 12));
    *csum = incr_csum_replace16(*csum, old_off2flag, new_off2flag);

    return doff;
}

/* BPF maps */

/* Lower kernel versions do not support BPF_F_MMAPABLE */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,5,0)
BPF_F_TABLE("array", int, u64, tb_prev_sample_time, 1, 0);
BPF_F_TABLE("array", int, u64, tb_prev_update_time, 1, 0);
BPF_F_TABLE("array", int, u32, tb_prev_pptime, MAX_VNF_ID, 0);
#else
BPF_F_TABLE("array", int, u64, tb_prev_sample_time, 1, BPF_F_MMAPABLE);
BPF_F_TABLE("array", int, u64, tb_prev_update_time, 1, BPF_F_MMAPABLE);
BPF_F_TABLE("array", int, u32, tb_prev_pptime, MAX_VNF_ID, BPF_F_MMAPABLE);
#endif

BPF_PERF_OUTPUT(ppt_events);

/* main functions */

int ppt_source(struct __sk_buff *skb)
{
    /* check sampling period before doing anything */

    int k = 0;

    u64 *prev_sample_time = tb_prev_sample_time.lookup(&k);
    if (unlikely(!prev_sample_time))
        return TC_ACT_OK;

    u64 now_time = get_now_ns(skb);
    if (now_time < *prev_sample_time + SAMPLE_PERIOD_NS)
        return TC_ACT_OK;

    /* parsing pkt structure */

    void* data_end = (void*)(long)skb->data_end;
    void* cursor = (void*)(long)skb->data;

    struct ethhdr *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        CURSOR_ADVANCE(tcp, cursor, sizeof(*tcp), data_end);

#ifndef FILTER_TCP
    return TC_ACT_OK;
#endif
#ifdef SRC_IP
        if (ip->saddr != htonl(SRC_IP))
            return TC_ACT_OK;
#endif
#ifdef DST_IP
        if (ip->daddr != htonl(DST_IP))
            return TC_ACT_OK;
#endif
#ifdef SRC_PORT
        if (tcp->sport != htonl(SRC_PORT))
            return TC_ACT_OK;
#endif
#ifdef DST_PORT
        if (tcp->dport != htonl(DST_PORT))
            return TC_ACT_OK;
#endif

        /* check if there is enough space */
        if (tcp->doff > TCP_W_OPT_LEN_WORD_MAX -
            ((PPT_H_SIZE + PPT_DAT_SIZE) >> 2))
            return TC_ACT_OK;

        /* ppt header */
        struct ppt_hdr_t ppt_hdr = {};
        struct ppt_data_t ppt_data = {};
        ppt_hdr.kind = PPT_H_KIND;
        ppt_hdr.hlen = PPT_H_SIZE + PPT_DAT_SIZE;
        ppt_hdr.exid = PPT_H_EXID;
        ppt_data.vnf_id = VNF_ID;

        ppt_data.tstamp = bpf_ktime_get_ns()/1000 & 0xffffff;

        /*  Because after adjust pkt room, all pointers wil be invalid,
            we need to update ip and tcp header prior
        */
        /* update IP header & checksum */
        u16 old_ip_tlen = ip->tot_len;
        u16 new_ip_tlen = htons(ntohs(old_ip_tlen) + PPT_H_SIZE + PPT_DAT_SIZE);
        ip->tot_len = new_ip_tlen;
        ip->check = incr_csum_replace16(ip->check, old_ip_tlen, new_ip_tlen);

        /* update TCP header len & checksum */
        u16 csum = tcp->check;
        tcp->doff = tcp_doff_csum_update(skb, &csum, tcp->doff,
                                        (PPT_H_SIZE + PPT_DAT_SIZE) >> 2);

        /* tcplen pseudo header */
        u16 old_tcplen = htons(ntohs(old_ip_tlen) - (ip->ihl << 2));
        u16 new_tcplen = htons(ntohs(new_ip_tlen) - (ip->ihl << 2));
        csum = incr_csum_replace16(csum, old_tcplen, new_tcplen);

        /* checksum with new ppt */
        csum = incr_csum_add32(csum, (PPT_H_KIND | ppt_hdr.hlen << 8 | PPT_H_EXID << 16));
        csum = incr_csum_add32(csum, ppt_data.vnf_id | (ppt_data.tstamp << 8));

        tcp->check = csum;

        /*  Now we actually create space to add ppt header.
            We want to create space right after TCP header and before TCP option,
            which bpf_skb_adjust_room does not support yet.
            Thus, we create space right before IP header (which is supported),
            then move the IP and TCP (w/o option) header back to correct position
        */
        struct tcphdr tcp_buf = {};
        bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE,
                        &tcp_buf, TCP_H_SIZE);
        bpf_skb_adjust_room(skb, PPT_H_SIZE + PPT_DAT_SIZE, BPF_ADJ_ROOM_NET, 0);
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE,
                            &tcp_buf, TCP_H_SIZE, 0);
        /* add PPT header to the new created space */
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + TCP_H_SIZE,
                            &ppt_hdr, PPT_H_SIZE, 0);
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + TCP_H_SIZE + PPT_H_SIZE,
                            &ppt_data, PPT_DAT_SIZE, 0);

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);

#ifndef FILTER_UDP
        return TC_ACT_OK;
#endif
#ifdef SRC_IP
        if (ip->saddr != htonl(SRC_IP))
            return TC_ACT_OK;
#endif
#ifdef DST_IP
        if (ip->daddr != htonl(DST_IP))
            return TC_ACT_OK;
#endif
#ifdef SRC_PORT
        if (udp->source != htonl(SRC_PORT))
            return TC_ACT_OK;
#endif
#ifdef DST_PORT
        if (udp->dest != htonl(DST_PORT))
            return TC_ACT_OK;
#endif

        /* TODO: check if there is enough space */

        /* ppt header */
        struct ppt_hdr_t ppt_hdr = {};
        struct ppt_data_t ppt_data = {};
        ppt_hdr.kind = PPT_H_KIND;
        ppt_hdr.hlen = PPT_H_SIZE + PPT_DAT_SIZE;
        ppt_hdr.exid = PPT_H_EXID;
        ppt_data.vnf_id = VNF_ID;

        ppt_data.tstamp = bpf_ktime_get_ns()/1000 & 0xffffff;

        /* update IP header & checksum */
        u16 old_ip_tlen = ip->tot_len;
        u16 new_ip_tlen = htons(ntohs(old_ip_tlen) + PPT_H_SIZE + PPT_DAT_SIZE);
        ip->tot_len = new_ip_tlen;
        ip->check = incr_csum_replace16(ip->check, old_ip_tlen, new_ip_tlen);

        /* add PPT header and data to the end of udp packet */
        u16 udp_len = ntohs(udp->len);
        bpf_skb_change_tail(skb, ETH_H_SIZE + ntohs(new_ip_tlen), 0);
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + udp_len,
                            &ppt_hdr, PPT_H_SIZE, 0);
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + udp_len + PPT_H_SIZE,
                            &ppt_data, PPT_DAT_SIZE, 0);
    }

    /* update prev_sample_time after everything is done */
    *prev_sample_time = now_time;

    return TC_ACT_OK;
}

/* add ppt header if is packet is already has ppt */
int ppt_transit_ingress(struct __sk_buff *skb)
{
    void* data_end = (void*)(long)skb->data_end;
    void* cursor = (void*)(long)skb->data;

    struct ethhdr *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        CURSOR_ADVANCE(tcp, cursor, sizeof(*tcp), data_end);
        /* check if tcp option exist */
        if (tcp->doff <= TCP_W_OPT_LEN_WORD_MIN)
            return TC_ACT_OK;

        struct ppt_hdr_t *ppt_hdr;
        CURSOR_ADVANCE(ppt_hdr, cursor, PPT_H_SIZE, data_end);
        if (ppt_hdr->kind != PPT_H_KIND || ppt_hdr->exid != PPT_H_EXID)
            return TC_ACT_OK;

        /* TODO: check if remaining space in tcp option is enough */

        struct ppt_data_t ppt_data = {};
        ppt_data.vnf_id = VNF_ID;
        ppt_data.tstamp = bpf_ktime_get_ns()/1000 & 0xffffff;;

        /* update IP header & checksum */
        u16 old_ip_tlen = ip->tot_len;
        u16 new_ip_tlen = htons(ntohs(old_ip_tlen) + (PPT_DAT_SIZE));
        ip->tot_len = new_ip_tlen;
        ip->check = incr_csum_replace16(ip->check, old_ip_tlen, new_ip_tlen);

        /* update TCP header len & checksum */
        u16 csum = tcp->check;
        tcp->doff = tcp_doff_csum_update(skb, &csum, tcp->doff,
                                        PPT_DAT_SIZE >> 2);
        /* tcplen pseudo header */
        u16 old_tcplen = htons(ntohs(old_ip_tlen) - (ip->ihl << 2));
        u16 new_tcplen = htons(ntohs(new_ip_tlen) - (ip->ihl << 2));
        csum = incr_csum_replace16(csum, old_tcplen, new_tcplen);

        /* checksum with new ppt timestamp */
        csum = incr_csum_add32(csum, ppt_data.vnf_id | (ppt_data.tstamp << 8));

        /* increase ppt hlen and update csum with new ppt hlen*/
        u8 new_ppt_hlen = ppt_hdr->hlen + PPT_DAT_SIZE;
        csum = incr_csum_replace16(csum,
                                PPT_H_KIND | (ppt_hdr->hlen << 8),
                                PPT_H_KIND | (new_ppt_hlen << 8));
        ppt_hdr->hlen = new_ppt_hlen;

        tcp->check = csum;

        /*  create space and add ppt data */
        struct tcphdr tcp_buf = {};
        struct ppt_hdr_t __ppt_hdr = {};
        bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE,
                        &tcp_buf, TCP_H_SIZE);
        bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE + TCP_H_SIZE,
                        &__ppt_hdr, sizeof(__ppt_hdr));
        bpf_skb_adjust_room(skb, PPT_DAT_SIZE, BPF_ADJ_ROOM_NET, 0);
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE,
                            &tcp_buf, TCP_H_SIZE, 0);
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + TCP_H_SIZE,
                            &__ppt_hdr, sizeof(__ppt_hdr), 0);
        /* add PPT header to the new created space */
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + TCP_H_SIZE + sizeof(__ppt_hdr),
                            &ppt_data, PPT_DAT_SIZE, 0);

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);

        u16 udp_len = ntohs(udp->len);

        struct ppt_hdr_t ppt_hdr = {};
        bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE + udp_len,
                           &ppt_hdr, PPT_H_SIZE);
        if (ppt_hdr.kind != PPT_H_KIND || ppt_hdr.exid != PPT_H_EXID)
            return TC_ACT_OK;

        struct ppt_data_t ppt_data = {};
        ppt_data.vnf_id = VNF_ID;
        ppt_data.tstamp = bpf_ktime_get_ns()/1000 & 0xffffff;

        /* update IP header & checksum */
        u16 old_ip_tlen = ip->tot_len;
        u16 new_ip_tlen = htons(ntohs(old_ip_tlen) + (PPT_DAT_SIZE));
        ip->tot_len = new_ip_tlen;
        ip->check = incr_csum_replace16(ip->check, old_ip_tlen, new_ip_tlen);

        /* new ppt data */
        bpf_skb_change_tail(skb, ETH_H_SIZE + ntohs(new_ip_tlen), 0);
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + udp_len + ppt_hdr.hlen,
                            &ppt_data, PPT_DAT_SIZE, 0);

        /* new ppt hdr len */
        ppt_hdr.hlen += PPT_DAT_SIZE;
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + udp_len,
                            &ppt_hdr, PPT_H_SIZE, 0);

    }

    return TC_ACT_OK;
}

/* replace tstamp with packet processing time */
int ppt_transit_egress(struct __sk_buff *skb)
{
    void* data_end = (void*)(long)skb->data_end;
    void* cursor = (void*)(long)skb->data;

    struct ethhdr *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        CURSOR_ADVANCE(tcp, cursor, sizeof(*tcp), data_end);
        /* check if tcp option exist */
        if (tcp->doff <= TCP_W_OPT_LEN_WORD_MIN)
            return TC_ACT_OK;

        struct ppt_hdr_t *ppt_hdr;
        CURSOR_ADVANCE(ppt_hdr, cursor, PPT_H_SIZE, data_end);
        if (ppt_hdr->kind != PPT_H_KIND || ppt_hdr->exid != PPT_H_EXID)
            return TC_ACT_OK;

        struct ppt_data_t *ppt_data;
        CURSOR_ADVANCE(ppt_data, cursor, PPT_DAT_SIZE, data_end);

        /* replace tstamp with actual pptime */
        u32 pptime = get_pptime(ppt_data->tstamp);
        tcp->check = incr_csum_replace32(tcp->check,
                                        ppt_data->vnf_id | (ppt_data->tstamp << 8),
                                        ppt_data->vnf_id | (pptime << 8));
        ppt_data->tstamp = pptime;

    } else if(ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);

        u16 udp_len = ntohs(udp->len);

        struct ppt_hdr_t ppt_hdr = {};
        bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE + udp_len,
                           &ppt_hdr, PPT_H_SIZE);
        if (ppt_hdr.kind != PPT_H_KIND || ppt_hdr.exid != PPT_H_EXID)
            return TC_ACT_OK;

        /* replace tstamp with actual pptime. the position is the last ppt_data */
        u8 num_ppt_data = (ppt_hdr.hlen - PPT_H_SIZE) >> 2;
        struct ppt_data_t ppt_data = {};
        bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE + ntohs(udp->len) +
                            PPT_H_SIZE + (num_ppt_data - 1) * PPT_DAT_SIZE,
                            &ppt_data, PPT_DAT_SIZE);
        u32 pptime = get_pptime(ppt_data.tstamp);
        ppt_data.tstamp = pptime;

        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + ntohs(udp->len) +
                            PPT_H_SIZE + (num_ppt_data - 1) * PPT_DAT_SIZE,
                            &ppt_data, PPT_DAT_SIZE, 0);
    }

    return TC_ACT_OK;
}

int ppt_sink(struct __sk_buff *skb)
{
    void* data_end = (void*)(long)skb->data_end;
    void* cursor = (void*)(long)skb->data;

    struct ethhdr *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);

    struct ppt_data_t ppt_data_arr[MAX_PPT_DATA] = {0};
    u8 num_ppt_data = 0;

    if(ip->protocol == IPPROTO_TCP){

        struct tcphdr *tcp;
        CURSOR_ADVANCE(tcp, cursor, sizeof(*tcp), data_end);
        /* check if tcp option exist */
        if (tcp->doff <= TCP_W_OPT_LEN_WORD_MIN)
            return TC_ACT_OK;

        struct ppt_hdr_t *ppt_hdr;
        CURSOR_ADVANCE(ppt_hdr, cursor, PPT_H_SIZE, data_end);
        if (ppt_hdr->kind != PPT_H_KIND || ppt_hdr->exid != PPT_H_EXID)
            return TC_ACT_OK;

        /* '>> 2' should be '/PPT_DAT_SIZE'.
        but the division is costly (is it optimized by compiler?)
        */
        num_ppt_data = (ppt_hdr->hlen - PPT_H_SIZE) >> 2;

        struct ppt_data_t *ppt_data;
        for (u8 i = 0; i < num_ppt_data && i < MAX_PPT_DATA; i++){
            CURSOR_ADVANCE(ppt_data, cursor, PPT_DAT_SIZE, data_end);
            ppt_data_arr[i] = *ppt_data;
        }

        /* restore original packet data */
        /* update IP header & checksum */
        u16 old_ip_tlen = ip->tot_len;
        u16 new_ip_tlen = htons(ntohs(old_ip_tlen) - ppt_hdr->hlen);
        ip->tot_len = new_ip_tlen;
        ip->check = incr_csum_replace16(ip->check, old_ip_tlen, new_ip_tlen);

        /* update TCP header len & checksum */
        u16 csum = tcp->check;
        tcp->doff = tcp_doff_csum_update(skb, &csum, tcp->doff,
                                        -(ppt_hdr->hlen >> 2));
        /* tcplen pseudo header */
        u16 old_tcplen = htons(ntohs(old_ip_tlen) - (ip->ihl << 2));
        u16 new_tcplen = htons(ntohs(new_ip_tlen) - (ip->ihl << 2));
        csum = incr_csum_replace16(csum, old_tcplen, new_tcplen);

        /* checksum when remove ppt */
        csum = incr_csum_remove32(csum,
                                ((u32) ppt_hdr->kind) |
                                ((u32) ppt_hdr->hlen) << 8 |
                                ((u32) ppt_hdr->exid) << 16);
        for (u8 i = 0; i < num_ppt_data && i < MAX_PPT_DATA; i++){
            csum = incr_csum_remove32(csum, (ppt_data_arr[i].vnf_id | (ppt_data_arr[i].tstamp << 8)));
        }
        tcp->check = csum;

        /* get the actual pptime for the newest (this) VNF
        we do this after csum recalculation because the first ppt_data tstamp
        is modified before submitted to userspace
        */
        ppt_data_arr[0].tstamp = get_pptime(ppt_data_arr[0].tstamp);

        /*  Now we actually remove ppt header */
        struct tcphdr tcp_buf = {};
        bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE,
                        &tcp_buf, TCP_H_SIZE);
        bpf_skb_adjust_room(skb, -(ppt_hdr->hlen), BPF_ADJ_ROOM_NET, 0);
        bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE,
                            &tcp_buf, TCP_H_SIZE, 0);

    } else if(ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);

        /* we need to move to the end of packet with variable len,
           which direct packet access do not support
        */
        struct ppt_hdr_t ppt_hdr = {};
        bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE + ntohs(udp->len),
                           &ppt_hdr, PPT_H_SIZE);
        if (ppt_hdr.kind != PPT_H_KIND || ppt_hdr.exid != PPT_H_EXID)
            return TC_ACT_OK;

        num_ppt_data = (ppt_hdr.hlen - PPT_H_SIZE) >> 2;

        struct ppt_data_t ppt_data_arr[MAX_PPT_DATA] = {0};
        for (u8 i = 0; i < num_ppt_data && i < MAX_PPT_DATA; i++){
            /* because in case of UDP, newest vnf goes to last, thus we read data from back
               so the user space receive the data in the same order of the tcp case.
               << 2 here means * PPT_DAT_SIZE
             */
            bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE + ntohs(udp->len) +
                               PPT_H_SIZE + ((num_ppt_data-1-i) << 2),
                               &(ppt_data_arr[i]), PPT_DAT_SIZE);
        }

        /* get the actual pptime for the newest (this) VNF before submitted to userspace */
        ppt_data_arr[0].tstamp = get_pptime(ppt_data_arr[0].tstamp);

        /* update IP header & checksum */
        u16 old_ip_tlen = ip->tot_len;
        u16 new_ip_tlen = htons(ntohs(old_ip_tlen) - ppt_hdr.hlen);
        ip->tot_len = new_ip_tlen;
        ip->check = incr_csum_replace16(ip->check, old_ip_tlen, new_ip_tlen);

        bpf_skb_change_tail(skb, ETH_H_SIZE + ntohs(new_ip_tlen), 0);
    }

    /* submit to userspace if there is any value exceed the margin */
#ifdef MARGIN
    int k = 0;
    u32 *prev_pptime;
    for (u8 i = 0; i < num_ppt_data && i < MAX_PPT_DATA; i++){
        k = ppt_data_arr[i].vnf_id;
        prev_pptime = tb_prev_pptime.lookup(&k);
        if (unlikely(!prev_pptime))
            return TC_ACT_OK;
        if (ABS(ppt_data_arr[i].tstamp, *prev_pptime) < MARGIN)
            ppt_data_arr[i].tstamp = 0;
        else
            *prev_pptime = ppt_data_arr[i].tstamp;
    }
#endif

    for (u8 i = 0; i < num_ppt_data && i < MAX_PPT_DATA; i++){
        if(ppt_data_arr[i].tstamp > 0)
            ppt_events.perf_submit(skb, &(ppt_data_arr[0]), MAX_PPT_DATA * sizeof(ppt_data_arr[0]));
        break;
    }

    return TC_ACT_OK;
}
