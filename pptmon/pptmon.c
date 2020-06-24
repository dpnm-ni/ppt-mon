/*
   Packet processing time (ppt) as tcp option:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      TCP header (w/o option)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | PPT_H_KIND    | PPT_H_SIZE    |          PPT_H_EXID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           TSTAMP                              |
   |                                                               |
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
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <net/checksum.h>
#include <linux/version.h>

/* BCC does not accept separated custom header file,
   so we need to put everything in one file
 */

#define SAMPLE_PERIOD_NS _PERIOD_NS

#define TCP_W_OPT_LEN_WORD_MAX 15
#define TCP_W_OPT_LEN_WORD_MIN 5
#define PPT_H_SIZE_WORD 3
#define PPT_H_SIZE (PPT_H_SIZE_WORD << 2)
/* use experimental tcp option kind */
#define PPT_H_KIND 254
/* network byte order */
#define PPT_H_EXID 0x0000
#define PPT_H_ONLY (PPT_H_KIND | PPT_H_SIZE << 8 | PPT_H_EXID << 16)

#define ETH_H_SIZE sizeof(struct ethhdr)
#define IP_H_SIZE sizeof(struct iphdr)
#define TCP_H_SIZE sizeof(struct tcphdr)

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


/* structs */

struct g_vars_t {
    u64 prev_tstamp;
};

struct ppthdr
{
    u32 header;
    u64 tstamp;
} __attribute__((packed));

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


/* BPF maps */

/* Lower kernel versions do not support BPF_F_MMAPABLE */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,5,0)
BPF_F_TABLE("array", int, struct g_vars_t, tb_g_vars, 1, 0);
#else
BPF_F_TABLE("array", int, struct g_vars_t, tb_g_vars, 1, BPF_F_MMAPABLE);
#endif

BPF_PERF_OUTPUT(ppt_events);

/* main functions */

int mon_ingress(struct __sk_buff *skb)
{
    /* check sampling period before doing anything */

    int k = 0;

    struct g_vars_t *g_vars = tb_g_vars.lookup(&k);
    if (unlikely(!g_vars))
        return TC_ACT_OK;

    if (get_now_ns(skb) < g_vars->prev_tstamp + SAMPLE_PERIOD_NS)
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
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp;
    CURSOR_ADVANCE(tcp, cursor, sizeof(*tcp), data_end);

    /* check if there is enough space */
    if (tcp->doff > TCP_W_OPT_LEN_WORD_MAX - PPT_H_SIZE_WORD)
        return TC_ACT_OK;

    /* ppt header */
    struct ppthdr ppt = {};
    ppt.header = PPT_H_ONLY;
    ppt.tstamp = htonll(bpf_ktime_get_ns());


    /*  Because after adjust pkt room, all pointers wil be invalid,
        we need to update ip and tcp header prior
     */
    /* update IP header & checksum */
    u16 old_ip_tlen = ip->tot_len;
    u16 new_ip_tlen = htons(ntohs(old_ip_tlen) + (PPT_H_SIZE));
    ip->tot_len = new_ip_tlen;
    ip->check = incr_csum_replace16(ip->check, old_ip_tlen, new_ip_tlen);

    /* update TCP header len & checksum */
    /* because offset is only 4 bits, we need to expand to 2 bytes
       for checksum calculation, which include offset, reseved, flags
     */
    u16 csum = tcp->check;
    u16 old_off2flag, new_off2flag;
    bpf_skb_load_bytes(skb,
                       TCP_OFFSET_OFF,
                       &old_off2flag,
                       sizeof(old_off2flag));

    tcp->doff = tcp->doff + (PPT_H_SIZE_WORD);

    bpf_skb_load_bytes(skb,
                       TCP_OFFSET_OFF,
                       &new_off2flag,
                       sizeof(new_off2flag));

    csum = incr_csum_replace16(csum, old_off2flag, new_off2flag);

    /* tcplen pseudo header */
    u16 old_tcplen = htons(ntohs(old_ip_tlen) - (ip->ihl << 2));
    u16 new_tcplen = htons(ntohs(new_ip_tlen) - (ip->ihl << 2));
    csum = incr_csum_replace16(csum, old_tcplen, new_tcplen);

    /* checksum with new ppt */
    csum = incr_csum_add32(csum, PPT_H_ONLY);
    csum = incr_csum_add32(csum, ppt.tstamp & 0xffffffff);
    csum = incr_csum_add32(csum, ppt.tstamp >> 32);

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
    bpf_skb_adjust_room(skb, PPT_H_SIZE, BPF_ADJ_ROOM_NET, 0);
    bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE,
                        &tcp_buf, TCP_H_SIZE, 0);
    /* add PPT header to the new created space */
    bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + TCP_H_SIZE,
                        &ppt, PPT_H_SIZE, 0);

    /* update g_vars after everything is done */
    g_vars->prev_tstamp = get_now_ns(skb);

    return TC_ACT_OK;
}


int mon_egress(struct __sk_buff *skb)
{
    void* data_end = (void*)(long)skb->data_end;
    void* cursor = (void*)(long)skb->data;

    struct ethhdr *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp;
    CURSOR_ADVANCE(tcp, cursor, sizeof(*tcp), data_end);
    /* check if tcp option exist */
    if (tcp->doff <= TCP_W_OPT_LEN_WORD_MIN)
        return TC_ACT_OK;

    struct ppthdr *ppt;
    CURSOR_ADVANCE(ppt, cursor, sizeof(*ppt), data_end);
    if (ppt->header != PPT_H_ONLY)
        return TC_ACT_OK;


    /* extract and process ppt data */
    u64 ppt_time = bpf_ktime_get_ns() - ntohll(ppt->tstamp);
    ppt_events.perf_submit(skb, &ppt_time, sizeof(ppt_time));

    /* restore original packet data */
    /*  Because after adjust pkt room, all pointers wil be invalid,
        we need to update ip and tcp header prior
     */
    /* update IP header & checksum */
    u16 old_ip_tlen = ip->tot_len;
    u16 new_ip_tlen = htons(ntohs(old_ip_tlen) - (PPT_H_SIZE));
    ip->tot_len = new_ip_tlen;
    ip->check = incr_csum_replace16(ip->check, old_ip_tlen, new_ip_tlen);

    /* update TCP header len & checksum */
    /* because offset is only 4 bits, we need to expand to 2 bytes
       for checksum calculation, which include offset, reseved, flags
     */
    u16 csum = tcp->check;
    u16 old_off2flag, new_off2flag;
    bpf_skb_load_bytes(skb,
                       TCP_OFFSET_OFF,
                       &old_off2flag,
                       sizeof(old_off2flag));

    tcp->doff = tcp->doff - (PPT_H_SIZE_WORD);

    bpf_skb_load_bytes(skb,
                       TCP_OFFSET_OFF,
                       &new_off2flag,
                       sizeof(new_off2flag));

    csum = incr_csum_replace16(csum, old_off2flag, new_off2flag);

    /* tcplen pseudo header */
    u16 old_tcplen = htons(ntohs(old_ip_tlen) - (ip->ihl << 2));
    u16 new_tcplen = htons(ntohs(new_ip_tlen) - (ip->ihl << 2));
    csum = incr_csum_replace16(csum, old_tcplen, new_tcplen);

    /* checksum when remove ppt */
    csum = incr_csum_remove32(csum, PPT_H_ONLY);
    csum = incr_csum_remove32(csum, ppt->tstamp & 0xffffffff);
    csum = incr_csum_remove32(csum, ppt->tstamp >> 32);

    tcp->check = csum;

    /*  Now we actually remove ppt header.
        bpf_skb_adjust_room allows removing space right after eth header.
        Thus, we move iptcp header right by PPT_H_SIZE, and then remove
        the space from ETH_H_SIZE to ETH_H_SIZE + PPT_H_SIZE
    */
    struct tcphdr tcp_buf = {};
    bpf_skb_load_bytes(skb, ETH_H_SIZE + IP_H_SIZE,
                       &tcp_buf, TCP_H_SIZE);
    bpf_skb_store_bytes(skb, ETH_H_SIZE + IP_H_SIZE + PPT_H_SIZE,
                        &tcp_buf, TCP_H_SIZE, 0);
    bpf_skb_adjust_room(skb, -PPT_H_SIZE, BPF_ADJ_ROOM_NET, 0);

    return TC_ACT_OK;
}
