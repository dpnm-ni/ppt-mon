/*
    packet processing time (ppt) as tcp option:
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

#define TCP_OPT_LEN_WORD_MAX 15
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
#define IPTCP_H_SIZE (IP_H_SIZE + TCP_H_SIZE)

#define offset_of(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#define IP_CSUM_OFF (ETH_H_SIZE + \
                     offset_of(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_H_SIZE + IP_H_SIZE + \
                      offset_of(struct tcphdr, check))
#define TCP_OFFSET_OFF (ETH_H_SIZE + IP_H_SIZE + 12)
#define PPT_OFF (ETH_H_SIZE + IP_H_SIZE + TCP_H_SIZE)

#define CURSOR_ADVANCE(_target, _cursor, _len,_data_end) \
    ({  _target = _cursor; _cursor += _len; \
        if(_cursor > _data_end) return XDP_DROP; })

struct iptcp_t
{
    u8 data[IPTCP_H_SIZE];
} __attribute__((packed));

struct ppt_t
{
    u32 header;
    u64 tstamp;
} __attribute__((packed));

static inline u16 incr_checksum_replace16(u16 old_check, u16 old, u16 new){
    u32 sum;
    old_check = ~old_check;
    old = ~old;
    sum = (u32)old_check + old + new;
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return (u16)(~sum & 0xffff);
}

static inline u16 incr_checksum_add16(u16 old_check, u16 new)
{
    u32 sum;
    old_check = ~old_check;
    sum = (u32)old_check + new;
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return (u16)(~sum & 0xffff);
}


static inline u16 incr_checksum_add32(u16 old_check, u32 new)
{
    u32 sum;
    old_check = ~old_check;
    sum = (u32)old_check + (new >> 16) + (new & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return (u16)(~sum & 0xffff);
}


int mon_ingress(struct __sk_buff *skb)
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

    /* check tcp option condition */
    if (tcp->doff > TCP_OPT_LEN_WORD_MAX - PPT_H_SIZE_WORD)
        return TC_ACT_OK;

    /* ppt header */
    struct ppt_t ppthdr = {};
    ppthdr.header = PPT_H_ONLY;
    ppthdr.tstamp = skb->tstamp;


    /*  Because after adjust pkt room, all pointers wil be invalid,
        we need to update ip and tcp header prior
     */
    /* update IP header & checksum */
    u16 old_ip_tlen = ip->tot_len;
    u16 new_ip_tlen = htons(ntohs(old_ip_tlen) + (PPT_H_SIZE));
    ip->tot_len = new_ip_tlen;
    ip->check = incr_checksum_replace16(ip->check, old_ip_tlen, new_ip_tlen);

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

    csum = incr_checksum_replace16(csum, old_off2flag, new_off2flag);

    /* tcplen pseudo header */
    u16 old_tcplen = htons(ntohs(old_ip_tlen) - (ip->ihl << 2));
    u16 new_tcplen = htons(ntohs(new_ip_tlen) - (ip->ihl << 2));
    csum = incr_checksum_replace16(csum, old_ip_tlen, new_ip_tlen);

    /* checksump with new ppt */
    csum = incr_checksum_add32(csum, PPT_H_ONLY);
    csum = incr_checksum_add32(csum, ppthdr.tstamp & 0xffffffff);
    csum = incr_checksum_add32(csum, ppthdr.tstamp >> 32);

    tcp->check = csum;

    /*  Now we actually create space to add ppt header.
        We want to create space right after TCP header and before TCP option,
        which bpf_skb_adjust_room does not support yet.
        Thus, we create space right before IP header (which is supported),
        then move the IP and TCP (w/o option) header back to correct position
    */
    struct iptcp_t iptcp = {};
    bpf_skb_load_bytes(skb, ETH_H_SIZE, &iptcp, IPTCP_H_SIZE);
    bpf_skb_adjust_room(skb, PPT_H_SIZE, BPF_ADJ_ROOM_NET, 0);
    bpf_skb_store_bytes(skb, ETH_H_SIZE, &iptcp, IPTCP_H_SIZE, 0);
    /* add PPT header to the new created space */
    bpf_skb_store_bytes(skb, ETH_H_SIZE + IPTCP_H_SIZE,
                        &ppthdr, PPT_H_SIZE, 0);

    return TC_ACT_OK;
}


int mon_egress(struct __sk_buff *skb)
{
    bpf_trace_printk("[OUT] :\n");
    return TC_ACT_OK;
}
