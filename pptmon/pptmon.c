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

#include <linux/if_ether.h>
#include <linux/in.h>
#include <uapi/linux/pkt_cls.h>
#include <bcc/proto.h>
#include <net/checksum.h>

#define TCP_OPT_LEN_WORD_MAX 15
#define PPT_H_SIZE_WORD 3
#define PPT_H_SIZE (PPT_H_SIZE_WORD << 2)
/* use experimental tcp option kind */
#define PPT_H_KIND 254
#define PPT_H_EXID 0x0
#define PPT_H_ONLY (PPT_H_KIND | PPT_H_SIZE << 8 | PPT_H_EXID << 16)

#define ETH_H_SIZE sizeof(struct ethernet_t)
#define IP_H_SIZE sizeof(struct ip_t)
#define TCP_H_SIZE sizeof(struct tcp_t)
#define IPTCP_H_SIZE (IP_H_SIZE + TCP_H_SIZE)

#define offset_of(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#define IP_CSUM_OFF (ETH_H_SIZE + \
                     offset_of(struct ip_t, hchecksum))
#define TCP_CSUM_OFF (ETH_H_SIZE + IP_H_SIZE + \
                      offset_of(struct tcp_t, cksum))
#define TCP_OFFSET_OFF (ETH_H_SIZE + IP_H_SIZE + 12)
#define PPT_OFF (ETH_H_SIZE + IP_H_SIZE + TCP_H_SIZE)

struct iptcp_t
{
    u8 data[IPTCP_H_SIZE];
} __attribute__((packed));

struct ppt_t
{
    u32 header;
    u64 tstamp;
} __attribute__((packed));

static inline u16 incr_checksum_add16(u16 old_check, u16 new)
{
    u32 sum;
    old_check = ~ntohs(old_check);
    sum = (u32)old_check + new;
    sum = (sum & 0xffff) + (sum >> 16);
    return htons(~((u16)(sum >> 16) + (sum & 0xffff)));
}

static inline u16 incr_checksum_add32(u16 old_check, u32 new)
{
    u32 sum;
    old_check = ~ntohs(old_check);
    sum = (u32)old_check + (new >> 16) + (new & 0xffff);
    sum = (sum & 0xffff) + (sum >> 16);
    return htons(~((u16)(sum >> 16) + (sum & 0xffff)));
}

int mon_ingress(struct __sk_buff *skb)
{
    u8 *cursor = 0;

    struct ethernet_t *ethhdr = cursor_advance(cursor, ETH_H_SIZE);
    if (ethhdr->type != ETH_P_IP)
        return TC_ACT_OK;

    struct ip_t *iphdr = cursor_advance(cursor, IP_H_SIZE);
    if (iphdr->nextp != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcp_t *tcphdr = cursor_advance(cursor, TCP_H_SIZE);

    /* check tcp option condition */
    if (tcphdr->offset > TCP_OPT_LEN_WORD_MAX - PPT_H_SIZE_WORD)
        return TC_ACT_OK;

    /*  We want to create space right after TCP header and before TCP option,
        which bpf_skb_adjust_room does not support yet.
        Thus, we create space right before IP header (which is supported),
        then move the IP and TCP (w/o option) header back to correct position
    */
    struct iptcp_t iptcphdr = {};
    bpf_skb_load_bytes(skb, ETH_H_SIZE, &iptcphdr, IPTCP_H_SIZE);
    bpf_skb_adjust_room(skb, PPT_H_SIZE, BPF_ADJ_ROOM_NET, 0);
    bpf_skb_store_bytes(skb, ETH_H_SIZE, &iptcphdr, IPTCP_H_SIZE, 0);

    /* add PPT header to the new created space */
    struct ppt_t ppthdr = {};
    ppthdr.header = PPT_H_ONLY;
    ppthdr.tstamp = skb->tstamp;
    bpf_skb_store_bytes(skb, ETH_H_SIZE + IPTCP_H_SIZE,
                        &ppthdr, PPT_H_SIZE, 0);

    /* update IP header & checksum */
    u16 old_tlen = iphdr->tlen;
    u16 new_tlen = iphdr->tlen + (PPT_H_SIZE);
    bpf_l3_csum_replace(skb,
                        IP_CSUM_OFF,
                        htons(old_tlen),
                        htons(new_tlen),
                        sizeof(new_tlen));
    iphdr->tlen = new_tlen;

    /* update TCP header len & checksum */
    /* because offset is only 4 bits, we need to expand to 2 bytes
       for checksum calculation, which include offset, reseved, flags
    */
    u16 old_off2flag, new_off2flag;
    bpf_skb_load_bytes(skb,
                       TCP_OFFSET_OFF,
                       &old_off2flag,
                       sizeof(old_off2flag));
    tcphdr->offset = tcphdr->offset + (PPT_H_SIZE_WORD);
    bpf_skb_load_bytes(skb,
                       TCP_OFFSET_OFF,
                       &new_off2flag,
                       sizeof(new_off2flag));
    bpf_l4_csum_replace(skb,
                        TCP_CSUM_OFF,
                        old_off2flag,
                        new_off2flag,
                        sizeof(new_off2flag));
    /* tcplen pseudo header */
    u16 new_tcplen = iphdr->tlen - (iphdr->hlen << 2);
    u16 old_tcplen = new_tcplen - PPT_H_SIZE;
    bpf_l4_csum_replace(skb,
                        TCP_CSUM_OFF,
                        htons(old_tcplen),
                        htons(new_tcplen),
                        sizeof(new_tcplen));

    /* update tcp checksump after adding ppt */
    u16 csum = tcphdr->cksum;
    csum = incr_checksum_add32(csum, PPT_H_ONLY);
    csum = incr_checksum_add32(csum, ppthdr.tstamp & 0xffffffff);
    csum = incr_checksum_add32(csum, ppthdr.tstamp >> 32);
    tcphdr->cksum = csum;

EXIT:
    return TC_ACT_OK;
}


int mon_egress(struct __sk_buff *skb)
{
    bpf_trace_printk("[OUT] :\n");
    return TC_ACT_OK;
}
