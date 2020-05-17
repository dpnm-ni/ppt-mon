#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>


int mon_ingress(struct __sk_buff *skb) {

    u8 *cursor = 0;

    bpf_trace_printk("[IN] pkt_type: %d\n", skb->pkt_type);


    EXIT:
    return TC_ACT_OK;
}

int mon_egress(struct __sk_buff *skb) {
    // bpf_trace_printk("[OUT] :\n");
    return TC_ACT_OK;
}
