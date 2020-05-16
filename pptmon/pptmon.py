import time
import json
from bcc import BPF
from pyroute2 import IPRoute

def main():
    ipr = IPRoute()
    iface = 'ens4'

    bpf_mon = BPF(src_file="pptmon.c", debug=0)
    fn_mon_ingress = bpf_mon.load_func("mon_ingress", BPF.SCHED_CLS)
    fn_mon_egress = bpf_mon.load_func("mon_egress", BPF.SCHED_CLS)

    iface_idx = ipr.link_lookup(ifname=iface)[0]
    ipr.tc("add", "clsact", iface_idx)

    # example: https://github.com/svinota/pyroute2/blob/master/pyroute2/netlink/rtnl/tcmsg/sched_clsact.py
    # ingress traffic
    ipr.tc("add-filter", "bpf", iface_idx, ":1", fd=fn_mon_ingress.fd, name=fn_mon_ingress.name,
           parent="ffff:fff2", classid=1, direct_action=True)

    # egress traffic
    ipr.tc("add-filter", "bpf", iface_idx, ":1", fd=fn_mon_egress.fd, name=fn_mon_egress.name,
           parent="ffff:fff3", classid=1, direct_action=True)

    print("pptmon is loaded")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        ipr.tc("del", "clsact", iface_idx)
