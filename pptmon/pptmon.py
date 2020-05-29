from bcc import BPF
from pyroute2 import IPRoute
import ctypes as ct
import argparse

def ppt_event_handler(ctx, data, size):
    class Event(ct.Structure):
        _fields_ = [("ppt_time", ct.c_uint64)]

    ppt = ct.cast(data, ct.POINTER(Event)).contents
    print(ppt.ppt_time)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--period", default=1000, type=int,
                        help="samping period [ms]. Default to 1000")
    args = parser.parse_args()

    ipr = IPRoute()
    iface = 'ens4'

    bpf_mon = BPF(src_file="pptmon.c", debug=0,
                  cflags=["-w",
                          "-D_PERIOD_NS=%d" % (args.period*1000000)])
    fn_mon_ingress = bpf_mon.load_func("mon_ingress", BPF.SCHED_CLS)
    fn_mon_egress = bpf_mon.load_func("mon_egress", BPF.SCHED_CLS)
    ppt_events = bpf_mon.get_table("ppt_events")

    if_idx = ipr.link_lookup(ifname=iface)[0]
    ipr.tc("add", "clsact", if_idx)

    # tc parent params for ingress and egress are taken from
    # sched_clsact.py example file in pyroute2

    # ingress traffic
    ipr.tc("add-filter", "bpf", if_idx, ":1", fd=fn_mon_ingress.fd,
            name=fn_mon_ingress.name, parent="ffff:fff2",
            direct_action=True)

    # egress traffic
    ipr.tc("add-filter", "bpf", if_idx, ":1", fd=fn_mon_egress.fd,
            name=fn_mon_egress.name, parent="ffff:fff3",
            direct_action=True)

    ppt_events.open_perf_buffer(ppt_event_handler, page_cnt=512)

    print("pptmon is loaded")

    try:
        while True:
            # poll new ppt events
            bpf_mon.kprobe_poll()

    except KeyboardInterrupt:
        pass

    finally:
        ipr.tc("del", "clsact", if_idx)
