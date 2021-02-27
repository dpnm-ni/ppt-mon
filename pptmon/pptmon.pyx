from bcc import BPF
from pyroute2 import IPRoute
from ipaddress import IPv4Address
import ctypes as ct
import argparse
import time
import ast

# import
from libc.stdint cimport uintptr_t
from libc.stdio cimport printf

cdef enum: _MAX_PPT_DATA = 1
MAX_PPT_DATA = _MAX_PPT_DATA
cdef unsigned int data_cnt = 0

def ppt_event_handler(ctx, data, size):
    global data_cnt
    ppt_data = <unsigned int*> (<uintptr_t> data)

    for i in range(0, _MAX_PPT_DATA):
        # network byte order
        vnf_id = ppt_data[i] & 0xff
        if (vnf_id):
            # printf("%lu\t%u\n", vnf_id, ppt_data[i] >> 8)
            data_cnt = data_cnt + 1

def print_num_data_point():
    printf("number of data points: %u\n", data_cnt)

def set_tb_val(tb, key, val):
    k = tb.Key(key)
    leaf = tb.Leaf(val)
    tb[k] = leaf


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-p", "--sample-period", default=1000, type=int,
                        help="samping period [ms]. Default to 1000")
    parser.add_argument("-i", "--inif", default="ens4",
                        help="packet in interface. Default to ens4")
    parser.add_argument("-o", "--outif",
                        help="packet out interface. Default similar to inif")
    parser.add_argument("--src-ip", help="flow source ip. Default match all")
    parser.add_argument("--dst-ip", help="flow dest ip. Default match all")
    parser.add_argument("--src-port", type=int, help="flow source port. Default match all")
    parser.add_argument("--dst-port", type=int, help="flow dest port. Default match all")
    parser.add_argument("--proto", help="flow protocol. Default match tcp and udp")
    parser.add_argument("-I", "--vnf-id", default=1, type=int,
                        choices=range(1, 256), metavar="[1, 255]",
                        help="VNF ID, between 1 and 255. Default to 1")
    parser.add_argument("-M", "--margins",
                        help="if |current_var - last_var| > margin, then generate new event\n"
                            "the input format is '[(vnf_id_1, margin_1), ..., (vnf_id_N, margin_N)]'\n"
                            "e.g.,: '[(1, 50), (2, 10)]'. Default margin is 0")
    parser.add_argument("-P", "--update-period", default=1000, type=int,
                        help="if margin is used, this set the period [ms] to force updating new value")
    parser.add_argument("-m", "--mode", default="source_sink",
                        choices=['source', 'transit', 'sink', 'source_sink'],
                        help="mode to run pptmon")
    args = parser.parse_args()

    cflags = ["-w",
            "-DVNF_ID=%d" % args.vnf_id,
            "-DMAX_PPT_DATA=%d" % MAX_PPT_DATA,
            "-DUPDATE_PERIOD_NS=%d" % (args.update_period*1000000),
            "-DSAMPLE_PERIOD_NS=%d" % (args.sample_period*1000000)]
    if args.outif is None:
        args.outif = args.inif
    if args.src_ip is not None:
        cflags.append("-DSRC_IP=%d" % int(IPv4Address(args.src_ip)))
    if args.src_port is not None:
        cflags.append("-DSRC_PORT=%d" % args.src_port)
    if args.dst_ip is not None:
        cflags.append("-DDST_IP=%d" % int(IPv4Address(args.dst_ip)))
    if args.dst_port is not None:
        cflags.append("-DDST_PORT=%d" % args.dst_port)
    if args.proto is None:
        cflags.append("-DFILTER_TCP")
        cflags.append("-DFILTER_UDP")
    elif args.proto == "tcp":
        cflags.append("-DFILTER_TCP")
    elif args.proto == "udp":
        cflags.append("-DFILTER_UDP")
    else:
        print("unsupported protocol: %s" %(args.proto))
        exit(1)
    if args.margins is not None:
        cflags.append("-DMARGIN")

    bpf_mon = BPF(src_file="pptmon.c", debug=0, cflags=cflags)
    fn_ppt_source = bpf_mon.load_func("ppt_source", BPF.SCHED_CLS)
    fn_ppt_transit_ingress = bpf_mon.load_func("ppt_transit_ingress", BPF.SCHED_CLS)
    fn_ppt_transit_egress = bpf_mon.load_func("ppt_transit_egress", BPF.SCHED_CLS)
    fn_ppt_sink = bpf_mon.load_func("ppt_sink", BPF.SCHED_CLS)
    ppt_events = bpf_mon.get_table("ppt_events")

    if args.margins is not None:
        tb_margins = bpf_mon.get_table("tb_margins")
        for margin in ast.literal_eval(args.margins):
            set_tb_val(tb_margins, margin[0], margin[1])

    ipr = IPRoute()
    inif_idx = ipr.link_lookup(ifname=args.inif)[0]
    outif_idx = ipr.link_lookup(ifname=args.outif)[0]
    ipr.tc("add", "clsact", inif_idx)
    if (outif_idx != inif_idx):
        ipr.tc("add", "clsact", outif_idx)

    # tc parent params for ingress and egress are taken from
    # sched_clsact.py example file in pyroute2

    # ingress traffic
    if args.mode == "source" or args.mode == "source_sink":
        ipr.tc("add-filter", "bpf", inif_idx, ":1", fd=fn_ppt_source.fd,
                name=fn_ppt_source.name, parent="ffff:fff2",
                direct_action=True)
    else: # mode is transit or sink
        ipr.tc("add-filter", "bpf", inif_idx, ":1", fd=fn_ppt_transit_ingress.fd,
                name=fn_ppt_transit_ingress.name, parent="ffff:fff2",
                direct_action=True)

    # egress traffic
    if args.mode == "sink" or args.mode == "source_sink":
        ipr.tc("add-filter", "bpf", outif_idx, ":1", fd=fn_ppt_sink.fd,
                name=fn_ppt_sink.name, parent="ffff:fff3",
                direct_action=True)
    else: # mode is source or transit
        ipr.tc("add-filter", "bpf", outif_idx, ":1", fd=fn_ppt_transit_egress.fd,
                name=fn_ppt_transit_egress.name, parent="ffff:fff3",
                direct_action=True)


    ppt_events.open_perf_buffer(ppt_event_handler, page_cnt=2048)

    print("pptmon is loaded\n")

    try:
        if args.mode == "sink" or args.mode == "source_sink":
            print("VNF ID:  PP TIME [us]")
            print("---------------------")
            while True:
                # poll new ppt events
                bpf_mon.kprobe_poll()
        else:
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        pass

    finally:
        print_num_data_point()
        ipr.tc("del", "clsact", inif_idx)
        if (outif_idx != inif_idx):
            ipr.tc("del", "clsact", outif_idx)
