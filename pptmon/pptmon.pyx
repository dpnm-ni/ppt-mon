from bcc import BPF
from pyroute2 import IPRoute
from ipaddress import IPv4Address
from influxdb import InfluxDBClient
from time import sleep
import ctypes as ct
import argparse

import ast
import threading

from libc.stdint cimport uintptr_t
from libc.stdio cimport printf
from posix.time cimport clock_gettime, timespec, CLOCK_REALTIME

# Default value
cdef enum: _MAX_PPT_DATA = 1
MAX_PPT_DATA = _MAX_PPT_DATA
idb_dbname = "pptmon"
idb_user = "root"
idb_password = "root"
# unit: second
idb_push_period = 1

# init var
cdef unsigned int data_cnt = 0
idb_client = None
idb_thread = None
exit_flag = threading.Event()
data_lock = threading.Lock()
data = []

def send_to_influxdb():
    global data
    while not exit_flag.is_set():
        sleep(idb_push_period)

        data_lock.acquire()
        data_copy = data
        data = []
        data_lock.release()

        if len(data_copy) > 0:
            idb_client.write_points(points=data_copy, protocol="line")
            print("sent to influxdb: ", len(data_copy))


def ppt_event_handler(ctx, dat, size):
    global data_cnt, data

    ppt_data = <unsigned int*> (<uintptr_t> dat)
    cdef timespec ts
    clock_gettime(CLOCK_REALTIME, &ts)
    cdef double cur_time = ts.tv_sec*1000000000 + ts.tv_nsec

    for i in range(0, _MAX_PPT_DATA):
        # network byte order
        vnf_id = ppt_data[i] & 0xff
        if (vnf_id):
            # printf("%lu\t%u\n", vnf_id, ppt_data[i] >> 8)
            data_cnt = data_cnt + 1
            if idb_client is not None:
                data_lock.acquire()
                data.append(u"%d value=%d %d" %(vnf_id, ppt_data[i] >> 8, cur_time))
                data_lock.release()

def print_num_data_point():
    printf("number of data points: %u\n", data_cnt)
    print(data)

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
    parser.add_argument("--idb-host",
                        help="Set to influxdb host if want to send data to influxdb")
    parser.add_argument("--idb-port", default=8086, type=int,
                        help="influxdb port. Default to 8086")
    parser.add_argument("-m", "--mode", default="source_sink",
                        choices=['source', 'transit', 'sink', 'source_sink'],
                        help="mode to run pptmon. Default to source_sink")

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

    if args.idb_host is not None:
        global idb_client, idb_thread
        idb_client = InfluxDBClient(args.idb_host, args.idb_port, idb_user, idb_password, idb_dbname)
        # create_database do nothing if db is already exist
        idb_client.create_database(idb_dbname)
        idb_thread = threading.Thread(target=send_to_influxdb)

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

    if idb_thread is not None:
        idb_thread.start()

    try:
        if args.mode == "sink" or args.mode == "source_sink":
            print("VNF ID:  PP TIME [us]")
            print("---------------------")
            while True:
                # poll new ppt events
                bpf_mon.perf_buffer_poll()
        else:
            while True:
                sleep(1)

    except KeyboardInterrupt:
        pass

    finally:
        ipr.tc("del", "clsact", inif_idx)
        if (outif_idx != inif_idx):
            ipr.tc("del", "clsact", outif_idx)
        print_num_data_point()
        exit_flag.set()
        if idb_thread is not None:
            idb_thread.join()
