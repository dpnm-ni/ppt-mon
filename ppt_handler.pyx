from libc.stdint cimport uintptr_t
from libc.stdio cimport printf

cdef enum: _MAX_PPT_DATA = 1
MAX_PPT_DATA = _MAX_PPT_DATA

def ppt_event_handler(ctx, data, size):
    ppt_data = <unsigned int*> (<uintptr_t> data)

    for i in range(0, _MAX_PPT_DATA):
        # network byte order
        vnf_id = ppt_data[i] & 0xff
        if (vnf_id):
            printf("%lu\t%u\n", vnf_id, ppt_data[i] >> 8)
