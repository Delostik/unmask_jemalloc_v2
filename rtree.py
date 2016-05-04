# unmask_jemalloc - De Mysteriis Dom jemalloc
# 
# Copyright (c) 2014 Patroklos Argyroudis <argp at domain census-labs.com>
# Copyright (c) 2014 Chariton Karamitas <huku at domain census-labs.com>
# Copyright (c) 2014 Census, Inc. (http://www.census-labs.com/)

import sys
import warnings
import platform
import resource

sys.path.append('.')

from gdbwrap import *

LG_RTREE_BITS_PER_LEVEL = 4

def rtree_subkey(key, level):
    global LG_SIZEOF_PTR
    bits = gdbutil.to_int(gdb.parse_and_eval('je_chunks_rtree.levels[%d].bits' % (level)))
    cumbits = gdbutil.to_int(gdb.parse_and_eval('je_chunks_rtree.levels[%d].bits' % (level)))
    return ((key >> ((1 << (LG_SIZEOF_PTR+3)) - cumbits)) & ((1 << bits) - 1))

def lg_floor(key):
    global LG_SIZEOF_PTR
    bits = (1 << (LG_SIZEOF_PTR - 1)) << 3
    for i in range(bits-1, -1, -1):
        if key & (1 << i):
            return i
    return 0

def rtree_start_level(key):
    height = gdbutil.to_int(gdb.parse_and_eval('je_chunks_rtree.height'))
    if key == 0:
        return height-1
    return gdbutil.to_int(gdb.parse_and_eval('je_chunks_rtree.start_level[%d]' % (lg_floor(key) >> LG_RTREE_BITS_PER_LEVEL)))
