# unmask_jemalloc - De Mysteriis Dom jemalloc
# 
# Copyright (c) 2014 Patroklos Argyroudis <argp at domain census-labs.com>
# Copyright (c) 2014 Chariton Karamitas <huku at domain census-labs.com>
# Copyright (c) 2014 Census, Inc. (http://www.census-labs.com/)

import os
import sys
import warnings

sys.path.append('.')

# import everything from gdbwrap in the current namespace so that the
# global `gdb' object is easily accessible
from gdbwrap import *
import jemalloc
import gdbutil
import rtree

true = True
false = False

# globals
jeheap = jemalloc.jemalloc()
parsed = false
# Minimum allocation alignment is 2^LG_QUANTUM bytes (except tiny size classes
# For x86_64 amd64 this value is 4, for arm is 3
LG_QUANTUM = 4
# sizeof(void *) = 2^LG_SIZEOF_PTR
LG_SIZEOF_PTR = 3
# sizeof(long) = 2^LG_SIZEOF_LONG
LG_SIZEOF_LONG = 3
# Minimum size class to support is 2^LG_TINY_MIN bytes
LG_TINY_MIN = 3
# One page is 2^LG_PAGE bytes
LG_PAGE = 12
# Maximum number of regiions in one run
LG_RUN_MAXREGS = (LG_PAGE - LG_TINY_MIN)
# Maximum bitmap bit count is 2^LG_BITMAP_MAXBITS
LG_BITMAP_MAXBITS = LG_RUN_MAXREGS
LG_SIZEOF_BITMAP = LG_SIZEOF_LONG
# Number of bits per group
LG_BITMAP_GROUP_NBITS = LG_SIZEOF_BITMAP + 3
BITMAP_GROUP_NBITS = 1 << LG_BITMAP_GROUP_NBITS
BITMAP_GROUP_NBITS_MASK = BITMAP_GROUP_NBITS - 1
# Maximum number of groups required to support LG_BITMAP_MAXBITS
# Need to be initialized
BITMAP_GROUPS_MAX = ((1 << LG_BITMAP_MAXBITS) + BITMAP_GROUP_NBITS_MASK) >> LG_BITMAP_GROUP_NBITS


########## internal parsing stuff ##########                

# parse general jemalloc information
def jeparse_general():
    global jeheap

    try:
        jeheap.narenas = gdbutil.to_int(gdb.parse_and_eval('narenas'))
    except RuntimeError:
        print('[unmask_jemalloc] error: symbol narenas not found')
        sys.exit()

    if LG_SIZEOF_PTR == 2 and LG_TINY_MIN == 3 and LG_QUANTUM == 3 and LG_PAGE == 12:
        jeheap.ntbins = 0
        jeheap.nlbins = 32
        jeheap.nbins = 39
        jeheap.NSIZES = 107
    elif LG_SIZEOF_PTR == 2 and LG_TINY_MIN == 3 and LG_QUANTUM == 4 and LG_PAGE == 12:
        jeheap.ntbins = 1
        jeheap.nlbins = 29
        jeheap.nbins = 36
        jeheap.NSIZES = 104
    elif LG_SIZEOF_PTR == 2 and LG_TINY_MIN == 4 and LG_QUANTUM == 4 and LG_PAGE == 12:
        jeheap.ntbins = 0
        jeheap.nlbins = 28
        jeheap.nbins = 35
        jeheap.NSIZES = 103
    elif LG_SIZEOF_PTR == 3 and LG_TINY_MIN == 3 and LG_QUANTUM == 3 and LG_PAGE == 12:
        jeheap.ntbins = 0
        jeheap.nlbins = 32
        jeheap.nbins = 39
        jeheap.NSIZES = 235
    elif LG_SIZEOF_PTR == 3 and LG_TINY_MIN == 3 and LG_QUANTUM == 4 and LG_PAGE == 12:
        jeheap.ntbins = 1
        jeheap.nlbins = 29
        jeheap.nbins = 36
        jeheap.NSIZES = 232
    elif LG_SIZEOF_PTR == 3 and LG_TINY_MIN == 4 and LG_QUANTUM == 4 and LG_PAGE == 12:
        jeheap.ntbins = 0
        jeheap.nlbins = 28
        jeheap.nbins = 35
        jeheap.NSIZES = 231
    else:
        print("[unmask_jemalloc] error: configuation not specified!")
        sys.exit()

    # usually 1<<21
    jeheap.chunk_size = gdbutil.to_int(gdb.parse_and_eval('je_chunksize'))

# parse jemalloc configuration options
def jeparse_options():
    global jeheap    
    
    opt_tcache = gdb.parse_and_eval('je_opt_tcache')
    if opt_tcache != 0:
        jeheap.MAGAZINES = true
        
        try:
            expr = 'sizeof(mag_rack_t) + (sizeof(bin_mags_t) * (jeheap.nbins - 1))'
            jeheap.magrack_size = gdbutil.to_int(gdb.parse_and_eval(expr))
        except RuntimeError:
            # standalone variant
            jeheap.STANDALONE = true
            expr = 'sizeof(tcache_t) + (sizeof(tcache_bin_t) * %d)' % (jeheap.nbins - 1)
            jemalloc.magrack_size = gdbutil.to_int(gdb.parse_and_eval(expr))

# parse jemalloc arena information
def jeparse_arenas():
    global jeheap

    jeheap.arenas[:] = []

    for i in range(0, jeheap.narenas):
        current_arena = jemalloc.arena(0, i, [])

        try:
            current_arena.addr = \
                gdbutil.to_int(gdb.parse_and_eval('je_arenas[%d]' % (i)))
        except:
            print('[unmask_jemalloc] error: cannot evaluate je_arenas[%d]') % (i)
            sys.exit()

        for j in range(0, jeheap.nbins):
            nrg        = 0
            run_sz     = 0
            reg_size   = 0
            reg_offset = 0
            end_addr   = 0

            jeheap.STANDALONE = true

            reg_size = gdbutil.to_int(gdb.parse_and_eval('je_arena_bin_info[%d].reg_size' % (j)))
            nrg = gdbutil.to_int(gdb.parse_and_eval('je_arena_bin_info[%d].nregs' % (j)))
            run_sz = gdbutil.to_int(gdb.parse_and_eval('je_arena_bin_info[%d].run_size' % (j)))
            reg_offset = gdbutil.to_int(gdb.parse_and_eval('je_arena_bin_info[%d].reg0_offset' % (j)))

            try:
                expr = 'je_arenas[%d].bins[%d].runcur' % (i, j)
                runcur_addr = runcur = gdbutil.to_int(gdb.parse_and_eval(expr))
                end_addr = runcur_addr + run_sz

                if runcur != 0:
                    expr = 'je_arenas[%d].bins[%d].runcur.nfree' % (i, j)
                    nfree = gdbutil.to_int(gdb.parse_and_eval(expr))
                
                    current_run = \
                        jemalloc.arena_run(runcur, end_addr, run_sz, 0, \
                            int(reg_size), reg_offset, nrg, nfree, [])

                    current_bin = jemalloc.arena_bin(0, j, current_run)
                    current_bin.addr = \
                        gdbutil.to_int(gdb.parse_and_eval('&je_arenas[%d].bins[%d]' % (i, j)))

                    current_arena.bins.append(current_bin)

                else:
                    # no regions for this size class yet, therefore no runcur
                    current_run = jemalloc.arena_run()
                    current_bin = jemalloc.arena_bin(0, j, current_run)
                    current_arena.bins.append(current_bin)

            except RuntimeError:
                current_run = jemalloc.arena_run()
                current_bin = jemalloc.arena_bin(0, j, current_run)
                current_arena.bins.append(current_bin)
                continue

        # add arena to the list of arenas
        jeheap.arenas.append(current_arena)


# parse metadata of current runs and their regions
def jeparse_runs(proc):
    global jeheap

    for i in range(0, len(jeheap.arenas)):
        for j in range(0, len(jeheap.arenas[i].bins)):

            try:
                run_addr = jeheap.arenas[i].bins[j].run.start
                bin_addr = gdbutil.buf_to_le(proc.read_memory(run_addr, jeheap.DWORD_SIZE))
                jeheap.arenas[i].bins[j].run.bin = bin_addr
            except RuntimeError:
                continue

            # delete the run's regions
            jeheap.arenas[i].bins[j].run.regions[:] = []
            
            # the run's regions
            reg0_offset = jeheap.arenas[i].bins[j].run.reg0_offset;
            first_region_addr = reg0_addr = run_addr + reg0_offset

            #regs_mask_bits = \
            #            (jeheap.arenas[i].bins[j].run.total_regions / 8) + 1

            regs_mask_str = \
                gdb.execute('x/%dbt je_arenas[%d].bins[%d].runcur.bitmap' % \
                    (BITMAP_GROUPS_MAX, i, j), to_string = true)

            regs_mask = ''

            for line in regs_mask_str.splitlines():
                line = line[line.find(':') + 1 : line.find('\n')]
                line = line.replace('\n', '')
                line = line.replace('\t', '')
                line = line.replace(' ', '')
                regs_mask += line

            jeheap.arenas[i].bins[j].run.regs_mask = regs_mask

            first_region = jemalloc.region(0, first_region_addr, \
                int(jeheap.arenas[i].bins[j].run.regs_mask[0]))

            addr = first_region.addr

            try:
                first_region.content_preview = \
                    hex(gdbutil.buf_to_le(proc.read_memory(addr, \
                        gdbutil.INT_SIZE))).rstrip('L')
            except RuntimeError:
                continue

            jeheap.arenas[i].bins[j].run.regions.append(first_region)

            for k in range(1, jeheap.arenas[i].bins[j].run.total_regions):
                try:
                    current_region = jemalloc.region(k, 0, \
                        int(jeheap.arenas[i].bins[j].run.regs_mask[k]))
                except:
                    current_region = jemalloc.region(k, 0, 0)

                addr = current_region.addr = \
                    reg0_addr + (k * jeheap.arenas[i].bins[j].run.region_size)
                
                try:
                    current_region.content_preview = \
                        hex(gdbutil.buf_to_le(proc.read_memory(addr, \
                            gdbutil.INT_SIZE))).rstrip('L')
                except:
                    continue

                jeheap.arenas[i].bins[j].run.regions.append(current_region)


# parse all jemalloc chunks
# TODO: THIS FUNCTION IS WRONG!!!!
# TODO: THIS FUNCTION IS WRONG!!!!
# TODO: THIS FUNCTION IS WRONG!!!!
def jeparse_chunks():
    global jeheap

    # delete the chunks' list
    jeheap.chunks[:] = []

    try:
        height = gdbutil.to_int(gdb.parse_and_eval('je_chunks_rtree.height'))

    except:
        print('[unmask_jemalloc] error: cannot parse chunk radix tree')
        sys.exit()
        
    # check if we're running on x86_64
    # TODO: make it global
    if jeheap.DWORD_SIZE == 8:
        dw_fmt = 'g'
    else:
        dw_fmt = 'w'
        
    # insert root node to stack first (on level[0])
    stack = []
    for level in range(0, 3):
        bits = gdbutil.to_int(gdb.parse_and_eval('je_chunks_rtree.levels[%d].bits' % (level)))
        for bit in range(0, bits):
            try:
                subtree = gdbutil.to_int(gdb.parse_and_eval('je_chunks_rtree.levels[%d].subtree[%d]' %(level, bit)))
                print(subtree)
                if subtree == 0:
                    continue
            except:
                continue
    print("fucked!")

    while len(stack):
        (node, node_height) = stack.pop()

        child_cnt = gdbutil.to_int(node.bits)
        dump = gdb.execute('x/%d%sx %#x' % (child_cnt, dw_fmt, node), to_string = true)
        print(dump)
        print('--------')

        for line in dump.split('\n'):
            line = line[line.find(':') + 1:]

            for address in line.split():
                address = int(address, 16)

                if address != 0:
                    # leaf nodes hold pointers to actual values
                    if node_height == height - 1:
                        expr = '((arena_chunk_t *)%#x)->arena' % address
                        arena = gdbutil.to_int(gdb.parse_and_eval(expr))
 
                        exists = false
                        if arena in [i.addr for i in jeheap.arenas]:
                            exists = true

                        if exists:
                            jeheap.chunks.append(jemalloc.arena_chunk(address, arena))
                        else:
                            jeheap.chunks.append(jemalloc.arena_chunk(address))

                    # non-leaf nodes are inserted in the stack
                    else:
                        stack.append((address, node_height + 1))

# parse the metadata of all runs and their regions
def jeparse_all_runs(proc):
    global jeheap

    # number of pages a chunk occupies
    chunk_npages = gdbutil.to_int(gdb.parse_and_eval("je_chunk_npages"))

    # offset of bits in arena_chunk_map_t in double words
    bitmap_offset = \
        gdbutil.offsetof('arena_chunk_map_bits_t', 'bits') / jeheap.DWORD_SIZE

    # number of double words occupied by an arena_chunk_map_t
    chunk_map_dwords = (bitmap_offset / jeheap.DWORD_SIZE) + 1

    # prefix to use in gdb's examine command
    if jeheap.DWORD_SIZE == 8:
        dword_fmt = 'g'
    else:
        dword_fmt = 'w'

    # the 12 least significant bits of each bitmap entry hold
    # various flags for the corresponding run
    flags_mask = (1 << 13) - 1

    # delete the heap's runs' array
    jeheap.runs[:] = []

    for chunk in jeheap.chunks:
        if not chunk.arena:
            continue

        try:
            # parse the whole map at once to avoid gdb delays
            expr = 'x/%d%sx ((arena_chunk_t *)%#x)->map_bits' % \
                (chunk_npages * chunk_map_dwords, dword_fmt, chunk.addr)
        except:
            print('[unmask_jemalloc] error: cannot read bitmap from chunk %#x' % (chunk.addr))
            sys.exit()

        lines = (gdb.execute(expr, to_string = true)).split('\n')

        dwords = []
        i = 0

        for line in lines:
            dwords += [int(dw, 16) for dw in line[line.find(':') + 1:].split()]

        bitmap = [dwords[i] for i in range(int(bitmap_offset), \
                int(len(dwords)), int(bitmap_offset + 1))]

        # traverse the bitmap
        for mapelm in bitmap:
            flags = mapelm & flags_mask

            # flags == 1 means the chunk is small and the rest of the bits
            # hold the actual run address
            if flags == 1:
                addr = mapelm & ~flags_mask
                size = gdbutil.get_page_size()

            # flags = 3 indicates a large chunk; calculate the run's address
            # directly from the map element index and extract the run's size 
            elif flags == 3:
                addr = chunk.addr + i * gdbutil.get_page_size()
                size = mapelm & ~flags_mask

            # run is not allocated? skip it
            else:
                continue
    
            if addr not in [r.start for r in jeheap.runs]:
                # XXX: we need to parse run headers here with a
                #      dedicated function
                new_run = jemalloc.arena_run(addr, 0, size, 0, 0, 0, 0, 0, [])
                jeheap.runs.append(new_run)

# our old workhorse, now broken in pieces
def jeparse(proc):
    global jeheap
    global parsed

    parsed = false
    print('[unmask_jemalloc] parsing structures from memory...')

    jeparse_general()
    jeparse_options()
    jeparse_arenas()
    jeparse_runs(proc)
    jeparse_chunks()
    jeparse_all_runs(proc)

    parsed = true
    print('[unmask_jemalloc] structures parsed')


########## exported gdb commands ##########

class jemalloc_help(gdb.Command):
    '''Details about the commands provided by unmask_jemalloc'''

    def __init__(self):
        gdb.Command.__init__(self, 'jehelp', gdb.COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        print('[unmask_jemalloc] De Mysteriis Dom jemalloc')
        print('[unmask_jemalloc] %s\n' % (jemalloc.VERSION))
        print('[unmask_jemalloc] available commands:')
        print('[unmask_jemalloc]   jechunks               : dump info on all available chunks')
        print('[unmask_jemalloc]   jearenas               : dump info on jemalloc arenas')
        print('[unmask_jemalloc]   jeruns [-c]            : dump info on jemalloc runs (-c for current runs only)')
        print('[unmask_jemalloc]   jebins                 : dump info on jemalloc bins')
        print('[unmask_jemalloc]   jeregions <size class> : dump all current regions of the given size class')
        print('[unmask_jemalloc]   jesearch [-c] <hex>    : search the heap for the given hex value (-c for current runs only)')
        print('[unmask_jemalloc]   jedump [filename]      : dump all available info to screen (default) or file')
        print('[unmask_jemalloc]   jeparse                : (re)parse jemalloc structures from memory')
        print('[unmask_jemalloc]   jeversion              : output version number')
        print('[unmask_jemalloc]   jehelp                 : this help message')


class jemalloc_version(gdb.Command):
    '''Output version number'''

    def __init__(self):
        gdb.Command.__init__(self, 'jeversion', gdb.COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        print('[unmask_jemalloc] %s' % (jemalloc.VERSION))


class jemalloc_parse(gdb.Command):
    '''Parse jemalloc structures from memory'''

    def __init__(self):
        gdb.Command.__init__(self, 'jeparse', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        jeparse(self.proc)


class jemalloc_dump(gdb.Command):
    '''Dump all available jemalloc info to screen (default) or to file'''

    def __init__(self):
        gdb.Command.__init__(self, 'jedump', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        global jeheap

        if arg == '':
            print('[unmask_jemalloc] dumping all jemalloc info to screen')
        else:
            print('[unmask_jemalloc] dumping all jemalloc info to file %s' % (arg))

            if os.path.exists(arg):
                print('[unmask_jemalloc] error: file %s already exists' % (arg))
                return

            try:
                sys.stdout = open(arg, 'w')
            except:
                print('[unmask_jemalloc] error opening file %s for writing' % (arg))
            
        if parsed == false:
            jeparse(self.proc)

        # general jemalloc info
        print(jeheap)
        print('')

        # info on chunks
        for chunk in jeheap.chunks:
            print(chunk)
            
        print('')

        # info on arenas
        for i in range(0, len(jeheap.arenas)):
            print(jeheap.arenas[i])
            
            print('')

            # info on current runs and bins
            for j in range(0, len(jeheap.arenas[i].bins)):
                print(jeheap.arenas[i].bins[j].run)
                print(jeheap.arenas[i].bins[j])

                # info on current regions
                for k in range(0, len(jeheap.arenas[i].bins[j].run.regions)):
                    print('[unmask_jemalloc] [region %03d] [%#x]' % \
                        (k, jeheap.arenas[i].bins[j].run.regions[k].addr))

                print('')

        # reset stdout
        if arg != '':
            sys.stdout = sys.__stdout__


class jemalloc_chunks(gdb.Command):
    '''Dump info on all available chunks'''

    def __init__(self):
        gdb.Command.__init__(self, 'jechunks', gdb.COMMAND_OBSCURE)
       
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        global jeheap

        if parsed == false:
            jeparse(self.proc)

        for chunk in jeheap.chunks:
            print(chunk)


class jemalloc_arenas(gdb.Command):
    '''Dump info on jemalloc arenas'''

    def __init__(self):
        gdb.Command.__init__(self, 'jearenas', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        global jeheap

        if parsed == false:
            jeparse(self.proc)

        print(jeheap)


class jemalloc_runs(gdb.Command):
    '''Dump info on jemalloc runs'''

    def __init__(self):
        gdb.Command.__init__(self, 'jeruns', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        global jeheap

        if parsed == false:
            jeparse(self.proc)

        arg = arg.split()
        if len(arg) >= 1 and arg[0] == '-c':
            current_runs = true
        else:
            current_runs = false

        if current_runs == true:
            print('[unmask_jemalloc] listing current runs only')

            for i in range(0, len(jeheap.arenas)):
                print(jeheap.arenas[i])
    
                for j in range(0, len(jeheap.arenas[i].bins)):
                    print(jeheap.arenas[i].bins[j].run)

        else:
            print('[unmask_jemalloc] listing all allocated runs')

            total_runs = len(jeheap.runs)
            print('[unmask_jemalloc] [total runs %d]' % (total_runs))

            for i in range(0, total_runs):
                print('[unmask_jemalloc] [run %#x] [size %07d]' % \
                    (jeheap.runs[i].start, jeheap.runs[i].size))


class jemalloc_bins(gdb.Command):
    '''Dump info on jemalloc bins'''

    def __init__(self):
        gdb.Command.__init__(self, 'jebins', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        global jeheap

        if parsed == false:
            jeparse(self.proc)

        for i in range(0, len(jeheap.arenas)):
            print(jeheap.arenas[i])

            for j in range(0, len(jeheap.arenas[i].bins)):
                print(jeheap.arenas[i].bins[j])


class jemalloc_regions(gdb.Command):
    '''Dump all current regions of the given size class'''

    def __init__(self):
        gdb.Command.__init__(self, 'jeregions', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        global jeheap

        if arg == '':
            print('[unmask_jemalloc] usage: jeregions <size class>')
            print('[unmask_jemalloc] for example: jeregions 1024')
            return

        if parsed == false:
            jeparse(self.proc)

        size_class = int(arg)

        print('[unmask_jemalloc] dumping all regions of size class %d' % (size_class))
        found = false

        for i in range(0, len(jeheap.arenas)):
            for j in range(0, len(jeheap.arenas[i].bins)):
                
                if jeheap.arenas[i].bins[j].run.region_size == size_class:
                    found = true
                    print(jeheap.arenas[i].bins[j].run)
                    
                    # the bitmask of small-sized runs is too big to display
                    # print '[unmask_jemalloc] [regs_mask %s]' % (jeheap.arenas[i].bins[j].run.regs_mask)

                    for k in range(0, len(jeheap.arenas[i].bins[j].run.regions)):
                        print(jeheap.arenas[i].bins[j].run.regions[k])

        if found == false:
            print('[unmask_jemalloc] no regions found for size class %d' % (size_class))


class jemalloc_search(gdb.Command):
    '''Search the jemalloc heap for the given hex value'''

    def __init__(self):
        gdb.Command.__init__(self, 'jesearch', gdb.COMMAND_OBSCURE)

        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        global jeheap

        if arg == '':
            print('[unmask_jemalloc] usage: jesearch [-c] <hex value>')
            print('[unmask_jemalloc] Use -c to search current runs only')
            print('[unmask_jemalloc] for example: jesearch 0x41424344')
            return

        arg = arg.split()
        if len(arg) >= 2 and arg[0] == '-c':
            current_runs = true
            search_for = arg[1]
        else:
            current_runs = false
            search_for = arg[0]

        if parsed == false:
            jeparse(self.proc)

        results = []
        found = false

        if current_runs == true:
            print('[unmask_jemalloc] searching all current runs for %s' % (search_for))
    
            for i in range(0, len(jeheap.arenas)):
                for j in range(0, len(jeheap.arenas[i].bins)):
                    try:
                        out_str = gdb.execute('find %#x, %#x, %s' % \
                            (jeheap.arenas[i].bins[j].run.start, \
                            jeheap.arenas[i].bins[j].run.end, \
                            search_for), \
                            to_string = true)
                    except:
                        continue
    
                    str_results = out_str.split('\n')
    
                    for str_result in str_results:
                        if str_result.startswith('0x'):
                            found = true
                            results.append((str_result, jeheap.arenas[i].bins[j].run.start))
        else:
            print('[unmask_jemalloc] searching all chunks for %s' % (search_for))

            for chunk in jeheap.chunks:
                try:
                    out_str = gdb.execute('find %#x, %#x, %s' % \
                        (chunk.addr, chunk.addr + jeheap.chunk_size, search_for), \
                        to_string = true)
                except:
                    continue

                str_results = out_str.split('\n')
    
                for str_result in str_results:
                    if str_result.startswith('0x'):
                        found = true
                        results.append((str_result, chunk.addr))

        if found == false:
            print('[unmask_jemalloc] value %s not found' % (search_for))
            return

        for (what, where) in results:
            if current_runs == true:
                print('[unmask_jemalloc] found %s at %s (run %#x)' % \
                    (search_for, what, where))
            else:
                print('[unmask_jemalloc] found %s at %s (chunk %#x)' % \
                    (search_for, what, where))


# required for classes that implement gdb commands
jemalloc_parse()
jemalloc_dump()
jemalloc_chunks()
jemalloc_arenas()
jemalloc_runs()
jemalloc_bins()
jemalloc_regions()
jemalloc_search()
jemalloc_help()
jemalloc_version()

# EOF
