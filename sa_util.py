from __future__ import division
import os
import os.path
import sys
import json
from ctypes import *
lib = cdll.LoadLibrary('./binary_analysis/static_analysis.so')
#https://stackoverflow.com/questions/145270/calling-c-c-from-python

curr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG_CTYPE = True
DEBUG = False

# Need to do this conversion cuz dyninst's dataflow analysis
# only uses the full register name ...
# https://stackoverflow.com/questions/15191178/how-do-ax-ah-al-map-onto-eax
# EAX is the full 32-bit value
# AX is the lower 16-bits
# AL is the lower 8 bits
# AH is the bits 8 through 15 (zero-based)
#https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture
reg_map = dict(al='rax',   ah='rax',   ax='rax',   eax='rax',  rax='rax',
               bl='rbx',   bh='rbx',   bx='rbx',   ebx='rbx',  rbx='rbx',
               cl='rcx',   ch='rcx',   cx='rcx',   ecx='rcx',  rcx='rcx',
               dl='rdx',   dh='rdx',   dx='rdx',   edx='rdx',  rdx='rdx',
               sil='rsi',  si='rsi',               esi='rsi',  rsi='rsi',
               dil='rdi',  di='rdi',               edi='rdi',  rdi='rdi',
               bpl='rbp',  bp='rbp',               ebp='rbp',  rbp='rbp',
               spl='rsp',  sp='rsp',               esp='rsp',  rsp='rsp',
               r8b='r8',   r8w='r8',               r8d='r8',   r8='r8',
               r9b='r9',   r9w='r9',               r9d='r9',   r9='r9',
               r10b='r10', r10w='r10',             r10d='r10', r10='r10',
               r11b='r11', r11w='r11',             r11d='r11', r11='r11',
               r12b='r12', r12w='r12',             r12d='r12', r12='r12',
               r13b='r13', r13w='r13',             r13d='r13', r13='r13',
               r14b='r14', r14w='r14',             r14d='r14', r14='r14',
               r15b='r15', r15w='r15',             r15d='r15', r15='r15' )

reg_size_map = dict(al=1,   ah=1, ax=2,   eax=4,  rax=8,
					bl=1,   bh=1, bx=2,   ebx=4,  rbx=8,
					cl=1,   ch=1, cx=2,   ecx=4,  rcx=8,
					dl=1,   dh=1, dx=2,   edx=4,  rdx=8,
					sil=1,        si=2,   esi=4,  rsi=8,
					dil=1,        di=2,   edi=4,  rdi=8,
					bpl=1,        bp=2,   ebp=4,  rbp=8,
					spl=1,        sp=2,   esp=4,  rsp=8,
					r8b=1,        r8w=2,  r8d=4,  r8=8,
					r9b=1,        r9w=2,  r9d=4,  r9=8,
					r10b=1,       r10w=2, r10d=4, r10=8,
					r11b=1,       r11w=2, r11d=4, r11=8,
					r12b=1,       r12w=2, r12d=4, r12=8,
					r13b=1,       r13w=2, r13d=4, r13=8,
					r14b=1,       r14w=2, r14d=4, r14=8,
					r15b=1,       r15w=2, r15d=4, r15=8)

################################################################
#### C function declarations for accessing Dyninst analysis ####
################################################################

def parseLoadsOrStores(json_exprs):
    # TODO, why is it called a read again?
    data_points = []
    visited = set()
    for json_expr in json_exprs:
        insn_addr = None
        if 'insn_addr' in json_expr:
            insn_addr = json_expr['insn_addr']
        read_same_as_write = None
        if 'read_same_as_write' in json_expr:
            read_same_as_write = True if json_expr['read_same_as_write'] == 1 else False
        is_bit_var = None
        if 'is_bit_var' in json_expr:
            is_bit_var = True if json_expr['is_bit_var'] == 1 else False
        bit_operationses = None
        if is_bit_var is True:
            bit_operationses = []
            json_bit_operationses = json_expr['bit_operationses']
            for json_bit_operations in json_bit_operationses:
                bit_operations = []
                for json_bit_operation in json_bit_operations:
                    bit_operations.append(
                        [json_bit_operation['insn_addr'], json_bit_operation['operand'],
                         json_bit_operation['operation']])
                bit_operationses.append(bit_operations)
        func = None
        if 'func' in json_expr:
            func = json_expr['func']
        expr = json_expr['expr']
        expr_str = str(insn_addr) + str(expr)
        if expr_str in visited:
            continue
        visited.add(expr_str)

        if expr != "":
            expr = expr.strip()
            type = expr.split('|')[0]
            expr = expr.split('|')[1]
        else:
            type = "empty"
            print('[warn] no reads found')

        reg = None
        shift = "0"
        off = "0"
        off_reg = None

        #if DEBUG: print("Parsing expression: " + expr)
        expr = expr.strip()
        segs = expr.split('+')
        assert len(segs) >= 1 and len(segs) <= 3, str(expr)
        for seg in segs:
            try:
                int(seg.strip(), 16)
            except:
                continue
            off = seg.strip()
            break

        for seg in segs:
            if '*' in seg:
                continue
            try:
                int(seg.strip(), 16)
            except:
                reg = seg.strip()
                break

        for seg in segs:
            if '*' not in seg:
                continue
            ssegs = seg.split('*')
            assert len(ssegs) == 2, str(expr)

            ri = 0
            ni = 1
            try:
                int(ssegs[1].strip(), 16)
            except:
                ri = 1
                ni = 0

            if reg is not None:
                off_reg = ssegs[ri].strip()
                assert off == "0", str(expr)
                off = ssegs[ni].strip()
            else:
                reg = ssegs[ri].strip()
                shift = ssegs[ni].strip()

        shift = int(shift, 16)
        off = int(off, 16)
        dst = None
        intermediate_def = False
        if 'dst' in json_expr:
            dst = json_expr['dst']
            if "::" in dst:
                dst = dst.split("::")[1]
        if 'intermediate_def' in json_expr:
            intermediate_def = True
        #both shift and offset are in hex form
        if DEBUG: print("Parsing result reg: " + expr_reg + \
                        " shift " + str(shift) + " off " + str(off) + " insn addr: " + str(insn_addr))
        #TODO, in the future use a map instead of a list...
        data_points.append([insn_addr, reg, shift, off, off_reg, 
                            read_same_as_write, is_bit_var, type, func, dst, bit_operationses, intermediate_def])
    return data_points

#FIXME: call instructions insns and not addrs
def get_func_to_callsites(prog):
    print()
    print( "[main] getting all functions' callsites: ")
    # https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    # https://bugs.python.org/issue1701409

    prog_name = c_char_p(str.encode(prog))

    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)

    lib.getCalleeToCallsites(prog_name)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    f = open(os.path.join(curr_dir, 'functionToCallSites_result'))
    json_func_to_callsites_array = json.load(f)
    data_points = {}
    for json_func_to_callsites in json_func_to_callsites_array:
        func_name = json_func_to_callsites['func'] #FIXME unify the field names..
        json_callsites = json_func_to_callsites['callsites']
        callsites = []
        for json_callsite in json_callsites:
            call_insn = json_callsite['insn_addr']
            caller = json_callsite['func_name']
            callsites.append([call_insn, caller])
        data_points[func_name] = callsites
    f.close()

    #if DEBUG_CTYPE: print( "[main] sa returned  " + str(data_points))
    return data_points

#FIXME: call instructions insns and not addrs
def get_mem_writes_to_static_addrs(prog):
    print()
    print( "[main] getting the instructions that write to static addresses: ")
    # https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    # https://bugs.python.org/issue1701409

    prog_name = c_char_p(str.encode(prog))

    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)

    lib.getMemWritesToStaticAddresses(prog_name)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    f = open(os.path.join(curr_dir, 'writesToStaticAddr_result'))
    json_insn_to_writes = json.load(f)
    data_points = {}
    for json_insn_to_write in json_insn_to_writes: #FIXME name better
        insn_addr = json_insn_to_write['insn_addr']
        expr = hex(int(json_insn_to_write['expr'], 16))
        func = json_insn_to_write['func']
        if expr not in data_points:
            data_points[expr] = []
        data_points[expr].append([insn_addr, func])
    f.close()
    #if DEBUG_CTYPE: print("[main] sa returned " + str(len(data_points)) + " results")
    #if DEBUG_CTYPE: print( "[main] sa returned " + str(data_points))

    mem_writes_per_static_write = {}
    f = open(os.path.join(curr_dir, 'nestedWritesToStaticAddr_result'))
    json_writes_per_insn = json.load(f)
    #if DEBUG_CTYPE: print("[main] : sa returned: " + str(json_writes_per_insn))
    for json_writes in json_writes_per_insn:
        if len(json_writes) == 0:
            continue
        insn = json_writes['addr']
        static_write_insn = json_writes['target_addr']
        true_insn_addr = json_writes['true_addr']
        is_loop_insn = json_writes['is_loop_insn']
        func_name = json_writes['func_name']
        src_reg = json_writes['src']
        if DEBUG: print("==> For instruction: " + str(insn) + " @ " + func_name)
        writes = parseLoadsOrStores(json_writes['writes'])

        if static_write_insn not in mem_writes_per_static_write:
            mem_writes_per_static_write[static_write_insn] = []
        mem_writes_per_static_write[static_write_insn].append([insn, func_name, writes, true_insn_addr, src_reg, is_loop_insn])
    f.close()
    #if DEBUG_CTYPE: print( "[main] sa returned " + str(data_points))
    #if DEBUG_CTYPE: print( "[main] sa returned " + str(mem_writes_per_static_write))
    return data_points, mem_writes_per_static_write

#FIXME: call instructions insns and not addrs
def get_mem_writes(insn_to_func, prog):
    print()
    print( "[main] getting the registers written at instructions: ")
    # https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    # https://bugs.python.org/issue1701409

    insn_to_func_json = []
    for pair in insn_to_func:
        insn = pair[0]
        func_name = pair[1]
        insn_to_func_json.append({'addr': insn, 'func_name': func_name})
    json_str = json.dumps(insn_to_func_json)
    addr_to_func_str = c_char_p(str.encode(json_str))
    prog_name = c_char_p(str.encode(prog))

    if DEBUG_CTYPE: print( "[main] addr to func: " + json_str)
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)

    lib.getMemWrites(addr_to_func_str, prog_name)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    mem_writes_per_insn = []
    f = open(os.path.join(curr_dir, 'writesPerInsn_result'))
    json_writes_per_insn = json.load(f)
    if DEBUG_CTYPE: print("[main] : sa returned: " + str(json_writes_per_insn))
    for json_writes in json_writes_per_insn:
        if len(json_writes) == 0:
            continue
        insn = json_writes['addr']
        true_insn_addr = json_writes['true_addr']
        is_loop_insn = json_writes['is_loop_insn']
        func_name = json_writes['func_name']
        src_reg = json_writes['src']
        if "::" in src_reg:
            src_reg = src_reg.split("::")[1]
        if DEBUG: print("==> For instruction: " + str(insn) + " @ " + func_name)
        data_points = parseLoadsOrStores(json_writes['writes'])

        mem_writes_per_insn.append([insn, func_name, data_points, true_insn_addr, src_reg, is_loop_insn])
    f.close()

    if DEBUG_CTYPE: print( "[main] sa returned " + str(mem_writes_per_insn))
    return mem_writes_per_insn

def get_reg_read_or_written(insn_to_func, prog, is_read):
    print()
    print( "[main] getting the registers read or written at instructions: ")

    insn_to_func_json = []
    for pair in insn_to_func:
        insn = pair[0]
        func_name = pair[1]
        insn_to_func_json.append({'addr': insn, 'func_name': func_name})
    json_str = json.dumps(insn_to_func_json)
    addr_to_func_str = c_char_p(str.encode(json_str))
    prog_name = c_char_p(str.encode(prog))

    if DEBUG_CTYPE: print( "[main] addr to func: " + json_str)
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)

    lib.getRegsReadOrWritten(addr_to_func_str, prog_name, is_read)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    reg_read_or_written_per_insn = []
    f = open(os.path.join(curr_dir, 'RegReadOrWrittenPerInsn_result'))
    json_writes_per_insn = json.load(f)
    if DEBUG_CTYPE: print("[main] : sa returned: " + str(json_writes_per_insn))
    for json_writes in json_writes_per_insn:
        if len(json_writes) == 0:
            continue
        insn = json_writes['addr']
        func_name = json_writes['func_name']
        src_reg = json_writes['src']
        if "::" in src_reg:
            src_reg = src_reg.split("::")[1]
        if DEBUG: print("==> For instruction: " + str(insn) + " @ " + func_name)
        reg_read_or_written_per_insn.append([insn, func_name, src_reg])
    f.close()

    if DEBUG_CTYPE: print( "[main] sa returned " + str(reg_read_or_written_per_insn))
    return reg_read_or_written_per_insn

def static_backslices(slice_starts, prog, sa_result_cache):
    print()
    print( "[main] taking static backslices: ")
    # https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    # https://bugs.python.org/issue1701409

    data_points_per_reg = []

    regname_to_reg = {}
    slice_starts_json = []
    for line in slice_starts:
        reg = line[0].lower()
        if reg == "":
            reg_name = reg
        else:
            if reg in reg_map:
                reg = reg_map[reg]
            reg_name = "[x86_64::" + reg + "]"
        regname_to_reg[reg_name] = reg

        addr = str(line[1])
        func = line[2]
        is_bit_var = 0 if line[3] is False else 1
        key = str(reg) + "_" + str(addr) + "_" + str(func) + "_" + str(is_bit_var) + "_" + str(prog)
        if key in sa_result_cache:
            data_points_per_reg.append(sa_result_cache[key])
        else:
            slice_starts_json.append({'reg_name': reg_name, 'addr': addr, 'func_name': func, 'is_bit_var': is_bit_var})
    if len(slice_starts_json) > 0:
        json_str = json.dumps(slice_starts_json)
        slice_starts_str = c_char_p(str.encode(json_str))
        prog_name = c_char_p(str.encode(prog))

        if DEBUG_CTYPE: print( "[main] slice starts: " + json_str)
        if DEBUG_CTYPE: print( "[main] prog: " + prog)

        if DEBUG_CTYPE: print("[main] : " + "Calling C", flush=True)
        lib.backwardSlices(slice_starts_str, prog_name)
        if DEBUG_CTYPE: print( "[main] : Back from C")

        f = open(os.path.join(curr_dir, 'backwardSlices_result'))
        json_loads_per_reg = json.load(f)
        f.close()
        #sa_result_cache[key] = json_loads_per_reg

        if DEBUG_CTYPE: print("[main] : returned: " + str(json_loads_per_reg))
        for json_loads in json_loads_per_reg:
            if len(json_loads) == 0:
                continue
            reg = regname_to_reg[json_loads['reg_name']]
            addr = json_loads['addr']
            func = json_loads['func_name']
            is_bit_var = json_loads['is_bit_var']
            if DEBUG: print("==> For use reg: " + reg + " @ " + str(addr))
            data_points = parseLoadsOrStores(json_loads['reads'])
            result = [reg, addr, data_points]
            key = str(reg) + "_" + str(addr) + "_" + str(func) + "_" + str(is_bit_var) + "_" + str(prog)
            sa_result_cache[key] = result
            data_points_per_reg.append(result)
    #if len(slice_starts_json) > 0:
    #    sa_result_file = os.path.join(curr_dir, 'sa_results.json')
    #    with open(sa_result_file, 'w') as cache_file:
    #        json.dump(sa_result_cache, cache_file)

    for input in data_points_per_reg:
        if DEBUG_CTYPE: print("[main] input " + str(input[0:2]))
        for result in input[2]:
            if DEBUG_CTYPE: print("[main] returned " + str(result))
    return data_points_per_reg

def static_backslice(reg, insn, func, prog):
    print()
    print( "[main] taking a static backslice: ")

    if reg == "":
        reg_name = c_char_p(str.encode(reg))
    else:
        reg_name = c_char_p(str.encode("[x86_64::" + reg + "]"))
    #https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    #https://bugs.python.org/issue1701409
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] reg: "  + reg)
    if DEBUG_CTYPE: print( "[main] addr: " + hex(insn))
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)
    lib.backwardSlice(prog_name, func_name, addr, reg_name)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    f = open(os.path.join(curr_dir, 'backwardSlice_result'))
    json_reads = json.load(f)
    if DEBUG_CTYPE: print("[main] : returned: " + json_reads)
    data_points = parseReads(json_reads)
    f.close()

    if DEBUG_CTYPE: print( "[main] returned " + str(data_points))
    return data_points


'''
def getImmedDom(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + str(prog_name))
    if DEBUG_CTYPE: print( "[main] func: " + str(func_name))
    if DEBUG_CTYPE: print( "[main] addr: " + hex(addr))
    dom = lib.getImmedDom(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] immed dom: " + str(dom))
    return dom
'''


def getImmedDom(insn, func, prog):
    print()
    print( "[main] getting the immediate dominator: ")
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + hex(insn))
    dom = lib.getImmedDom(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] immed dom: " + str(dom))
    return dom

def getAllPredes(insn, func, prog):
    print()
    print( "[main] getting all predecessors: ")
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + hex(insn), flush=True)
    lib.getAllPredes(prog_name, func_name, addr)
    f = open(os.path.join(curr_dir, 'getAllPredes_result'))
    json_bbs = json.load(f)
    f.close()
    if DEBUG_CTYPE: print( "[main] predes: " + str(json_bbs))
    return json_bbs

def getAllBBs(insn, func, prog):
    print()
    print( "[main] getting all basic blocks: ")
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + hex(insn), flush=True)
    lib.getAllBBs(prog_name, func_name, addr)
    f = open(os.path.join(curr_dir, 'getAllBBs_result'))
    json_bbs = json.load(f)
    f.close()
    if DEBUG_CTYPE: print( "[main] bbs: " )#+ str(json_bbs))
    return json_bbs


'''
def getFirstInstrInBB(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + str(prog_name))
    if DEBUG_CTYPE: print( "[main] func: " + str(func_name))
    if DEBUG_CTYPE: print( "[main] addr: " + hex(addr))
    f_insn = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(f_insn))
    return f_insn
'''


def getFirstInstrInBB(insn, func, prog):
    print()
    print( "[main] getting the first instruction in basic block: ")
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + hex(insn))
    f_insn = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(f_insn))
    return f_insn


def getInstrAfter(insn, func, prog):
    print()
    print( "[main] getting the instruction after: ")
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + hex(insn), flush=True)
    f_insn = lib.getInstrAfter(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(f_insn))
    return f_insn


'''
def getLastInstrInBB(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + str(prog_name))
    if DEBUG_CTYPE: print( "[main] func: " + str(func_name))
    if DEBUG_CTYPE: print( "[main] addr: " + hex(addr))
    l_insn = lib.getLastInstrInBB(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(l_insn))
    return l_insn
'''


def getLastInstrInBB(insn, func, prog):
    print()
    print( "[main] getting the last instruction in basic block: ")
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + hex(insn), flush=True)
    l_insn = lib.getLastInstrInBB(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(l_insn))
    return l_insn
