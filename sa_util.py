from __future__ import division
import os
import os.path
import sys
import json
import time
from ctypes import *
import subprocess
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
        off1 = None
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
                if ssegs[ni].strip() != "1":
                    #assert off == "0", str(expr)
                    if off == "0":
                        off = ssegs[ni].strip()
                    else:
                        off1 = off
                        off = ssegs[ni].strip()
            else:
                reg = ssegs[ri].strip()
                shift = ssegs[ni].strip()

        shift = int(shift, 16)
        off = int(off, 16)
        if off1 is not None:
            off1 = int(off1, 16)
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
                            read_same_as_write, is_bit_var, type, func, dst, bit_operationses, intermediate_def, off1])
    return data_points

#FIXME: call instructions insns and not addrs
def get_func_to_callsites(prog):
    print()
    print( "[main] getting all functions' callsites: ")
    # https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    # https://bugs.python.org/issue1701409

    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)

    if not os.path.exists(os.path.join(curr_dir, 'functionToCallSites_result')):
        prog_name = c_char_p(str.encode(prog))
        lib.getCalleeToCallsites(prog_name)
        if DEBUG_CTYPE: print( "[main] : Back from C")

    f = open(os.path.join(curr_dir, 'functionToCallSites_result'))
    json_func_to_callsites_array = json.load(f)
    data_points = {}
    functions = set()
    functions_map = {}
    for json_func_to_callsites in json_func_to_callsites_array:
        func_name = json_func_to_callsites['func'] #FIXME unify the field names..
        json_callsites = json_func_to_callsites['callsites']
        callsites = []
        functions.add(func_name)
        callsites_map = {}
        for json_callsite in json_callsites:
            call_insn = json_callsite['insn_addr']
            caller = json_callsite['func_name']
            if call_insn not in callsites_map:
                callsites_map[call_insn] = set()
            callsites_map[call_insn].add(caller)
        for json_callsite in json_callsites:
            call_insn = json_callsite['insn_addr']
            caller = json_callsite['func_name']
            functions.add(caller)
            if len(callsites_map[call_insn]) == 2:
                if ".cold." in caller:
                    #segs = caller.split(".cold.")
                    #assert segs[0] in callsites_map[call_insn], str(callsites_map[call_insn])
                    #assert int(segs[1]) >= 0, caller
                    caller_pair = list(callsites_map[call_insn])
                    if caller_pair[0] not in functions_map:
                        functions_map[caller_pair[0]] = caller_pair[1]
                    if caller_pair[1] not in functions_map:
                        functions_map[caller_pair[1]] = caller_pair[0]
                    print("[sa/warn] Ignore cold path function: " + caller + " callee " + func_name)
                    continue
            callsites.append([call_insn, caller])
        data_points[func_name] = callsites
    f.close()

    for f in functions:
        if ".cold." in f:
            segs = f.split(".cold.")
            if segs[0] not in functions:
                continue
            try:
                if int(segs[1]) < 0:
                    continue
            except Exception as e:
                continue
            if segs[0] not in functions_map: functions_map[segs[0]] = f
            if f not in functions_map: functions_map[f] = segs[0]

    #if DEBUG_CTYPE: print( "[main] sa returned  " + str(data_points))
    return data_points, functions_map

#FIXME: call instructions insns and not addrs
def get_mem_writes_to_static_addrs(binary_ptr):
    print()
    print( "[main] getting the instructions that write to static addresses: ")
    # https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    # https://bugs.python.org/issue1701409

    if not os.path.exists(os.path.join(curr_dir, 'writesToStaticAddr_result')):
        if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)

        lib.getMemWritesToStaticAddresses(c_ulong(binary_ptr))
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
def get_mem_writes(binary_ptr, insn_addr_to_func):
    print()
    print( "[main] getting the registers written at instructions: ")
    # https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    # https://bugs.python.org/issue1701409

    insn_addr_to_func_json = []
    for pair in insn_addr_to_func:
        insn_addr = pair[0]
        func_name = pair[1]
        insn_addr_to_func_json.append({'addr': insn_addr, 'func_name': func_name})
    json_str = json.dumps(insn_addr_to_func_json)
    insn_addr_to_func_str = c_char_p(str.encode(json_str))

    if DEBUG_CTYPE: print( "[main] insn_addr to func: " + json_str)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)

    lib.getMemWrites(c_ulong(binary_ptr), insn_addr_to_func_str)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    mem_writes_per_insn = []
    f = open(os.path.join(curr_dir, 'writesPerInsn_result'))
    json_writes_per_insn = json.load(f)
    if DEBUG_CTYPE: print("[main] : sa returned: " + str(json_writes_per_insn))
    for json_writes in json_writes_per_insn:
        if len(json_writes) == 0:
            continue
        insn_addr = json_writes['addr']
        true_insn_addr = json_writes['true_addr']
        is_loop_insn = json_writes['is_loop_insn']
        func_name = json_writes['func_name']
        src_reg = json_writes['src']
        if "::" in src_reg:
            src_reg = src_reg.split("::")[1]
        if DEBUG: print("==> For instruction: " + str(insn_addr) + " @ " + func_name)
        data_points = parseLoadsOrStores(json_writes['writes'])

        mem_writes_per_insn.append([insn_addr, func_name, data_points, true_insn_addr, src_reg, is_loop_insn])
    f.close()

    if DEBUG_CTYPE: print( "[main] sa returned " + str(mem_writes_per_insn))
    return mem_writes_per_insn

def get_reg_read_or_written(binary_ptr, insn_addr_to_func, is_read):
    print()
    print( "[main] getting the registers read or written at instructions: ")

    insn_addr_to_func_json = []
    for pair in insn_addr_to_func:
        insn_addr = pair[0]
        func_name = pair[1]
        insn_addr_to_func_json.append({'addr': insn_addr, 'func_name': func_name})
    json_str = json.dumps(insn_addr_to_func_json)

    if DEBUG_CTYPE: print( "[main] insn_addr to func: " + json_str)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)

    insn_addr_to_func_str = c_char_p(str.encode(json_str))
    lib.getRegsReadOrWritten(c_ulong(binary_ptr), insn_addr_to_func_str, is_read)
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

def static_backslices(binary_ptr, slice_starts, prog, sa_result_cache):
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
            else:
                print("[BUG] unknown reg? " + str(reg))
            reg_name = "[x86_64::" + reg + "]"
        regname_to_reg[reg_name] = reg

        insn_addr = str(line[1])
        func = line[2]
        is_bit_var = 0 if line[3] is False else 1
        key = str(reg) + "_" + str(insn_addr) + "_" + str(func) + "_" + str(is_bit_var) + "_" + str(prog) #FIXME: prog is not necessary
        if key in sa_result_cache:
            data_points_per_reg.append(sa_result_cache[key])
        else:
            slice_starts_json.append({'reg_name': reg_name, 'addr': insn_addr, 'func_name': func, 'is_bit_var': is_bit_var})
    if len(slice_starts_json) > 0:
        json_str = json.dumps(slice_starts_json)
        if DEBUG_CTYPE: print( "[main] slice starts: " + json_str)
        if DEBUG_CTYPE: print("[main] : " + "Calling C", flush=True)

        slice_starts_str = c_char_p(str.encode(json_str))
        t1 = time.time()
        lib.backwardSlices(c_ulong(binary_ptr), slice_starts_str)
        t2 = time.time()
        print("backwardSlices took: " + str(t2 - t1))
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
            insn_addr = json_loads['addr']
            func = json_loads['func_name']
            is_bit_var = json_loads['is_bit_var']
            if DEBUG: print("==> For use reg: " + reg + " @ " + str(insn_addr))
            data_points = parseLoadsOrStores(json_loads['reads'])
            result = [reg, insn_addr, data_points]
            key = str(reg) + "_" + str(insn_addr) + "_" + str(func) + "_" + str(is_bit_var) + "_" + str(prog)
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

def static_backslice(binary_ptr, reg, insn_addr, func):
    print()
    print( "[main] taking a static backslice: ")
    #https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    #https://bugs.python.org/issue1701409
    if DEBUG_CTYPE: print( "[main] reg: "  + reg)
    if DEBUG_CTYPE: print( "[main] insn_addr: " + hex(insn_addr))
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C", flush=True)

    if reg == "":
        reg_name = c_char_p(str.encode(reg))
    else:
        reg_name = c_char_p(str.encode("[x86_64::" + reg + "]"))
    func_name = c_char_p(str.encode(func))
    lib.backwardSlice(c_ulong(binary_ptr), func_name, c_ulong(insn_addr), reg_name)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    f = open(os.path.join(curr_dir, 'backwardSlice_result'))
    json_reads = json.load(f)
    if DEBUG_CTYPE: print("[main] : returned: " + json_reads)
    data_points = parseLoadsOrStores(json_reads)
    f.close()

    if DEBUG_CTYPE: print( "[main] returned " + str(data_points))
    return data_points

def get_addr_indices(binary_ptr, func, start_addr, end_addr, addrs):
    print()
    print( "[main] getting the indexes for addrs: ")
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print("[main] start addr: " + hex(start_addr))
    if DEBUG_CTYPE: print("[main] end addr: " + hex(end_addr))
    if DEBUG_CTYPE: print("[main] addrs: " + str(addrs))
    if DEBUG_CTYPE: print("[main] : " + "Calling C", flush=True)
    func_name = c_char_p(str.encode(func))
    addrs_str = c_char_p(str.encode(json.dumps(addrs)))
    lib.getAddrIndices(c_ulong(binary_ptr), func_name, c_ulong(start_addr), c_ulong(end_addr), addrs_str)
    f = open(os.path.join(curr_dir, 'getAddrIndices_result'))
    json_addrs = json.load(f)
    f.close()
    if DEBUG_CTYPE: print("[main] returned " + str(json_addrs))
    return json_addrs

def get_addr_indices2(binary_ptr, func, addrs):
    print()
    print( "[main] getting the indexes for addrs2: ")
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print("[main] addrs: " + str(addrs))
    if DEBUG_CTYPE: print("[main] : " + "Calling C", flush=True)
    func_name = c_char_p(str.encode(func))
    addrs_str = c_char_p(str.encode(json.dumps(addrs)))
    lib.getAddrIndices2(c_ulong(binary_ptr), func_name, addrs_str)
    f = open(os.path.join(curr_dir, 'getAddrIndices2_result'))
    json_addrs = json.load(f)
    f.close()
    if DEBUG_CTYPE: print("[main] returned " + str(json_addrs))
    return json_addrs

def getImmedDom(binary_ptr, insn_addr, func):
    print()
    print( "[main] getting the immediate dominator: ")
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] insn_addr: " + hex(insn_addr))
    func_name = c_char_p(str.encode(func))
    dom = lib.getImmedDom(c_ulong(binary_ptr), func_name, c_ulong(insn_addr))
    if DEBUG_CTYPE: print( "[main] immed dom: " + str(dom))
    return dom

def getAllPredes(insn_addr, func, prog):
    print()
    print( "[main] getting all predecessors: ")
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] insn_addr: " + hex(insn_addr), flush=True)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    lib.getAllPredes(prog_name, func_name, c_ulong(insn_addr))
    f = open(os.path.join(curr_dir, 'getAllPredes_result'))
    json_bbs = json.load(f)
    f.close()
    if DEBUG_CTYPE: print( "[main] predes: " + str(json_bbs))
    return json_bbs

def getAllBBs2(binary_ptr2, binary_ptr, insn_addr, func, prog, bb_result_cache={}, overwrite_cache=False):
    print()
    print( "[main] getting all basic blocks: ")
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] insn_addr: " + hex(insn_addr), flush=True)
    key = str(insn_addr) + "_" + str(func)
    if overwrite_cache is False and key in bb_result_cache:
        return bb_result_cache[key]

    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    t1 = time.time()
    lib.getAllBBs2(c_ulong(binary_ptr2), c_ulong(binary_ptr), prog_name, func_name, c_ulong(insn_addr))
    t2 = time.time()
    print("getAllBBs took: " + str(t2 - t1))
    f = open(os.path.join(curr_dir, 'getAllBBs_result'))
    json_bbs = json.load(f)
    f.close()
    if DEBUG_CTYPE: print( "[main] bbs: " )#+ str(json_bbs))
    bb_result_cache[key] = json_bbs
    return json_bbs

def getAllBBs(binary_ptr, insn_addr, func, prog, bb_result_cache={}, overwrite_cache=False):
    print()
    print( "[main] getting all basic blocks: ")
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] insn_addr: " + hex(insn_addr), flush=True)
    key = str(insn_addr) + "_" + str(func)
    if overwrite_cache is False and key in bb_result_cache:
        return bb_result_cache[key]

    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    t1 = time.time()
    lib.getAllBBs(c_ulong(binary_ptr), prog_name, func_name, c_ulong(insn_addr))
    t2 = time.time()
    print("getAllBBs took: " + str(t2 - t1))
    f = open(os.path.join(curr_dir, 'getAllBBs_result'))
    json_bbs = json.load(f)
    f.close()
    if DEBUG_CTYPE: print( "[main] bbs: " )#+ str(json_bbs))
    bb_result_cache[key] = json_bbs
    return json_bbs

def getFirstInstrInBB(binary_ptr, insn_addr, func):
    print()
    print( "[main] getting the first instruction in basic block: ")
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] insn_addr: " + hex(insn_addr))
    func_name = c_char_p(str.encode(func))
    first_insn_addr = lib.getFirstInstrInBB(c_ulong(binary_ptr), func_name, c_ulong(insn_addr))
    if DEBUG_CTYPE: print( "[main] first instr: " + str(first_insn_addr))
    return first_insn_addr

def getInstrAfter(binary_ptr, insn_addr, func):
    print()
    print( "[main] getting the instruction after: ")
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] insn_addr: " + hex(insn_addr), flush=True)
    func_name = c_char_p(str.encode(func))
    insn_after_addr = lib.getInstrAfter(c_ulong(binary_ptr), func_name, c_ulong(insn_addr))
    if DEBUG_CTYPE: print( "[main] instr after: " + str(insn_after_addr))
    return insn_after_addr

def getLastInstrInBB(binary_ptr, insn_addr, func):
    print()
    print( "[main] getting the last instruction in basic block: ")
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] insn_addr: " + hex(insn_addr), flush=True)
    func_name = c_char_p(str.encode(func))
    last_insn_addr = lib.getLastInstrInBB(c_ulong(binary_ptr), func_name, c_ulong(insn_addr))
    if DEBUG_CTYPE: print( "[main] last instr: " + str(last_insn_addr))
    return last_insn_addr

def setup(prog):
    print()
    print( "[main] Setting up analysis: ")
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    lib.setup(prog_name)
    with open('pointers', 'r') as f:
        lines = f.readlines()
        binary_ptr = int(lines[0], 16)
    return binary_ptr

def setup2(prog):
    print()
    print( "[main] Setting up analysis: ")
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    lib.setup2(prog_name)
    with open('pointers', 'r') as f:
        lines = f.readlines()
        binary_ptr = int(lines[0], 16)
    return binary_ptr
