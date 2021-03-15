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

################################################################
#### C function declarations for accessing Dyninst analysis ####
################################################################

def parseLoadsOrStores(json_exprs):
    # TODO, why is it called a read again?
    data_points = []
    data_points_set = set()
    for json_expr in json_exprs:
        insn_addr = None
        if 'insn_addr' in json_expr:
            insn_addr = json_expr['insn_addr']
        expr = json_expr['expr']
        expr_str = str(insn_addr) + str(expr)
        if expr_str in data_points_set:
            continue
        data_points_set.add(expr_str)

        reg = None
        shift = "0"
        off = "0"
        off_reg = None

        #if DEBUG: print("Parsing expression: " + expr)
        segs = expr.strip().split('+')
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
        #both shift and offset are in hex form
        if DEBUG: print("Parsing result reg: " + expr_reg + \
                        " shift " + str(shift) + " off " + str(off) + " insn addr: " + str(insn_addr))
        data_points.append([insn_addr, reg, shift, off, off_reg])
    return data_points


#FIXME: call instructions insns and not addrs
def get_mem_writes_to_static_addrs(prog):
    print()
    print( "[main] getting the instructions that write to static addresses: ")
    # https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    # https://bugs.python.org/issue1701409

    prog_name = c_char_p(str.encode(prog))

    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C")

    lib.getMemWritesToStaticAddresses(prog_name)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    mem_writes_per_insn = []
    f = open(os.path.join(curr_dir, 'writesToStaticAddr_result'))
    json_insn_to_writes = json.load(f)
    data_points = {}
    for json_insn_to_write in json_insn_to_writes:
        insn_addr = json_insn_to_write['insn_addr']
        expr = hex(int(json_insn_to_write['expr'], 16))
        func = json_insn_to_write['func']
        if expr not in data_points:
            data_points[expr] = []
        data_points[expr].append([insn_addr, func])
    f.close()

    if DEBUG_CTYPE: print( "[main] " + str(data_points))
    return data_points


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
    if DEBUG_CTYPE: print( "[main] : " + "Calling C")

    lib.getMemWrites(addr_to_func_str, prog_name)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    mem_writes_per_insn = []
    f = open(os.path.join(curr_dir, 'writesPerInsn_result'))
    json_writes_per_insn = json.load(f)
    if DEBUG_CTYPE: print("[main] : returned: " + str(json_writes_per_insn))
    for json_writes in json_writes_per_insn:
        if len(json_writes) == 0:
            continue
        insn = json_writes['addr']
        true_insn_addr = json_writes['true_addr']
        is_loop_insn = json_writes['is_loop_insn']
        func_name = json_writes['func_name']
        src_reg = json_writes['src']
        if DEBUG: print("==> For instruction: " + str(insn) + " @ " + func_name)
        data_points = parseLoadsOrStores(json_writes['writes'])

        mem_writes_per_insn.append([insn, func_name, data_points, true_insn_addr, src_reg, is_loop_insn])
    f.close()

    if DEBUG_CTYPE: print( "[main] " + str(mem_writes_per_insn))
    return mem_writes_per_insn

def static_backslices(reg_to_addr, func, prog):
    print()
    print( "[main] taking static backslices: ")
    # https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    # https://bugs.python.org/issue1701409

    regname_to_reg = {}

    reg_to_addr_json = []
    for pair in reg_to_addr:
        reg = pair[0]
        if reg == "":
            reg_name = reg
        else:
            reg_name = "[x86_64::" + reg + "]"
        regname_to_reg[reg_name] = reg

        addr = str(pair[1])
        reg_to_addr_json.append({'reg_name': reg_name, 'addr': addr})
    json_str = json.dumps(reg_to_addr_json)
    reg_to_addr_str = c_char_p(str.encode(json_str))
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))

    if DEBUG_CTYPE: print( "[main] reg to addr: " + json_str)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C")

    lib.backwardSlices(reg_to_addr_str, prog_name, func_name)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    data_points_per_reg = []
    f = open(os.path.join(curr_dir, 'backwardSlices_result'))
    json_loads_per_reg = json.load(f)
    if DEBUG_CTYPE: print("[main] : returned: " + str(json_loads_per_reg))
    for json_loads in json_loads_per_reg:
        if len(json_loads) == 0:
            continue
        reg_name = regname_to_reg[json_loads['reg_name']]
        addr = json_loads['addr']
        if DEBUG: print("==> For use reg: " + reg_name + " @ " + str(addr))
        data_points = parseLoadsOrStores(json_loads['reads'])

        data_points_per_reg.append([reg_name, addr, data_points])
    f.close()

    if DEBUG_CTYPE: print( "[main] " + str(data_points_per_reg))
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
    if DEBUG_CTYPE: print( "[main] addr: " + str(insn))
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] : " + "Calling C")
    lib.backwardSlice(prog_name, func_name, addr, reg_name)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    f = open(os.path.join(curr_dir, 'backwardSlice_result'))
    json_reads = json.load(f)
    if DEBUG_CTYPE: print("[main] : returned: " + json_reads)
    data_points = parseReads(json_reads)
    f.close()

    if DEBUG_CTYPE: print( "[main] " + str(data_points))
    return data_points


'''
def getImmedDom(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + str(prog_name))
    if DEBUG_CTYPE: print( "[main] func: " + str(func_name))
    if DEBUG_CTYPE: print( "[main] addr: " + str(addr))
    dom = lib.getImmedDom(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] immed dom: " + str(dom))
    return dom
'''


def getImmedDom(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + str(insn))
    dom = lib.getImmedDom(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] immed dom: " + str(dom))
    return dom

def getAllPredes(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + str(insn))
    lib.getAllPredes(prog_name, func_name, addr)
    f = open(os.path.join(curr_dir, 'getAllPredes_result'))
    json_bbs = json.load(f)
    f.close()
    if DEBUG_CTYPE: print( "[main] predes: " + str(json_bbs))
    return json_bbs

def getAllBBs(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + str(insn))
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
    if DEBUG_CTYPE: print( "[main] addr: " + str(addr))
    f_insn = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(f_insn))
    return f_insn
'''


def getFirstInstrInBB(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + str(insn))
    f_insn = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(f_insn))
    return f_insn


def getInstrAfter(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + str(insn))
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
    if DEBUG_CTYPE: print( "[main] addr: " + str(addr))
    l_insn = lib.getLastInstrInBB(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(l_insn))
    return l_insn
'''


def getLastInstrInBB(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + prog)
    if DEBUG_CTYPE: print( "[main] func: " + func)
    if DEBUG_CTYPE: print( "[main] addr: " + str(insn))
    l_insn = lib.getLastInstrInBB(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(l_insn))
    return l_insn
