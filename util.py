from __future__ import division
import os
import os.path
import sys
import subprocess
from subprocess import call
from optparse import OptionParser
from collections import deque
from ctypes import *
sys.path.append(os.path.abspath('./rr'))
from sat_def import *
from get_def import *
sys.path.append(os.path.abspath('./pin'))
from instruction_reg_trace import *
from instruction_trace import *
from function_trace import *
from bit_trace import *
lib = cdll.LoadLibrary('./binary_analysis/static_analysis.so')
#https://stackoverflow.com/questions/145270/calling-c-c-from-python

curr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG_CTYPE = True
DEBUG = True

################################################################
#### C function declarations for accessing Dyninst analysis ####
################################################################

def parseLoads(json_loads):
    # TODO, why is it called a read again?
    data_points = []
    data_points_set = set()
    for json_load in json_loads:
        # In the form: |4234758,RSP + 68|4234648,RSP + 68
        insn_addr = json_load['insn_addr']
        expr = json_load['expr']
        load_str = str(insn_addr) + str(expr)
        if load_str in data_points_set:
            continue
        data_points_set.add(load_str)

        load_reg = expr.strip()
        shift = "0"
        off = "0"

        #if DEBUG: print("Parsing expression: " + expr)
        if '*' in load_reg:
            if '+' in expr:
                off = load_reg.split("+")[0].strip()
                load_reg = load_reg.split("+")[1].strip()
            shift = load_reg.split("*")[1].strip()
            load_reg = load_reg.split("*")[0].strip()
            print("Is an expression too difficult for RR to handle")
        elif '+' in load_reg:
            off = load_reg.split("+")[1].strip()
            load_reg = load_reg.split("+")[0].strip()
        shift = int(shift, 16)
        off = int(off, 16)
        #both shift and offset are in hex form
        if DEBUG: print("Parsing result reg: " + load_reg + \
                        " shift " + str(shift) + " off " + str(off) + " insn addr: " + str(insn_addr))
        data_points.append([insn_addr, load_reg, shift, off])
    return data_points

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
        data_points = parseLoads(json_loads['reads'])

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

################################################################
#### Helper functions that interact with PIN functionalities ###
################################################################
def are_predecessors_predictive(succe, prede, path, prog, arg):
    trace = InsTrace(os.path.join(path, prog) + " " + arg, pin='~/pin-3.11/pin')
    ret = trace.get_predictive_predecessors(succe, prede)
    return ret

def trace_function(function, path, prog, arg):
    trace = TraceCollector(os.path.join(path, prog) + " " + arg, pin='~/pin-3.11/pin')
    trace.run_function_trace(function)
    trace.read_trace_from_disk(function)
    #trace.cleanup(function)
    return trace.traces[function]

################################################################
#### Helper functions that interact with RR functionalities ####
################################################################

def dynamic_backslice_old(reg, off, insn, func, prog):
    #TODO, can only do this when is in same function?
    fake_branch, fake_target = get_fake_target_and_branch \
                (insn, func, prog)
    insn_str = hex(insn)
    
    print( "[main] inputtng to RR: "  \
        + str(fake_target) + " " + str(fake_branch) + " " \
        + str(insn_str) + " " + str(reg) + " " + str(off))

    rr_result_defs = get_def('*' + fake_target, '*' + fake_branch, \
                                 insn_str, reg, off)
    return list(rr_result_defs[0].union(rr_result_defs[1]))

def dynamic_backslice2_old(branch, target, reg, off, insn):
    #TODO, can only do this when is in same function?
    insn_str = hex(insn)
    target_str = hex(target)
    branch_str = hex(branch)

    print( "[main] inputtng to RR2: "  \
        + str(target_str) + " " + str(branch_str) + " " \
        + str(insn_str) + " " + str(reg) + " " + str(off))

    rr_result_defs = get_sat_def('*' + target_str, '*' + branch_str, \
                                 insn_str, reg, off)
    return list(rr_result_defs[0].union(rr_result_defs[1]))

def rr_backslice(reg, shift, off, insn, branch, target):
    #TODO, the offset and shift are stored as decimals,
    # should they be passes dec or hex to RR?
    # Looks like they take hex strings
    target_str = '*' + hex(target)
    branch_str = '*' + hex(branch)
    insn_str = '*' + hex(insn)
    reg_str = reg.lower()
    shift_str = hex(shift)
    off_str = hex(off)

    print("[main] Inputtng to RR: " \
        + " reg: " + str(reg_str) + " off: " + str(off_str) + " @ " + str(insn_str)\
        + " branch @" + str(branch_str) + " target @" + str(target_str))

    rr_result_defs = get_def(branch_str, target_str, insn_str, reg_str, off_str)
    print("[main] Result: " + str(rr_result_defs))
    return list(rr_result_defs[0].union(rr_result_defs[1]))

################################################################
####                  Other helper functions                ####
################################################################

def get_function(insn, prog):
    if not isinstance(insn, str):
        insn = hex(insn)
    cmd = ['addr2line', '-e', prog, '-f', insn]
    print("[main] running command: " + str(cmd))
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    func = result.stdout.decode('ascii').split()[0]
    print("[main] command returned: " + str(func))
    return func

def get_fake_target_and_branch(insn, func, prog):
    fake_branch = getInstrAfter(insn, func, prog)
    fake_target = getInstrAfter(fake_branch, func, prog)
    #fake_target = getLastInstrInBB(insn, func, prog)
    if fake_branch >= fake_target:
        print("[main] [warn] BB just have one instr? " + str(fake_branch) + " " + str(fake_target))
    fake_branch = hex(fake_branch)
    fake_target = hex(fake_target)
    return fake_branch, fake_target


