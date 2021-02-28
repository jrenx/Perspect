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
sys.path.append(os.path.abspath('./pin'))
from instruction_reg_trace import *
from instruction_trace import *
from function_trace import *
from bit_trace import *
lib = cdll.LoadLibrary('./binary_analysis/static_analysis.so')
#https://stackoverflow.com/questions/145270/calling-c-c-from-python

curr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG_CTYPE = True

################################################################
#### C function declarations for accessing Dyninst analysis ####
################################################################

def parseReads(json_reads):
    # TODO, why is it called a read again?
    data_points = []
    for json_read in json_reads:
        # In the form: |4234758,RSP + 68|4234648,RSP + 68
        insn_addr = json_read['insn_addr']
        expr = json_read['expr']

        def_reg = expr.strip()
        off = "0"

        if '+' in expr:
            def_reg = expr.split("+")[0].strip()
            off = expr.split("+")[1].strip()
        if '*' in expr:
            print("Is an expression too difficult for RR to handle")
            raise
            # continue
        data_points.append([insn_addr, def_reg, off])

def static_backslices(reg_to_addr, func, prog):
    print()
    print( "[main] taking a static backslice: ")
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

    lib.backwardSlices(reg_to_addr_str, prog, func)
    if DEBUG_CTYPE: print( "[main] : Back from C")

    data_points_per_reg = []
    f = open(os.path.join(curr_dir, 'backwardSlices_result'))
    json_reads_per_reg = json.load(f)
    if DEBUG_CTYPE: print("[main] : returned: " + str(json_reads_per_reg))
    for json_reads in json_reads_per_reg:
        if len(json_reads) == 0:
            continue
        print("HERE " + str(json_reads))
        reg_name = regname_to_reg[json_reads['reg_name']]
        addr = json_reads['addr']
        data_points = parseReads(json_reads['reads'])
        data_points_per_reg.append({reg_name, addr, data_points})
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
    if DEBUG_CTYPE: print( "[main] addr: " + insn)
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
    if DEBUG_CTYPE: print( "[main] prog: " + str(prog_name))
    if DEBUG_CTYPE: print( "[main] func: " + str(func_name))
    if DEBUG_CTYPE: print( "[main] addr: " + str(addr))
    dom = lib.getImmedDom(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] immed dom: " + str(dom))
    return dom

def getAllPredes(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + str(prog_name))
    if DEBUG_CTYPE: print( "[main] func: " + str(func_name))
    if DEBUG_CTYPE: print( "[main] addr: " + str(addr))
    lib.getAllPredes(prog_name, func_name, addr)
    f = open(os.path.join(curr_dir, 'getAllPredes_result'))
    json_bbs = json.load(f)
    f.close()
    if DEBUG_CTYPE: print( "[main] predes: " + str(json_bbs))
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
    if DEBUG_CTYPE: print( "[main] prog: " + str(prog_name))
    if DEBUG_CTYPE: print( "[main] func: " + str(func_name))
    if DEBUG_CTYPE: print( "[main] addr: " + str(addr))
    f_insn = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if DEBUG_CTYPE: print( "[main] first instr: " + str(f_insn))
    return f_insn


def getInstrAfter(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if DEBUG_CTYPE: print( "[main] prog: " + str(prog_name))
    if DEBUG_CTYPE: print( "[main] func: " + str(func_name))
    if DEBUG_CTYPE: print( "[main] addr: " + str(addr))
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
    if DEBUG_CTYPE: print( "[main] prog: " + str(prog_name))
    if DEBUG_CTYPE: print( "[main] func: " + str(func_name))
    if DEBUG_CTYPE: print( "[main] addr: " + str(addr))
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

def dynamic_backslice(reg, off, insn, func, prog): 
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

def dynamic_backslice2(branch, target, reg, off, insn): 
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


