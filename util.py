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

DEBUG_CTYPE = True

################################################################
#### C function declarations for accessing Dyninst analysis ####
################################################################

def static_backslice(reg, insn, func, prog):
    print()
    print( "[main] taking a static backslice: ")
    reg_name = c_char_p(str.encode("[x86_64::" + reg + "]"))
    if reg == "":
        reg_name = c_char_p(str.encode(reg))
    #https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    #https://bugs.python.org/issue1701409
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] reg: "  + str(reg_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] : " + "Calling C")
    lib.backwardSlice(prog_name, func_name, addr, reg_name)
    if (DEBUG_CTYPE): print( "[main] : Back from C")
    f = open("result", "r")
    ret = f.read().strip()
    if (DEBUG_CTYPE): print( "[main] : returned: " + ret)
    #In the form: |4234758,RSP + 68|4234648,RSP + 68
    segs = ret.split("|")
    data_points = []
    for seg in segs:
        if seg.strip() == "":
            continue
        pc = seg.split(",")[0]
        data = seg.split(",")[1]

        def_reg = data.strip()
        off = "0"
        if "+" in data:
            def_reg = data.split("+")[0].strip()
            off = data.split("+")[1].strip()
        if '*' in def_reg:
            print("Is an expression too difficult for RR to handle")
            raise
            #continue
        data_points.append([pc, def_reg, off])
    if (DEBUG_CTYPE): print( "[main] " + str(data_points))
    return data_points

def getImmedDom(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    dom = lib.getImmedDom(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] immed dom: " + str(dom))
    return dom

def getFirstInstrInBB(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    f_insn = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(f_insn))
    return f_insn

def getFirstInstrInBB(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    f_insn = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(f_insn))
    return f_insn

def getInstrAfter(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    f_insn = lib.getInstrAfter(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(f_insn))
    return f_insn

def getLastInstrInBB(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    l_insn = lib.getLastInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(l_insn))
    return l_insn

def getLastInstrInBB(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    l_insn = lib.getLastInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(l_insn))
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


