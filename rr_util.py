from __future__ import division
import os
import os.path
import sys
import subprocess
from subprocess import call
sys.path.append(os.path.abspath('./rr'))
from sat_def import *
from get_def import *
lib = cdll.LoadLibrary('./binary_analysis/static_analysis.so')
#https://stackoverflow.com/questions/145270/calling-c-c-from-python

curr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG_CTYPE = True
DEBUG = True

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

def rr_backslice(reg, shift, off, insn, branch, target, prog):
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
        + " branch @" + str(branch_str) + " target @" + str(target_str)\
        + " program: " +str(prog))

    rr_result_defs = get_def(prog, branch_str, target_str, insn_str, reg_str, off_str)
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


