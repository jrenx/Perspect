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

#FIXME: just pass in the MemoryAccess struct?
def rr_backslice(prog, branch, target, insn, reg, shift = 0, off = 0, off_reg = None): #, rr_result_cache = None):
    #TODO, the offset and shift are stored as decimals,
    # should they be passes dec or hex to RR?
    # Looks like they take hex strings
    branch_str = ('*' + hex(branch)) if branch is not None else branch
    target_str = ('*' + hex(target)) if target is not None else target
    insn_str = '*' + hex(insn)
    reg_str = reg.lower()
    shift_str = hex(shift)
    off_str = hex(off)
    off_reg_str = None if off_reg is None else off_reg.lower()
    key = prog + "_" + str(branch_str) + "_" + str(target_str) + "_" \
          + insn_str + "_" + reg_str + "_" + shift_str + "_" + off_str + "_" + str(off_reg_str)

    rr_result_cache = {}
    rr_result_file = os.path.join(curr_dir, 'rr_results.json')
    if os.path.exists(rr_result_file):
        with open(rr_result_file) as file:
            rr_result_cache = json.load(file)

    if key in rr_result_cache:
        return rr_result_cache[key]

    print("[main] Inputtng to RR: " \
        + " reg: " + str(reg_str) + " shift: " + str(shift_str) + " off_reg: " + str(off_reg_str) + " off: " + str(off_str)\
        + " @ " + str(insn_str) + " branch @" + str(branch_str) + " target @" + str(target_str)\
        + " program: " +str(prog), flush=True)

    rr_result_defs = get_def(prog, branch_str, target_str, insn_str, reg_str, shift_str, off_str, off_reg_str)
    print("[main] Result from RR: " + str(len(rr_result_defs)) + " def points: " + str(rr_result_defs))

    rr_result_cache[key] = rr_result_defs

    #rr_result_file = os.path.join(curr_dir, 'rr_results.json')
    with open(rr_result_file, 'w') as f:
        json.dump(rr_result_cache, f)

    return rr_result_defs

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


