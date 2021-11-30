from __future__ import division
import os
import os.path
import sys
import subprocess
from subprocess import call
import socket
import sys
sys.path.append(os.path.abspath('./rr'))
from sat_def import *
from get_def import *
lib = cdll.LoadLibrary('./binary_analysis/static_analysis.so')
from util import *
from get_simple_breakpoints import *
#https://stackoverflow.com/questions/145270/calling-c-c-from-python

curr_dir = os.path.dirname(os.path.realpath(__file__))
pid = str(os.getpid())
DEBUG_CTYPE = True
DEBUG = True
HOST = "localhost"
PORT = parse_inner_port()
################################################################
#### Helper functions that interact with RR functionalities ####
################################################################

def rr_backslice2(binary_ptr, prog, branch_str, target_str, insn_str, reg_str, shift_str, off_str, off_reg_str, rr_result_cache): #, rr_result_cache = None):

    print("[main][" + pid + "] Inputting to RR: " \
        + " reg: " + str(reg_str) + " shift: " + str(shift_str) + " off_reg: " + str(off_reg_str) + " off: " + str(off_str)\
        + " @ " + str(insn_str) + " branch @" + str(branch_str) + " target @" + str(target_str)\
        + " program: " +str(prog), flush=True)

    key = prog + "_" + str(branch_str) + "_" + str(target_str) + "_" \
          + insn_str + "_" + reg_str + "_" + shift_str + "_" + off_str + "_" + str(off_reg_str)
    # FIXME, prog is redundant
    
    rr_result_defs = get_def(binary_ptr, branch_str, target_str, insn_str, reg_str, shift_str, off_str, off_reg_str)
    print("[main][" + pid + "] Result from RR: " + str(len(rr_result_defs)) + " def points: " + str(rr_result_defs))

    rr_result_cache[key] = rr_result_defs

    #rr_result_file = os.path.join(curr_dir, 'rr_results.json')
    #with open(rr_result_file, 'w') as f:
    #    json.dump(rr_result_cache, f)

    return rr_result_defs

#FIXME: just pass in the MemoryAccess struct?
def rr_backslice(binary_ptr, prog, branch, target, insn, reg, shift, off, off_reg, rr_result_cache): #, rr_result_cache = None):
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
    print("[rr] inputting for RR analysis: " + str(key))
    if key in rr_result_cache:
        print("[rr] Found in cache.")
        return rr_result_cache[key]
    #if conn is None:
    #    print("[main] writing to file: " + key)
    #    with open("rr_inputs", "a") as f:
    #        f.write(key+"\n")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((HOST, PORT))
        sock.sendall(bytes(key + "\n", "utf-8"))
        print("[main] sending to socket: " + key)
    raise Exception()

    print("[main] Inputting to RR: " \
        + " reg: " + str(reg_str) + " shift: " + str(shift_str) + " off_reg: " + str(off_reg_str) + " off: " + str(off_str)\
        + " @ " + str(insn_str) + " branch @" + str(branch_str) + " target @" + str(target_str)\
        + " program: " +str(prog), flush=True)
    
    rr_result_defs = get_def(binary_ptr, branch_str, target_str, insn_str, reg_str, shift_str, off_str, off_reg_str)
    print("[main] Result from RR: " + str(len(rr_result_defs)) + " def points: " + str(rr_result_defs))

    rr_result_cache[key] = rr_result_defs

    #rr_result_file = os.path.join(curr_dir, 'rr_results.json')
    #with open(rr_result_file, 'w') as f:
    #    json.dump(rr_result_cache, f)

    return rr_result_defs

def instruction_executed(insn):
   run_simple_breakpoint([insn])
   return len(parse_simple_breakpoint()) > 0
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

def get_fake_target_and_branch(binary_ptr, insn, func):
    fake_branch = getInstrAfter(binary_ptr, insn, func)
    fake_target = getInstrAfter(binary_ptr, fake_branch, func)
    #fake_target = getLastInstrInBB(insn, func, prog)
    if fake_branch >= fake_target:
        print("[main] [warn] BB just have one instr? " + str(fake_branch) + " " + str(fake_target))
    fake_branch = hex(fake_branch)
    fake_target = hex(fake_target)
    return fake_branch, fake_target


