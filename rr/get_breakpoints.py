import subprocess
import json
import os
import re
import time
import datetime

rr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG = True
def run_breakpoint(breakpoints, reg_points, regs, off_regs, offsets, shifts, src_regs, loop_insn_flags, step, deref,
                   do_timeout=True):
    """
    print("[tmp] reg_point_to_regs: " + str(reg_point_to_regs))
    reg_points = list(reg_point_to_regs.keys())
    regs = []
    indice_map = {}
    for i in range(len(reg_point_to_regs)):
        v = reg_point_to_regs[reg_points[i]]
        indice_map[i] = len(v)
        regs.extend(v)
    """

    #print("[tmp] reg_points: " + str(reg_points))
    #print("[tmp] regs: " + str(regs))
    #print("[tmp] indice_map: " + str(indice_map))
    config = {'breakpoints': breakpoints,
              'reg_points': reg_points,
              'regs': regs,
              'off_regs': off_regs,
              'offsets': offsets,
              'shifts': shifts,
              'src_regs': src_regs,
              'loop_insn_flags' : loop_insn_flags,
              'step': step,
              'deref': deref}
    json.dump(config, open(os.path.join(rr_dir, 'config.json'), 'w'))
    count = len(breakpoints) + len(reg_points)
    success = True
    a = datetime.datetime.now()
    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        if do_timeout is True:
            print("Total number of breakpoints: " + str(count))
            timeout = max(300, count*15)
            print("Timeout is: " + str(timeout), flush=True)
            rr_process.communicate(('source' + os.path.join(rr_dir, 'get_breakpoints')).encode(), timeout=timeout)
        else:
            rr_process.communicate(('source' + os.path.join(rr_dir, 'get_breakpoints')).encode(), timeout=120)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        success = False
    b = datetime.datetime.now()
    print("Running breakpoints took: " + str(b - a))
    return success


def parse_breakpoint(breakpoints, reg_points, deref):
    """
    Parse the result log file into a list of pairs.
    :param breakpoints: list of breakpoints with no register read
    :param reg_points: list of breakpoints that requires read register value or follow the value
    :return: list of pair (breakpoint_addr, reg_vale, deref_value). reg_value and deref_value is None
    if info not available.
    """
    return json.load(open(os.path.join(rr_dir, 'breakpoints.log'), 'r'))


if __name__ == '__main__':
    breakpoints = ['*0x40937d', '*0x409394']
    reg_points = ['*0x409379']
    #regs = ['rbp']
    #run_breakpoint(breakpoints, reg_points, regs, False, False)
    trace = parse_breakpoint(breakpoints, reg_points, True)
    #print(trace[:10])
    #print(trace[-10:])
