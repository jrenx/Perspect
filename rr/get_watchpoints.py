import subprocess
import json
import os
import re
import time
import datetime

rr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG = True
def run_watchpoint(watchpoints, breakpoints=[], regs=[], off_regs=[], offsets=[], shifts=[]):
    config = {'watchpoints': watchpoints,
              'rwatchpoints': watchpoints,
              'breakpoints': breakpoints,
              'regs': regs,
              'off_regs': off_regs,
              'offsets': offsets,
              'shifts': shifts}
    json.dump(config, open(os.path.join(rr_dir, 'config.json'), 'w'))

    success = True
    a = datetime.datetime.now()
    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, shell=True)
    try:
        rr_process.communicate(('source' + os.path.join(rr_dir, 'watchpoints.py')).encode(), timeout=60)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        success = False
    b = datetime.datetime.now()
    print("Running watchpoints took: " + str(b - a))
    return success

def parse_watchpoint(reads=None, addr_to_def_to_ignore=None):
    """
    :return: list of pair (watchpoint, addr, value). value is the location where watchpoint is triggered, None if addr is from
    breakpoints.
    """
    trace = json.load(open(os.path.join(rr_dir, 'watchpoints.log'), 'r'))
    if reads is None:
        return trace
    else:
        ret = []
        addr_to_watchpoint = {}
        for point in trace:
            addr = point[0]
            insn = point[1]
            if insn in reads:
                if addr in addr_to_watchpoint:
                    ret.append(addr_to_watchpoint[addr])
                    del addr_to_watchpoint[addr]
            else:
                if addr in addr_to_def_to_ignore:
                    continue
                addr_to_watchpoint[addr] = point
        return ret, len(trace)

if __name__ == '__main__':
    #breakpoints = ['*0x409c84']
    breakpoints = []
    #watchpoints = ['0xf83fffbe68', '0xf83fffefd8']
    #watchpoints = ['0x7fdc12590d28']
    #watchpoints = ['0x479ef8']
    watchpoints = ['0xf840002dc0', '0x50a7f8']
    #watchpoints = ['0xf84002f7a0']
    run_watchpoint(breakpoints, watchpoints)
    #trace = parse_watchpoint(breakpoints, watchpoints, "*0x420e59")
    #print(trace[:10])
    #print(trace[90:100])
