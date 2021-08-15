import subprocess
import json
import os
import re
import time
import datetime

rr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG = True

def get_child_processes(parent_pid):
    children = set()
    # https://superuser.com/questions/363169/ps-how-can-i-recursively-get-all-child-process-for-a-given-pid
    for line in os.popen("ps --forest -o pid=,tty=,stat=,time=,cmd= -g $(ps -o sid= -p " + str(parent_pid) + ")"):
        fields = line.split()
        children.add(int(fields[0]))
    """
    if parent_pid in children:
        children.remove(parent_pid)
    curr_pid = os.getpid()
    if curr_pid in children:
        children.remove(curr_pid)
    """

    rr_processes = set()
    for line in os.popen("ps ax | grep \"sudo rr replay\" | grep -v grep"):
        fields = line.split()
        pid = int(fields[0])
        rr_processes.add(pid)
    for line in os.popen("ps ax | grep \"gdb -l 10000 -ex set sysroot\" | grep -v grep"):
        fields = line.split()
        pid = int(fields[0])
        rr_processes.add(pid)

    children = children.intersection(rr_processes)
    print("[rr] Children processes of " + str(pid) + " are " + str(children))
    return children

def run_watchpoint(watchpoints, breakpoints=[], regs=[], off_regs=[], offsets=[], shifts=[], additional_timeout=0):
    timeout = 60 + additional_timeout
    config = {'watchpoints': watchpoints,
              'rwatchpoints': watchpoints,
              'breakpoints': breakpoints,
              'regs': regs,
              'off_regs': off_regs,
              'offsets': offsets,
              'shifts': shifts,
              'timeout': timeout}
    print("[rr] Running watchpoint with timeout:" + str(timeout) + " with config " + str(config))
    json.dump(config, open(os.path.join(rr_dir, 'config.json'), 'w'))

    success = True
    a = datetime.datetime.now()
    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, shell=True)
    children = get_child_processes(rr_process.pid)
    try:
        rr_process.communicate(('source' + os.path.join(rr_dir, 'watchpoints.py')).encode())
    except subprocess.TimeoutExpired:
        success = False

    b = datetime.datetime.now()
    print("[rr] Running watchpoints took: " + str(b - a))
    return success

def parse_watchpoint(reads=None, addr_to_def_to_ignore=None):
    """
    :return: list of pair (watchpoint, addr, value). value is the location where watchpoint is triggered, None if addr is from
    breakpoints.
    """
    trace = json.load(open(os.path.join(rr_dir, 'watchpoints.log'), 'r'))
    if reads is None:
        ret = trace
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

    if DEBUG is True:
        timestamp = str(time.time())
        print("[rr] renaming to " + str(os.path.join(rr_dir, 'watchpoints.log' + '.' + timestamp)))
        os.rename(os.path.join(rr_dir, 'watchpoints.log'), os.path.join(rr_dir, 'watchpoints.log' + '.' + timestamp))

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
