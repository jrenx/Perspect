import subprocess
import json
import os
import re
import time
import datetime

rr_dir = os.path.dirname(os.path.realpath(__file__))
pid = str(os.getpid())
DEBUG = True

def get_child_processes(parent_pid):
    children = set()
    # https://superuser.com/questions/363169/ps-how-can-i-recursively-get-all-child-process-for-a-given-pid
    with os.popen("ps --forest -o pid=,tty=,stat=,time=,cmd= -g $(ps -o sid= -p " + str(parent_pid) + ")") as p:
        for line in p.readlines():
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
    with os.popen("ps ax | grep \"rr replay\" | grep -v grep") as p:
        lines = p.readlines()
        for line in lines:
            fields = line.split()
            child_pid = int(fields[0])
            rr_processes.add(child_pid)
    with os.popen("ps ax | grep \"gdb -l 10000 -ex set sysroot\" | grep -v grep") as p:
        lines = p.readlines()
        for line in lines:
            fields = line.split()
            child_pid = int(fields[0])
            rr_processes.add(child_pid)

    children = children.intersection(rr_processes)
    print("[rr][" + pid + "] Children processes of " + str(pid) + " are " + str(children))
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
    print("[rr][" + pid + "] Running watchpoint with timeout:" + str(timeout) + " with config " + str(config))
    with open(os.path.join(rr_dir, 'config.json'), 'w') as f:
        json.dump(config, f)

    success = True
    a = datetime.datetime.now()
    rr_process = subprocess.Popen('rr replay --cpu-unbound', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    children = get_child_processes(rr_process.pid)
    try:
        rr_process.communicate(('source' + os.path.join(rr_dir, 'watchpoints.py')).encode(), timeout=timeout*2)
    except subprocess.TimeoutExpired:
        success = False
        for child_id in children:
            print("Trying to kill child " + str(child_id), flush=True)
            os.system("sudo kill -9 " + str(child_id))

    b = datetime.datetime.now()
    duration = b - a
    print("[rr][" + pid + "] Running watchpoints took: " + str(duration), flush=True)
    return success, duration.total_seconds()

def parse_watchpoint(reads=None, addr_to_def_to_ignore=None):
    """
    :return: list of pair (watchpoint, addr, value). value is the location where watchpoint is triggered, None if addr is from
    breakpoints.
    """
    with open(os.path.join(rr_dir, 'watchpoints.log'), 'r') as f:
        trace = json.load(f)
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
        print("[rr][" + pid + "] renaming to " + str(os.path.join(rr_dir, 'watchpoints.log' + '.' + timestamp)))
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
