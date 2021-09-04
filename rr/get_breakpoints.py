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
    print("[rr][" + pid + "] Children processes of " + str(pid) + " are " + str(children))
    return children

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
    timeout = 120
    if do_timeout:
        timeout = 300
        #count = len(breakpoints) + len(reg_points)
        #timeout = max(300, count * 15)
    config = {'breakpoints': breakpoints,
              'reg_points': reg_points,
              'regs': regs,
              'off_regs': off_regs,
              'offsets': offsets,
              'shifts': shifts,
              'src_regs': src_regs,
              'loop_insn_flags' : loop_insn_flags,
              'step': step,
              'deref': deref,
              'timeout': timeout}
    with open(os.path.join(rr_dir, 'config.json'), 'w') as f:
        json.dump(config, f)
    print("Timeout is: " + str(timeout), flush=True)
    success = True
    a = datetime.datetime.now()
    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, shell=True)
    #children = get_child_processes(rr_process.pid)
    try:
        rr_process.communicate(('source' + os.path.join(rr_dir, 'breakpoints.py')).encode())
    except subprocess.TimeoutExpired:
        success = False

    b = datetime.datetime.now()
    duration = b - a
    print("[rr][" + pid + "] Running breakpoints took: " + str(duration))
    return success, duration.total_seconds()

def parse_breakpoint(breakpoints, reg_points, deref):
    """
    Parse the result log file into a list of pairs.
    :param breakpoints: list of breakpoints with no register read
    :param reg_points: list of breakpoints that requires read register value or follow the value
    :return: list of pair (breakpoint_addr, reg_vale, deref_value). reg_value and deref_value is None
    if info not available.
    """
    with open(os.path.join(rr_dir, 'breakpoints.log'), 'r') as f:
        trace = json.load(f)

    if DEBUG is True:
        timestamp = str(time.time())
        print("[rr][" + pid + "] renaming to " + str(os.path.join(rr_dir, 'breakpoints.log' + '.' + timestamp)))
        os.rename(os.path.join(rr_dir, 'breakpoints.log'), os.path.join(rr_dir, 'breakpoints.log' + '.' + timestamp))

    return trace

if __name__ == '__main__':
    #breakpoints = ['*0x40937d', '*0x409394']
    #reg_points = ['*0x409379']
    #regs = ['rbp']
    #run_breakpoint(breakpoints, reg_points, regs, False, False)
    breakpoints = ["*0x409380", "*0x409418"]
    reg_points = ["*0x409379"]
    regs = ["rdx"]
    off_regs = ["r13"]
    offsets = [8]
    shifts = [0]
    src_regs = [""]
    loop_insn_flags = ["0"]
    step = False
    deref = False
    run_breakpoint(breakpoints, reg_points, regs, off_regs, offsets, shifts, src_regs, loop_insn_flags, step, deref)
    trace = parse_breakpoint(breakpoints, reg_points, True)
    #print(trace[:10])
    #print(trace[-10:])
