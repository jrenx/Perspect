import subprocess
import json
import os
import re
import time
import datetime

rr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG = True
VERBOSE = False

#def get_child_processes(parent_pid):
#    children = set()
#    # https://superuser.com/questions/363169/ps-how-can-i-recursively-get-all-child-process-for-a-given-pid
#    with os.popen("ps --forest -o pid=,tty=,stat=,time=,cmd= -g $(ps -o sid= -p " + str(parent_pid) + ")") as p:
#        for line in p.readlines():
#            fields = line.split()
#            children.add(int(fields[0]))
#    """
#    if parent_pid in children:
#        children.remove(parent_pid)
#    curr_pid = os.getpid()
#    if curr_pid in children:
#        children.remove(curr_pid)
#    """
#
#    rr_processes = set()
#    with os.popen("ps ax | grep \"rr replay\" | grep -v grep") as p:
#        lines = p.readlines()
#        for line in lines:
#            fields = line.split()
#            child_pid = int(fields[0])
#            rr_processes.add(child_pid)
#    with os.popen("ps ax | grep \"gdb -l 10000 -ex set sysroot\" | grep -v grep") as p:
#        lines = p.readlines()
#        for line in lines:
#            fields = line.split()
#            child_pid = int(fields[0])
#            rr_processes.add(child_pid)
#
#    children = children.intersection(rr_processes)
#    print("[rr][" + pid + "] Children processes of " + str(pid) + " are " + str(children))
#    return children

def run_simple_breakpoint(breakpoints, timeout=None):

    config = {'breakpoints': breakpoints,
              'timeout': timeout}
    with open(os.path.join(rr_dir, 'simple_config.json'), 'w') as f:
        json.dump(config, f)
    print("Timeout is: " + str(timeout), flush=True)
    success = True
    a = datetime.datetime.now()
    rr_process = subprocess.Popen('rr replay --cpu-unbound', stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, shell=True)
    children = get_child_processes(rr_process.pid)
    try:
        if VERBOSE is True:
            rr_process.stdin.write(('set logging file rr/simple_breakpoint_result_' + str(time.time()) + '.log\n').encode())
            rr_process.stdin.write('set pagination off\n'.encode())
            rr_process.stdin.write('set logging overwrite on\n'.encode())
            rr_process.stdin.write('set logging redirect on\n'.encode())
            rr_process.stdin.write('set logging on\n'.encode())
        if timeout is None:
            rr_process.communicate(('source' + os.path.join(rr_dir, 'simple_breakpoints.py')).encode())
        else:
            rr_process.communicate(('source' + os.path.join(rr_dir, 'simple_breakpoints.py')).encode(), timeout=timeout*2)
    except subprocess.TimeoutExpired:
        print("[rr][warn] Running breakpoints triggered hard timeout.")
        success = False
        for child_id in children:
            print("Trying to kill child " + str(child_id), flush=True)
            os.system("sudo kill -9 " + str(child_id))

    b = datetime.datetime.now()
    duration = b - a
    print("[rr] Running breakpoints took: " + str(duration), flush=True)
    return success, duration.total_seconds()

def parse_simple_breakpoint():
    with open(os.path.join(rr_dir, 'simple_breakpoints.log'), 'r') as f:
        trace = json.load(f)

    if DEBUG is True:
        timestamp = str(time.time())
        print("[rr][" + pid + "] renaming to " + str(os.path.join(rr_dir, 'simple_breakpoints.log' + '.' + timestamp)))
        os.rename(os.path.join(rr_dir, 'simple_breakpoints.log'), os.path.join(rr_dir, 'simple_breakpoints.log' + '.' + timestamp))

    return trace

if __name__ == '__main__':
    breakpoints = ["*0x409380", "*0x409418"]
    run_breakpoint(breakpoints)
    trace = parse_simple_breakpoint()
    print(trace)
