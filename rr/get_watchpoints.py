import subprocess
import json
import os
import re
import time
import datetime

rr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG = True
def run_watchpoint(breakpoints, watchpoints):
    config = {'breakpoints': breakpoints,
              'watchpoints': watchpoints,
              'rwatchpoints': watchpoints,}
    json.dump(config, open(os.path.join(rr_dir, 'config.json'), 'w'))

    success = True
    a = datetime.datetime.now()
    rr_process = subprocess.Popen('sudo rr replay >/dev/null', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        rr_process.communicate(('source' + os.path.join(rr_dir, 'watchpoints.py')).encode(), timeout=60)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        success = False
    b = datetime.datetime.now()
    print("Running watchpoints took: " + str(b - a))
    return success

def parse_watchpoint(breakpoints, watchpoints):
    """
    :return: list of pair (watchpoint, addr, value). value is the location where watchpoint is triggered, None if addr is from
    breakpoints.
    """
    return json.load(open(os.path.join(rr_dir, 'watchpoints.log'), 'r'))


if __name__ == '__main__':
    #breakpoints = ['*0x409c84']
    breakpoints = []
    #watchpoints = ['0xf83fffbe68', '0xf83fffefd8']
    #watchpoints = ['0x7fdc12590d28']
    watchpoints = ['0x479ef8']
    #run_watchpoint(breakpoints, watchpoints)
    trace = parse_watchpoint(breakpoints, watchpoints, "*0x420e59")
    #print(trace[:10])
    #print(trace[90:100])
