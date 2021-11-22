from __future__ import division
import gdb

import json
import os
import time

rr_dir = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(rr_dir, 'simple_config.json')) as configFile:
    config = json.load(configFile)

breakpoints = config['breakpoints']
timeout = config['timeout']
start_time = time.time()

for br in breakpoints:
    if br not in reg_points:
        gdb.execute('br {}'.format(br))

trace = []
not_exit = True

def br_handler(event):
    time_passed = time.time() - start_time
    global not_exit
    if timeout is not None and time_passed > timeout:
        not_exit = False
        return
    if not isinstance(event, gdb.BreakpointEvent):
        return

    br = event.breakpoints[-1]
    br_num = int(br.number) - 1
    bp = breakpoints[br_num]
    trace.append((bp, None, None))
    no_exit = False

gdb.events.stop.connect(br_handler)

def exit_handler(event):
    global not_exit
    not_exit = False
    
gdb.events.exited.connect(exit_handler)

while not_exit:
    try:
        gdb.execute('c')
    except Exception:
        break

with open(os.path.join(rr_dir, 'simple_breakpoints.log'), 'w') as log_file:
    json.dump(trace, log_file)

gdb.execute('quit', False, True)
