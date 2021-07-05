import os
import sys
import json

import gdb

rr_dir = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(rr_dir, 'config.json')) as config_file:
    config = json.load(config_file)

breakpoints = config['breakpoints']
watchpoints = config['watchpoints']

for wp in watchpoints:
    print("watch " + str(wp))
    try:
        gdb.execute('watch *{}'.format(wp))
    except Exception:
        try:
            gdb.execute('watch *(long *){}'.format(wp))
        except Exception:
            sys.stderr.write('[Error] Failed to set watchpoint {}'.format(wp))

for br in breakpoints:
    gdb.execute("br {}".format(br))

trace = []

def wp_handler(event):
    if not isinstance(event, gdb.BreakpointEvent):
        return
    frame = gdb.newest_frame()
    br = event.breakpoints[-1]
    trace.append((watchpoints[int(br.number) - 1], hex(frame.pc()), str(frame.name())))

gdb.events.stop.connect(wp_handler)

not_exit = True

def exit_handler(event):
    with open(os.path.join(rr_dir, 'watchpoints.log'), 'w') as log_file:
        json.dump(trace, log_file)
    not_exit = False
    
gdb.events.exited.connect(exit_handler)

while not_exit:
    try:
        gdb.execute('c')
    except Exception:
        break

gdb.execute('quit', False, True)