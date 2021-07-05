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
            print('[Error] Failed to set watchpoint {}'.format(wp), file=sys.stderr)

for br in breakpoints:
    gdb.execute("br {}".format(br))

breakpoint_values = [int(br.strip('*'), base=16) for br in breakpoints]
watchpoint_values = [int(wp.strip('*'), base=16) for wp in watchpoints]

trace = []

while True:
    try:
        gdb.execute('c')
        frame = gdb.newest_frame()
    except Exception:
        break # End of process
    pc = int(frame.pc())
    if pc in watchpoints:
        func = str(frame.name())
        trace.append((watchpoints[watchpoint_values.index(pc)], hex(pc), func))
    else:
        print('[Error] gdb stop at unkown point {}'.format(hex(pc)), file=sys.stderr)

with open(os.path.join(rr_dir, 'watchpoints.log'), 'w') as log_file:
    json.dump(trace, log_file)
