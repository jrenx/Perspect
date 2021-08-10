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
    br_num = int(br.number) - 1
    num_watchpoints = len(watchpoints)
    if br_num < num_watchpoints:
        trace.append((watchpoints[br_num], hex(frame.pc()).strip('L'), frame.name()))
    else:
        br_num = br_num - num_watchpoints
        trace.append(calculate_addr(br_num, frame))


def calculate_addr(br_num, frame):
    reg = config['regs'][br_num]
    shift = int(config['shifts'][br_num])
    off_reg = config['off_regs'][br_num]
    offset = int(config['offsets'][br_num])
    #if '0x' in shift:
    #    shift = int(shift, 16)
    #else:
    #    shift = int(shift)
    #if '0x' in offset:
    #    offset = int(offset, 16)
    #else:
    #    offset = int(offset)

    reg_value = 0
    if reg != '':
        reg_value = int(frame.read_register(reg))

    off_reg_value = 1
    if off_reg != '':
        off_reg_value = int(frame.read_register(off_reg))
    addr_hex = hex((reg_value << shift) + (off_reg_value * offset)).strip('L')

    return (addr_hex, breakpoints[br_num], None)

gdb.events.stop.connect(wp_handler)

not_exit = True

def exit_handler(event):
    global not_exit
    not_exit = False
    
gdb.events.exited.connect(exit_handler)

while not_exit:
    try:
        gdb.execute('c')
    except Exception:
        break

with open(os.path.join(rr_dir, 'watchpoints.log'), 'w') as log_file:
    json.dump(trace, log_file)

gdb.execute('quit', False, True)
