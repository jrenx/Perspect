import gdb

import json
import os
import time

rr_dir = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(rr_dir, 'config.json')) as configFile:
    config = json.load(configFile)

breakpoints = config['breakpoints']
reg_points = config['reg_points']
timeout = config['timeout']
start_time = time.time()

for br in reg_points:
    gdb.execute('br {}'.format(br))
for br in breakpoints:
    if br not in reg_points:
        gdb.execute('br {}'.format(br))

trace = []
not_exit = True

def br_handler(event):
    if time.time() - start_time > timeout:
        global not_exit
        not_exit = False
        return
    if not isinstance(event, gdb.BreakpointEvent):
        return
    frame = gdb.newest_frame()
    br = event.breakpoints[-1]
    br_num = int(br.number) - 1
    if br_num < len(reg_points):
        is_loop_insn = int(config['loop_insn_flags'][br_num])

        if is_loop_insn != 1 or not config['step']:
            if config['step'] and br_num != 0:#first reg point is always a read
                gdb.execute('si')
            read_breakpoint(br_num, frame)
        else:
            gdb.events.stop.disconnect(br_handler)
            loop_pc = int(reg_points[br_num].strip('*'))
            gdb.execute('si')
            pc = int(frame.pc())
            while pc == loop_pc:
                read_breakpoint(br_num, frame)
                gdb.execute('si')
                pc = int(frame.pc())
            gdb.events.stop.connect(br_handler)

    elif br_num < len(reg_points) + len(breakpoints):
        br_num -= len(reg_points)
        trace.append((hex(int(frame.pc())), None, None))
    else:
        raise RuntimeError("Unknown breakpoint number: {}".format(br_num + 1))

def read_breakpoint(br_num, frame):
    reg = config['regs'][br_num]
    shift = config['shifts'][br_num]
    off_reg = config['off_regs'][br_num]
    src_reg = config['src_regs'][br_num]
    offset = config['offsets'][br_num]
    if '0x' in offset:
        offset = int(offset, 16)
    else:
        offset = int(offset)

    reg_value = 0
    off_reg_value = 1
    if reg != '':
        reg_value = int(frame.read_register(reg))
    if off_reg != '':
        off_reg_value = int(frame.read_register(off_reg))
    addr = hex(reg_value << shift + off_reg_value * offset)

    if not config['deref']:
        trace.append((hex(int(frame.pc())), hex(reg_value), None))
    else:
        if '(' in src_reg or ',' in src_reg or '%' in src_reg:
            cmd = 'p/x *(' + addr + ')'
        elif src_reg != '':
            if br_num == 0:
                gdb.execute('si')
            cmd = 'p/x ${}'.format(src_reg)
        else:
            print("SPECIAL")
            cmd = 'x/32b ' + addr
        value = hex(int(gdb.execute(cmd, False, True)))
        trace.append(hex(int(frame.pc())), hex(addr), value)

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

with open(os.path.join(rr_dir, 'breakpoints.log'), 'w') as log_file:
    json.dump(trace, log_file)

gdb.execute('quit', False, True)