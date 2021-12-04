from __future__ import division
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
target = config['target']
start_time = time.time()

for br in reg_points:
    gdb.execute('br {}'.format(br))
for br in breakpoints:
    if br not in reg_points:
        gdb.execute('br {}'.format(br))

trace = []
addrs = set()
reads = 0
not_exit = True
target_seen = False

def br_handler(event):
    time_passed = time.time() - start_time
    global not_exit
    if timeout is not None and time_passed > timeout:
        not_exit = False
        return
    if not isinstance(event, gdb.BreakpointEvent):
        return
    global target_seen
    if target is not None and target_seen is False:
        if time_passed > 1200:
            print("[rr] Exit the execution because no target has been seen but 5min has past.")
            not_exit = False
            return
    if not config['deref']:
        global reads
        #print("READS " + str(reads))
        #print("ADDRS " + str((len(addrs) + 1)))
        #print("[rr] read to addr ratio: " + str(reads / (len(addrs) + 1)))
        if target is None and (len(addrs)) > 1000:
            print("[rr] Too many addrs to investigate, return ...")
            not_exit = False
            return
        if target is None and (reads / (len(addrs) + 1)) > 100.0:
            if time_passed > 300:
                print("[rr] Exit the execution because there are very few addrs relative to reads.")
                not_exit = False
                return
        global trace
        #print("[rr] bp to read ratio: " + str(len(trace) / (reads+1)))
        if (len(trace) / (reads+1)) > 100.0:
            if time_passed > 120:
                trace = []
                print("[rr] Exit the execution because there are very few reads relative to branch or targets.")
                not_exit = False
                return

    frame = gdb.newest_frame()
    br = event.breakpoints[-1]
    br_num = int(br.number) - 1
    if br_num < len(reg_points):
        is_loop_insn = int(config['loop_insn_flags'][br_num])

        if is_loop_insn != 1:
            if config['step'] and br_num != 0:#first reg point is always a read
                gdb.execute('si')
            read_breakpoint(br_num, frame)
        else:
            gdb.events.stop.disconnect(br_handler)
            loop_pc = int(reg_points[br_num].strip('*'), 16)
            if not config['step']:
                read_breakpoint(br_num, frame)
            gdb.execute('si')

            try:
                pc = int(frame.pc())
                while pc == loop_pc:
                    read_breakpoint(br_num, frame)
                    gdb.execute('si')
                    pc = int(frame.pc())
                if config['step']:
                    read_breakpoint(br_num, frame)
            except gdb.error as e:
                print("Encountered gdb error, frame is likely invalid: " + str(e))
            gdb.events.stop.connect(br_handler)

    elif br_num < len(reg_points) + len(breakpoints):
        br_num -= len(reg_points)
        bp = breakpoints[br_num]
        if target is not None:
            if bp == target:
                target_seen = True
        trace.append((bp, None, None))
    else:
        raise RuntimeError("Unknown breakpoint number: {}".format(br_num + 1))

def read_breakpoint(br_num, frame):
    reg = config['regs'][br_num]
    shift = config['shifts'][br_num]
    off_reg = config['off_regs'][br_num]
    src_reg = config['src_regs'][br_num]
    offset = config['offsets'][br_num]
    if '0x' in shift:
        shift = int(shift, 16)
    else:
        shift = int(shift)
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
    addr = hex((reg_value << shift) + (off_reg_value * offset)).strip('L')

    if not config['deref']:
        trace.append((reg_points[br_num], addr, None))
        addrs.add(addr)
        global reads
        reads += 1
        #print("READ " + str(reads))
    elif addr != '0x0':
        value = None
        if '(' in src_reg or ',' in src_reg or '%' in src_reg:
            cmd = 'p/x *(' + addr + ')'
            ret = gdb.execute(cmd, False, True)
            value = ret.split()[2].strip()
        elif src_reg != '':
            if br_num == 0:
                gdb.execute('si')
            cmd = 'p/x ${}'.format(src_reg)
            ret = gdb.execute(cmd, False, True)
            value = ret.split()[2].strip()
        else:
            #print("SPECIAL")
            cmd = 'x/32b ' + addr
            ret = gdb.execute(cmd, False, True)
            ret = ret.splitlines()[0]
            segs = ret.split()
            number = 0
            for j, seg in enumerate(segs):
                if j == 0 or j == 1:
                    continue
                number += (int(seg, 16) if seg.startswith('0x') else int(seg)) << (j - 1) * 8
            value = hex(number)
        trace.append((reg_points[br_num], addr, value))

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
