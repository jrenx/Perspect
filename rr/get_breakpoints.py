import subprocess
import json
import os
import re
import time
import datetime

rr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG = True
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
    config = {'breakpoints': breakpoints,
              'reg_points': reg_points,
              'regs': regs,
              'off_regs': off_regs,
              'offsets': offsets,
              'shifts': shifts,
              'src_regs': src_regs,
              'loop_insn_flags' : loop_insn_flags,
              'step': step,
              'deref': deref}
    json.dump(config, open(os.path.join(rr_dir, 'config.json'), 'w'))
    count = len(breakpoints) + len(reg_points)
    success = True
    a = datetime.datetime.now()
    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        if do_timeout is True:
            print("Total number of breakpoints: " + str(count))
            timeout = max(1200, count*15)
            print("Timeout is: " + str(timeout), flush=True)
            rr_process.communicate(('source' + os.path.join(rr_dir, 'get_breakpoints')).encode(), timeout=timeout)
        else:
            rr_process.communicate(('source' + os.path.join(rr_dir, 'get_breakpoints')).encode(), timeout=600)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        success = False
    b = datetime.datetime.now()
    print("Running breakpoints took: " + str(b - a))
    return success


def parse_breakpoint(breakpoints, reg_points, deref):
    """
    Parse the result log file into a list of pairs.
    :param breakpoints: list of breakpoints with no register read
    :param reg_points: list of breakpoints that requires read register value or follow the value
    :return: list of pair (breakpoint_addr, reg_vale, deref_value). reg_value and deref_value is None
    if info not available.
    """
    result = []
    curr_br_num = -1
    addr = None
    pending_point = None
    prev_line = None

    with open(os.path.join(rr_dir, "breakpoints.log"), 'r') as log:
        for i, line in enumerate(log):
            if "Error" in line:
                print("[breakpoint][warn] Is this an error from GDB? " + line)
            if re.search(r'Breakpoint \d+,', line):
                br_num = int(line.split()[1].strip(',')) - 1
                if br_num >= len(reg_points):
                    assert (br_num - len(reg_points)) < len(breakpoints), \
                        line + "\n" + str(prev_line) + "\n" + str(i)
                    bp = breakpoints[br_num - len(reg_points)]
                    if curr_br_num != -1:
                        rp = reg_points[curr_br_num]
                        if int(bp.strip('*'), 16) - int(rp.strip('*'), 16) <= 8:
                            #print('[tmp][warn] reg point ' + rp + ' is immediately followed by breakpoint ' + bp)
                            pending_point = (bp, None, None)
                        else:
                            raise ValueError('reg point with no addr value at file index: ' + str(i) + ' ' + line)
                    else:
                        result.append((bp, None, None))
                        addr = None
                        assert pending_point == None
                else:
                    curr_br_num = br_num
            elif curr_br_num != -1:
                if 'memory error' in line:
                    result.append((reg_points[curr_br_num], None, None))
                    if pending_point is not None:
                        result.append(pending_point)
                        pending_point = None
                    addr = None
                    curr_br_num = -1
                else:
                    val = None
                    segs = line.split()
                    if len(segs) == 3 and line.startswith('$'):
                        val = segs[2]
                    elif addr is not None and len(segs) == 9 and addr == segs[0].strip(":"):
                        assert prev_line.strip() == 'SPECIAL', \
                            str(addr) + "\n" + line + "\n" + str(prev_line) + "\n" + str(i)
                        number = 0
                        for j, seg in enumerate(segs):
                            if j == 0:
                                continue
                            number += int(seg, 16) << (j - 1)*8
                        val = hex(number)

                    if val is None:
                        prev_line = line
                        continue
                    if deref and addr is None:
                        addr = val
                        prev_line = line
                        continue
                    if deref and addr is not None:
                        result.append((reg_points[curr_br_num], addr, val))
                    else:
                        result.append((reg_points[curr_br_num], val, None))

                    if pending_point is not None:
                        result.append(pending_point)
                        pending_point = None
                    addr = None
                    curr_br_num = -1
                """
                elif len(line.split()) == 3 and line.split()[0][0].isalpha():
                    if deref:
                        addr = line.split()[1]
                    else:
                        result.append((reg_points[curr_br_num], line.split()[1], None))
                        #curr_br_num = -1
                        addr = None
                """
            prev_line = line
    if DEBUG:
        timestamp = str(time.time())
        print("[rr] renaming to " + str(os.path.join(rr_dir, 'breakpoints.log' + '.' + timestamp)))
        os.rename(os.path.join(rr_dir, 'breakpoints.log'), os.path.join(rr_dir, 'breakpoints.log' + '.' + timestamp))
    return result


if __name__ == '__main__':
    breakpoints = ['*0x40937d', '*0x409394']
    reg_points = ['*0x409379']
    #regs = ['rbp']
    #run_breakpoint(breakpoints, reg_points, regs, False, False)
    trace = parse_breakpoint(breakpoints, reg_points, True)
    #print(trace[:10])
    #print(trace[-10:])
