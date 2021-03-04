import subprocess
import json
import os
import re

rr_dir = os.path.dirname(os.path.realpath(__file__))

def run_breakpoint(breakpoints, reg_points, regs, step, deref):
    config = {'breakpoints': breakpoints,
              'reg_points': reg_points,
              'regs': regs,
              'step': step,
              'deref': deref}
    json.dump(config, open(os.path.join(rr_dir, 'config.json'), 'w'))

    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        rr_process.communicate(('source' + os.path.join(rr_dir, 'get_breakpoints')).encode(), timeout=300)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        return False
    return True


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
    value = None

    with open(os.path.join(rr_dir, "breakpoints.log"), 'r') as log:
        for line in log:
            if re.search(r'Breakpoint \d+,', line):
                br_num = int(line.split()[1].strip(',')) - 1
                if br_num >= len(reg_points):
                    if curr_br_num != -1:
                        raise ValueError('reg point with no value')
                    result.append((breakpoints[br_num - len(reg_points)], None, None))
                    curr_br_num = -1
                    value = None
                else:
                    curr_br_num = br_num
            elif curr_br_num != -1:
                if 'memory error' in line:
                    result.append((reg_points[curr_br_num], None))
                    curr_br_num = -1
                    value = None
                elif len(line.split()) == 3 and line.startswith('$'):
                    if deref and value is not None:
                        result.append((reg_points[curr_br_num], value, line.split()[2]))
                    else:
                        result.append((reg_points[curr_br_num], line.split()[2], None))
                    curr_br_num = -1
                    value = None
                elif len(line.split()) == 3 and line.split()[0].isalpha():
                    if deref:
                        value = line.split()[1]
                    else:
                        result.append((reg_points[curr_br_num], line.split()[1], None))
                        curr_br_num = -1
                        value = None

    return result


if __name__ == '__main__':
    breakpoints = ['*0x409c84', '*0x409c55']
    reg_points = ['*0x409c24']
    regs = ['rbp']
    run_breakpoint(breakpoints, reg_points, regs, False, False)
    trace = parse_breakpoint(breakpoints, reg_points, False)
    print(trace[:10])
    print(trace[-10:])
