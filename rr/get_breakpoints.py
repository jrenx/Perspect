import subprocess
import json
import os
import re


def run_breakpoint(breakpoints, reg_points, regs, step, deref):
    config = {'breakpoints': breakpoints,
              'reg_points': reg_points,
              'regs': regs,
              'step': step,
              'deref': deref}
    json.dump(config, open(os.path.join(os.getcwd(), 'config.json'), 'w'))

    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        rr_process.communicate(('source' + os.path.join(os.getcwd(), 'get_breakpoints')).encode(), timeout=300)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        return False
    return True


def parse_breakpoint(breakpoints, reg_points):
    """
    Parse the result log file into a list of pairs.
    :param breakpoints: list of breakpoints with no register read
    :param reg_points: list of breakpoints that requires read register value or follow the value
    :return: list of pair (breakpoint_addr, value). value is None if breakpoint_addr in breakpoints.
    value is the register value if deref is False when process is run.
    value is the value stored in address of register value if deref is True when process is run.
    """
    result = []
    curr_br_num = -1

    with open(os.path.join(os.getcwd(), "breakpoints.log"), 'r') as log:
        for line in log:
            if re.search(r'Breakpoint \d+,', line):
                br_num = int(line.split()[1].strip(',')) - 1
                if br_num >= len(reg_points):
                    if curr_br_num != -1:
                        raise ValueError('reg point with no value')
                    result.append((breakpoints[br_num - len(reg_points)], None))
                    curr_br_num = -1
                else:
                    curr_br_num = br_num
            elif curr_br_num != -1:
                if 'memory error' in line:
                    result.append((reg_points[curr_br_num], None))
                    curr_br_num = -1
                elif len(line.split()) == 3 and line.startswith('$'):
                    result.append((reg_points[curr_br_num], line.split()[2]))
                    curr_br_num = -1
                elif len(line.split()) == 3 and line.split()[0].isalpha():
                    result.append((reg_points[curr_br_num], line.split()[1]))
                    curr_br_num = -1

    return result


if __name__ == '__main__':
    breakpoints = ['*0x409c84', '*0x409c55']
    reg_points = ['*0x409c24']
    regs = ['rbp']
    run_breakpoint(breakpoints, reg_points, regs, False, False)
    trace = parse_breakpoint(breakpoints, reg_points)
    print(trace[:10])
    print(trace[-10:])
