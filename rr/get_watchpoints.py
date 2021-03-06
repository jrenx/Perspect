import subprocess
import json
import os
import re

rr_dir = os.path.dirname(os.path.realpath(__file__))

def run_watchpoint(breakpoints, watchpoints):
    config = {'breakpoints': breakpoints,
              'watchpoints': watchpoints}
    json.dump(config, open(os.path.join(rr_dir, 'config.json'), 'w'))

    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        rr_process.communicate(('source' + os.path.join(rr_dir, 'get_watchpoints')).encode(), timeout=300)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        return False
    return True


def parse_watchpoint(breakpoints, watchpoints):
    """
    Parse the result log file into a list of pairs.
    :param breakpoints: list of breakpoints
    :param watchpoints: list of watchpoints
    :return: list of pair (addr, value). value is the location where watchpoint is triggered, None if addr is from
    breakpoints.
    """
    result = []
    curr_watch_num = -1

    with open(os.path.join(rr_dir, 'watchpoints.log'), 'r') as log:
        for line in log:
            if re.search(r'Breakpoint \d+,', line):
                if curr_watch_num != -1:
                    raise ValueError('watchpoint with no source location')
                br_num = int(line.split()[1].strip(',')) - 1
                #print("[tmp] branch number: " + str(br_num) + " number of watch points " + str(len(watchpoints)))
                result.append((breakpoints[br_num - len(watchpoints)], None, None))
                curr_watch_num = -1
            elif re.search(r'Hardware watchpoint \d+:', line):
                if curr_watch_num != -1:
                    raise ValueError('watchpoint with no source location')
                curr_watch_num = int(line.split()[2].strip(':')) - 1
            elif curr_watch_num != -1 and line.startswith('pc') and len(line.split()) == 4:
                segs = line.split()
                addr = segs[1]
                func = segs[3].strip('<').strip('>').split('+')[0]
                result.append((watchpoints[curr_watch_num], addr, func))
                curr_watch_num = -1
    return result


if __name__ == '__main__':
    breakpoints = ['*0x409c84']
    watchpoints = ['0xf83fffbe68', '0xf83fffefd8']
    run_watchpoint(breakpoints, watchpoints)
    trace = parse_watchpoint(breakpoints, watchpoints)
    print(trace[:10])
    print(trace[90:100])
