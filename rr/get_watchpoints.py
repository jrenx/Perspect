import subprocess
import json
import os
import re
import time
import datetime

rr_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG = True
def run_watchpoint(breakpoints, watchpoints):
    config = {'breakpoints': breakpoints,
              'watchpoints': watchpoints,
              'rwatchpoints': watchpoints,}
    json.dump(config, open(os.path.join(rr_dir, 'config.json'), 'w'))

    success = True
    a = datetime.datetime.now()
    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        rr_process.communicate(('source' + os.path.join(rr_dir, 'get_watchpoints')).encode(), timeout=300)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        success = False
    b = datetime.datetime.now()
    print("Running watchpoints took: " + str(b - a))
    return success

def parse_watchpoint(breakpoints, watchpoints, read_pc_str):
    """
    Parse the result log file into a list of pairs.
    :param breakpoints: list of breakpoints
    :param watchpoints: list of watchpoints
    :return: list of pair (addr, value). value is the location where watchpoint is triggered, None if addr is from
    breakpoints.
    """
    read_pc = int(read_pc_str.strip('*'), 16)
    result = []
    last_write = {}
    watchpoint_count = len(watchpoints)
    curr_watch_num = -1
    watchpoints_not_seen = set(watchpoints)
    with open(os.path.join(rr_dir, 'watchpoints.log'), 'r') as log:
        for line in log:
            #if "Error" in line and "os.Error" not in line:
                #print("[watchpoint][warn] Is this an error from GDB? " + line)
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
            elif re.search(r'Hardware read watchpoint \d+:', line):
                if curr_watch_num != -1:
                    raise ValueError('watchpoint with no source location')
                curr_watch_num = int(line.split()[3].strip(':')) - 1
            elif curr_watch_num != -1 and line.startswith('pc') and len(line.split()) == 4:
                segs = line.split()
                addr = segs[1]
                func = segs[3].strip('<').strip('>').split('+')[0]

                # If is a write point, put in the last write map
                # if is a read point, find the last write and add to map
                if curr_watch_num < watchpoint_count:
                    #print("Is write")
                    watchpoint = watchpoints[curr_watch_num]
                    last_write[curr_watch_num] = [addr, func]
                    if watchpoint in watchpoints_not_seen:
                        watchpoints_not_seen.remove(watchpoint)
                else:
                    #print("Is read")
                    assert(watchpoint_count < watchpoint_count * 2)
                    if 0 < (int(addr,16) - read_pc) < 8: #TODO this is really a hack cuz RR always stops at the instruction after
                        #print("Is target read")
                        write_watch_num = curr_watch_num - watchpoint_count
                        watchpoint = watchpoints[write_watch_num]
                        if write_watch_num in last_write:
                            result.append((watchpoint, last_write[write_watch_num][0], last_write[write_watch_num][1])) #TODO
                            #print("Adding result")
                            del last_write[write_watch_num]
                curr_watch_num = -1
    print('[rr][warn] watchpoints not seen: ' + str(watchpoints_not_seen))
    if DEBUG:
        timestamp = str(time.time())
        print("[rr] renaming to " + str(os.path.join(rr_dir, 'watchpoints.log' + '.' + timestamp)))
        os.rename(os.path.join(rr_dir, 'watchpoints.log'), os.path.join(rr_dir, 'watchpoints.log' + '.' + timestamp))
    return result


if __name__ == '__main__':
    #breakpoints = ['*0x409c84']
    breakpoints = []
    #watchpoints = ['0xf83fffbe68', '0xf83fffefd8']
    watchpoints = ['0x7fdc12590d28']
    run_watchpoint(breakpoints, watchpoints)
    trace = parse_watchpoint(breakpoints, watchpoints)
    #print(trace[:10])
    #print(trace[90:100])
