import os
from difflib import *
import socket

curr_dir = os.path.dirname(os.path.realpath(__file__))

def diff_two_files_and_create_line_mapps(fname1, fname2):
    with open(fname1, "r") as f1:
        fcontent1 = f1.read().splitlines(keepends=True)
    with open(fname2, "r") as f2:
        fcontent2 = f2.read().splitlines(keepends=True)
    diff = ndiff(fcontent1, fcontent2)
    i1 = i2 = icommon = 0
    map1 = {}
    map2 = {}
    for l in diff:
        if l.startswith('? '):
            continue

        icommon += 1
        if l.startswith('- '):
            i1 += 1
        elif l.startswith('+ '):
            i2 += 1
        else:
            assert l.startswith('  ')
            i1 += 1
            i2 += 1

        map1[i1] = icommon
        map2[i2] = icommon
    return map1, map2

def execute_cmd_in_parallel(all_inputs, script_name, prefix, num_processor, prog):
    print("[indices] Total number of inputs: " + str(len(all_inputs)))
    servers = []
    with open("servers.config", "r") as f:
        for l in f.readlines():
            servers.append(l.strip())
    partition_size = round(len(all_inputs) / len(servers)/ num_processor) + 1
    print("[indices] Each worker executes: " + str(partition_size) + " inputs")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    my_ip = s.getsockname()[0]
    s.close()

    i = 0
    count = 0
    file_names = []
    for server in servers:
        for p in range(num_processor):
            file_name = prefix + str(count)
            count += 1
            print("[indices] Writing to: " + file_name, flush=True)
            file_names.append(file_name)
            f = open(file_name, 'w')
            num_inputs = partition_size if (i + partition_size) < len(all_inputs) else (len(all_inputs) - i)
            print("[indices] Number of inputs to write: " + str(num_inputs))

            for n in range(num_inputs):
                f.write(all_inputs[i] + "\n")
                i += 1

            f.close()
            cmd = 'scp {} {}:{}/'.format(file_name, server, curr_dir)
            print("Running command: " + cmd, flush=True)
            os.system(cmd)
            if server != my_ip:
                os.remove(file_name)
            cmd = 'ssh ' + server + ' "cd ' + curr_dir + '/; nohup ./' + script_name + ' ' \
                  + file_name + ' ' + prog + '_debug ' + my_ip + ':' + curr_dir +'/ > ' + file_name + '.out 2>&1 &"'
            print("Running command: " + cmd, flush=True)
            os.system(cmd)

    ret = []
    for file_name in file_names:
        while not os.path.exists(file_name + "_DONE"):
            continue
        print("[indices] File: " + file_name + ".out is ready ", flush=True)
        with open(file_name + ".out") as f:
            for l in f.readlines():
                ret.append(l)
        os.remove(file_name + "_DONE")
        os.remove(file_name + ".out")
    return ret

def get_line(insn, prog):
    if not isinstance(insn, str):
        insn = hex(insn)
    cmd = ['addr2line', '-e', prog, insn]
    #print("[main] running command: " + str(cmd))
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    return parse_get_line_output(result.stdout.decode('ascii'))

def parse_get_line_output(result):
    result_seg = result.strip().split(":")
    file = result_seg[0]#.split("/")[-1]
    try:
        line = int(result_seg[1].split()[0])
        #print("[main] command returned: " + str(line))
    except ValueError:
        line = None
    return file, line

def get_insn_offsets(line, file, prog):
    cmd = 'gdb ./'+ prog + ' -ex "info line ' + file + ':' + str(line)+'" --batch > infoLine_result'
    #print("[main] running command: " + str(cmd))
    os.system(cmd)
    with open("infoLine_result", 'r') as f:
        result = f.readlines()
    return parse_insn_offsets(result[-1])

def parse_insn_offsets(result):
    #print(result)
    if "contains no code" in result:
        return (float('inf'), float('-inf'))
    if "out of range" in result:
        return (float('inf'), float('-inf'))
    result = result.split("at address")[1]
    result = result.split("and ends at")
    start = int(result[0].split()[0], 16)
    end = int(result[1].split()[0], 16)
    #print("start " + hex(start) + " end " + hex(end))
    return (start, end)

def parse_inputs():
    limit = None
    program = None
    program_args = None
    program_path = None
    starting_event_file = None
    with open("analysis.config", "r") as f:
        for l in f.readlines():
            segs = l.split("=")
            if segs[0] == "limit":
                limit = int(segs[1].strip())
            elif segs[0] == "program":
                program = segs[1].strip()
            elif segs[0] == "program_args":
                program_args = segs[1].strip()
            elif segs[0] == "program_path":
                program_path = segs[1].strip()
            elif segs[0] == "starting_event_file":
                starting_event_file = segs[1].strip()
    print("Limit is: " + str(limit))
    print("Program is: " + str(program))
    print("Program args are: " + str(program_args))
    print("Program path is: " + str(program_path))
    print("Starting event file is: " + str(starting_event_file))

    starting_events = []
    starting_insn_to_weight = {}
    if starting_event_file is not None:
        with open(starting_event_file, "r") as f:
            for l in f.readlines():
                segs = l.split()
                reg = "" if segs[0] == "_" else regs[0]
                insn = int(segs[1], 16)
                starting_events.append([reg, insn, segs[2]])
                if len(segs) >= 4:
                    starting_insn_to_weight[insn] = float(segs[3])
    print("Starting events are: " + str(starting_events))
    print("Starting events weights are: " + str(starting_insn_to_weight))
    return  limit, program, program_args, program_path, starting_events, starting_insn_to_weight

if __name__ == '__main__':
    #parse_inputs()
    diff_two_files_and_create_line_mapps("rec_row.c_4.0.13", "rec_row.c_4.2.1")
