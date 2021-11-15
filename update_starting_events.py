import os
import subprocess
from util import *
from dynamic_dep_graph import *

curr_dir = os.path.dirname(os.path.realpath(__file__))
limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()

dd = DynamicDependence(starting_events, program, program_args, program_path, starting_insn_to_weight)
print(program)
dd.prepare_to_build_dynamic_dependencies(limit)

print("[ra] Getting the counts of each unique node in the dynamic trace")
if not os.path.exists(dd.trace_path + ".count"):
    preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'count_node')
    pp_process = subprocess.Popen([preprocessor_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = pp_process.communicate()
    print(stdout)
    print(stderr)
node_counts = {}
with open(dd.trace_path + ".count", 'r') as f:  # TODO
    for l in f.readlines():
        insn = int(l.split()[0], 16)
        if insn not in starting_insn_to_weight:
            continue
        count = int(l.split()[1])
        node_counts[insn] = count
print("[ra] Finished getting the counts of each unique node in the dynamic trace")
print(starting_events)
print(starting_insn_to_weight)
starting_events_strs = []
for event in starting_events:
    reg = event[0] if event[0] != "" else "_"
    insn = event[1]
    func = event[2]
    event_str = reg + " " + hex(insn) + " " + func
    weight = starting_insn_to_weight.get(insn, None)
    if weight is not None:
        if node_counts[insn] > 0:
            weight = weight/node_counts[insn] * 1000
        elif node_counts[insn] == 0:
            weight = 0
        else:
            assert(False), node_counts[insn]
        event_str += (" " + str(weight))
    starting_events_strs.append(event_str)

starting_event_file = None
with open("analysis.config", "r") as f:
        for l in f.readlines():
            segs = l.split('=')
            if segs[0] == "starting_event_file":
                starting_event_file = segs[1].strip()
                break
print(starting_events_strs)
with open(starting_event_file, "w") as f:
    for event_str in starting_events_strs:
        f.write(event_str + "\n")


