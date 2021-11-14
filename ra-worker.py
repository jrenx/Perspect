import sys
import os
import shutil
import multiprocessing as mp
import threading
import socket
import json
import datetime
import traceback
import threading
import time
from parallelizable_relation_analysis import *
from dynamic_dep_graph import *
from util import *
from ra_util import *

PORT = parse_relation_analysis_port()
#dd = None
curr_dir = os.path.dirname(os.path.realpath(__file__))
debug_log_dir = "ra_worker_debug_logs"
num_processor = parse_relation_analysis_parallelization_factor()

def run_task(id, pipe, prog, arg, path, starting_events, starting_insn_to_weight, steps,
        other_indices_map, other_indices_map_inner, other_simple_relation_groups, node_avg_timestamps):
    dd = DynamicDependence(starting_events, prog, arg, path, starting_insn_to_weight)
    dd.prepare_to_build_dynamic_dependencies(steps)
    #StaticDepGraph.build_postorder_list()
    #StaticDepGraph.build_postorder_ranks()
    pipe.send("ready")
    while True:
        obj = pipe.recv()
        if obj == "Shutdown":
            break
        print("[worker] Process {} recive task {}".format(id, obj))
        start_time = datetime.datetime.now()
        ret = {}
        segs = obj.split("|")
        insn = int(segs[0], 16)
        func = segs[1]
        graph = StaticDepGraph.get_graph(func, insn)
        node = graph.insn_to_node[insn]
        starting_weight = float(segs[2])
        max_contrib = float(segs[3])
        try:
            old = sys.stdout
            old_e = sys.stderr
            f = open(os.path.join(curr_dir, debug_log_dir, hex(insn) + "_graph.log"), 'w')
            sys.stdout = f
            sys.stderr = f
            a = time.time()
            dgraph = dd.build_dynamic_dependencies(insn=insn, pa_id=id)
            wavefront, rgroup = ParallelizableRelationAnalysis.one_pass(dgraph, node, starting_weight, max_contrib, prog,
                                                                             other_indices_map, \
                                                                             other_indices_map_inner,
                                                                             other_simple_relation_groups,\
                                                                             node_avg_timestamps)

            print("WAVEFRONT: " + str(wavefront))
            print("RGOUP: " + str(rgroup))
            b = time.time()
            print("analyzing " + str(obj) + " took " + str(b - a))
            f.close()
            sys.stdout = old
            sys.stderr = old_e

            ret[insn] = ([(str(w.insn) + "@" + w.function) for w in wavefront], rgroup.toJSON() if rgroup is not None else None)
        except Exception as e:
            ret[insn] = (None, None)
            print("[rr][ERROR] Process {} failed for input: {}".format(id, str(obj)))
            print(str(e))
            print("-" * 60)
            traceback.print_exc(file=sys.stdout)
            print("-" * 60)

        duraton = datetime.datetime.now() - start_time
        print("[worker] Process {} finish task {} in {}".format(id, obj, duraton))
        pipe.send(ret)  # TODO
    print("[worker] Process {} finished execution.".format(id), flush=True)
    pipe.send("Shutdown")


def main():
    ra_worker_ready_file = os.path.join(curr_dir, "ra_worker_ready")

    if os.path.exists(ra_worker_ready_file):
        os.remove(ra_worker_ready_file)

    if not os.path.exists(os.path.join(curr_dir, debug_log_dir)):
        os.makedirs(os.path.join(curr_dir, debug_log_dir))

    limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()
    _, _, _, other_relations_file, other_indices_file = parse_relation_analysis_inputs()

    processes = []
    pipes = []

    dd = DynamicDependence(starting_events, program, program_args, program_path, starting_insn_to_weight)
    dd.prepare_to_build_dynamic_dependencies(limit)

    print("[ra] Getting the average timestamp of each unique node in the dynamic trace")
    if not os.path.exists(dd.trace_path + ".avg_timestamp"):
        preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'count_node')
        pp_process = subprocess.Popen([preprocessor_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = pp_process.communicate()
        print(stdout)
        print(stderr)
    node_avg_timestamps = load_node_info(dd.trace_path + ".avg_timestamp")
    print("[ra] Finished getting the average timestamp of each unique node in the dynamic trace")
    
    if other_indices_file is not None:
        other_indices_file_path = os.path.join(curr_dir, "cache", program, other_indices_file)
        other_indices_map = load_indices(other_indices_file_path)
    
    if other_indices_file is not None:
        other_indices_file_path_inner = os.path.join(curr_dir, "cache", program, other_indices_file + "_inner")
        other_indices_map_inner = load_indices(other_indices_file_path_inner)
    
    if other_relations_file is not None:
        other_relations_file_path = os.path.join(curr_dir, "cache", program, other_relations_file)
        other_simple_relation_groups = RelationAnalysis.load_simple_relations(other_relations_file_path)

    preparse_cmd = "./preprocessor/preprocess_parallel " + dd.trace_path + " > preparser_out &"
    print("Starting preparser with command: " + preparse_cmd)
    os.system(preparse_cmd)

    mp.set_start_method('spawn')
    for i in range(num_processor):
        parent_conn, child_conn = mp.Pipe(duplex=True)
        p = mp.Process(target=run_task, args=(i, child_conn, program, program_args, program_path, starting_events, starting_insn_to_weight, limit,
                                              other_indices_map, other_indices_map_inner, other_simple_relation_groups, node_avg_timestamps))
        p.start()
        processes.append(p)
        pipes.append(parent_conn)

    for pipe in pipes:
        ret = pipe.recv()
        assert ret.strip() == "ready"
        
    print("[server] All workers are ready")
    f = open(ra_worker_ready_file, "w")
    f.write("ready")
    f.close()

    print("[server] Setting up sockets")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((socket.gethostname(), PORT))
    listener.listen(num_processor)

    try:
        while True:
            (client, addr) = listener.accept()
            print("[server] Getting connection from {}".format(addr))

            def connect_bridge(socket, pipe):
                while True:
                    line = socket.recv(4096).decode().strip()
                    print("[server] Receive from socket: {}".format(line), flush=True)
                    if line == "":
                        pipes.append(pipe)
                        return

                    print("[server] Sending task {}".format(line), flush=True)
                    pipe.send(line)
                    print("[server] Sent task {}".format(line), flush=True)

                    ret = pipe.recv()
                    print("[server] Receiving result for task {}".format(line), flush=True)
                    result = json.dumps(ret).encode()
                    socket.send(result)
                    print("[server] Sent result for task {}".format(line) + " len is " + str(len(result)), flush=True)

            if len(pipes) > 0:
                pipe = pipes.pop()
                threading.Thread(target=connect_bridge, args=(client, pipe)).start()

    except KeyboardInterrupt:
        pass
    listener.close()
    for i in range(num_processor):
        processes[i].join()
    print("Worker processes finished running")
    with os.popen("ps ax | grep \"preprocess_parallel\" | grep -v grep") as p:
        lines = p.readlines()
        for line in lines:
            fields = line.split()
            child_pid = int(fields[0])
            print("Trying to kill process " + str(child_pid), flush=True)
            os.system("kill -9 " + str(child_pid))

if __name__ == '__main__':
    main()
