import sys
import os
import shutil
import multiprocessing as mp
import threading
import socket
import json
import datetime
import traceback
from dynamic_dep_graph import *
from parallelizable_relation_analysis import *

PORT = 15000
dd = None

def run_task(id, pipe, prog, arg, path, starting_events):
    dd = DynamicDependence(starting_events, prog, arg, path)
    dd.prepare_to_build_dynamic_dependencies(10000)
    #StaticDepGraph.build_postorder_list()
    #StaticDepGraph.build_postorder_ranks()
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
        node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]
        starting_weight = int(segs[2])
        max_contrib = int(segs[3])
        try:
            dgraph = dd.build_dynamic_dependencies(insn=insn, pa_id=id)
            wavefront, rgroup = ParallelizableRelationAnalysis.one_pass(dgraph, node, starting_weight, max_contrib)

            ret[insn] = ([(str(w.insn) + "@" + w.function) for w in wavefront], rgroup.toJSON())
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
    prog = "909_ziptest_exe9"
    arg = "test.zip"
    path = "/home/anygroup/perf_debug_tool/"
    starting_events = []
    starting_events.append(["rdi", 0x409daa, "sweep"])
    starting_events.append(["rbx", 0x407240, "runtime.mallocgc"])
    starting_events.append(["rdx", 0x40742b, "runtime.mallocgc"])
    starting_events.append(["rcx", 0x40764c, "runtime.free"])

    num_processor = 16

    processes = []
    pipes = []

    mp.set_start_method('spawn')
    for i in range(num_processor):
        parent_conn, child_conn = mp.Pipe(duplex=True)
        p = mp.Process(target=run_task, args=(i, child_conn, prog, arg, path, starting_events))
        p.start()
        processes.append(p)
        pipes.append(parent_conn)

    print("[server] Setting up sockets")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((socket.gethostname(), PORT))
    listener.listen(16)

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
                socket.send(json.dumps(ret).encode())
                print("[server] Sent result for task {}".format(line), flush=True)

        if len(pipes) > 0:
            pipe = pipes.pop()
            threading.Thread(target=connect_bridge, args=(client, pipe)).start()

    for i in range(num_processor):
        processes[i].join()


if __name__ == '__main__':
    main()
