from json.decoder import JSONDecodeError
import time
import heapq
import numpy as np
from scipy.stats import norm
import subprocess
import socketserver
import socket
import threading
import queue
import sys
import os
import select
import json
import traceback
from dynamic_dep_graph import *
from relations import *
from util import *
from relation_analysis import *

DEBUG = True
Weight_Threshold = 0
#worker_addresses = [("10.1.0.23", 15000)]
curr_dir = os.path.dirname(os.path.realpath(__file__))

def sender_receiver_worker(s, q, results_q):
    try:
        while True:
            while q.empty():
                continue
            line = q.get()

            if line.startswith("FIN"):
                print("[sender_receiver] Received FIN, closing connection", flush=True)
                #s.send(("Shutdown").encode())
                s.close()
                q.put(line)
                return

            print("[sender_receiver] Sending task {}".format(line), flush=True)
            s.send(line.encode())
            print("[sender_receiver] Sent task {}".format(line), flush=True)
            read_sockets, _, _ = select.select([s], [], [])

            s = read_sockets[0]
            # Parse results
            chunks = []
            while True:
                chunks.append(s.recv(4096))
                ret = b''.join(chunks).decode()
                if ret == "":
                    break
                try:
                    json.loads(ret)
                except JSONDecodeError:
                    continue
                break
            ret = b''.join(chunks).decode()
            if ret == "": # Server should not close the socket. Only for precaution
                s.close()
                print("[sender_receiver] Received empty string, closing connection", flush=True)
                return
            ret = json.loads(ret)
            print("[sender_receiver] Receiving result for task {}".format(hex(int(list(ret.keys())[0])) if (len(ret) > 0) else ""), flush=True)
            results_q.put(ret)
    except Exception as e:
        print("Caught exception in sender receiver thread: " + str(e))
        print(str(e))
        print("-" * 60)
        traceback.print_exc(file=sys.stdout)
        print("-" * 60)
        s.close()

def sender_receiver(q, results_q):
    sockets = []
    threads = []
    num_processor = 8
    port = 15000
    worker_addresses = []
    with open("servers.config", "r") as f:
        for l in f.readlines():
            worker_addresses.append((l.strip(), port))
    for addr in worker_addresses:
        for _ in range(num_processor):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print("[sender_receiver] Connecting to {}".format(addr), flush=True)
                s.connect(addr)
            except Exception as e:
                print("Caught exception in sender receiver loop: " + str(e))
                print(str(e))
                print("-" * 60)
                traceback.print_exc(file=sys.stdout)
                print("-" * 60)
                continue
            print("[sender_receiver] Connected to {}".format(addr), flush=True)
            sockets.append(s)
            t = threading.Thread(target=sender_receiver_worker, args=(s, q, results_q))
            t.start()
            threads.append(t)
    print("[sender_receiver] Finished setting up connections", flush=True)
    for t in threads:
        t.join()


class ParallelRelationAnalysis(RelationAnalysis):
    def analyze(self, use_cache=False):
        print(use_cache)
        a = time.time()

        print(self.rgroup_file)
        if use_cache is True:
            file_exists = self.fetch_cached_rgroup()
            if file_exists:
                return

        received_results = queue.Queue()
        received_cache = {}
        pending_inputs = queue.Queue()

        sender_receiver_t = threading.Thread(target=sender_receiver,
                                    args=(pending_inputs, received_results))
        sender_receiver_t.start()

        try:
            #self.dd.prepare_to_build_dynamic_dependencies(self.steps)
            #TODO, do below in the static graph logic
            #StaticDepGraph.build_postorder_list()
            #StaticDepGraph.build_postorder_ranks()
            #print(len(StaticDepGraph.postorder_list))
            #print(len(StaticDepGraph.postorder_ranks))

            visited = set()
            wavefront = deque()

            iteration = 0
            max_contrib = 0

            for starting_event in self.starting_events:
                insn = starting_event[1]
                func = starting_event[2]
                graph = StaticDepGraph.get_graph(func, insn)
                if graph is None:
                    continue
                wavefront.append((None, graph.insn_to_node[insn]))
                pending_inputs.put(hex(insn) + "|" + func + "|" + str(0) + "|" + str(0))
            while len(wavefront) > 0:
                curr_weight, starting_node = wavefront.popleft()
                if starting_node is not None:
                    insn = starting_node.insn
                    func = starting_node.function

                key = None
                if self.other_simple_relation_groups is not None:
                    key = self.other_simple_relation_groups.indices.get_indices(starting_node)

                if key is None and self.explained_by_invariant_relation(starting_node):
                    print("\n" + hex(insn) + "@" + func + " has a node forward and backward invariant already explained...")
                    continue

                if self.other_indices_map is not None and self.other_indices_map.indices_not_found(starting_node):
                    #prede_explained = False
                    #for p in itertools.chain(starting_node.df_predes, starting_node.cf_predes):
                    #    if self.other_indices_map.get_indices(p) is not None:
                    #        prede_explained = True
                    #        break
                    #if prede_explained is False:
                    print("\n" + hex(insn) + "@" + func + " is not found in the other repro's static slice...")
                    continue

                iteration += 1
                print("\n=======================================================================", flush=True)
                print("[ra] Relational analysis, pass number: " + str(iteration) + " weight: " +
                      str(100 if curr_weight is None else curr_weight.total_weight) +
                      " max weight: " + str(max_contrib))
                starting_node.print_node("[ra] starting static node: ")

                print("[ra] Waiting results for: " + hex(starting_node.insn))
                while starting_node.insn not in received_cache:
                    ret = received_results.get()
                    for (key, value) in ret.items():
                        print("[ra] Getting results for: " + hex(int(key)))
                        curr_wavefront = []
                        rgroup = None
                        if value[0] is not None and value[1] is not None:
                            for node_str in value[0]:
                                segs = node_str.split("@")
                                graph = StaticDepGraph.get_graph(segs[1], int(segs[0]))
                                wavelet = graph.insn_to_node[int(segs[0])]
                                curr_wavefront.append(wavelet)
                            rgroup = RelationGroup.fromJSON(value[1], self.prog)
                        received_cache[int(key)] = (curr_wavefront, rgroup)
                        print("[ra] Done getting results for: " + hex(int(key)))
                (curr_wavefront, rgroup) = received_cache[starting_node.insn]
                print("[ra] Got results for: " + hex(starting_node.insn))
                if rgroup is None:
                    continue

                updated_weight = rgroup.weight
                if starting_node in self.static_node_to_weight:
                    updated_weight = self.static_node_to_weight[starting_node].total_weight
                    if rgroup.weight is None: # or rgroup.weight != self.static_node_to_weight[starting_node].total_weight:
                        #TODO print
                        rgroup.add_base_weight(self.static_node_to_weight[starting_node].total_weight)

                if key is None and updated_weight < (max_contrib * 0.01):
                    print("[ra] Base weight is less than 1% of the max weight, ignore the node "
                          + starting_node.hex_insn + "@" + starting_node.function)
                    continue

                rgroup.sort_relations()
                self.relation_groups.append(rgroup)
                self.add_to_explained_variant_relation(rgroup)

                self.update_weights(rgroup)
                if rgroup.weight > max_contrib: max_contrib = rgroup.weight

                curr_weighted_wavefront = self.get_weighted_wavefront(curr_wavefront)
                print("=======================================================================")
                for weight, wavelet in curr_weighted_wavefront:
                    if wavelet in visited:
                        print("\n" + hex(wavelet.insn) + "@" + wavelet.function + " already visited...")
                        continue
                    visited.add(wavelet)
                    if self.explained_by_invariant_relation(wavelet):
                        print("\n" + hex(wavelet.insn) + "@" + wavelet.function + " has a node forward and backward invariant already explained...")
                        continue

                    wavefront.append((weight, wavelet))
                    starting_weight = 0 if weight is None else weight.total_weight
                    pending_inputs.put(wavelet.hex_insn + "|" + wavelet.function + "|" + str(starting_weight) + "|" + str(max_contrib))
                    self.print_wavelet(weight, wavelet, "NEW")

                print("=======================================================================")
                #wavefront = sorted(wavefront, key=lambda weight_and_node: weight_and_node[0])
                for weight, starting_node in wavefront:
                    self.print_wavelet(weight, starting_node, "ALL")

                #break #TODO
            pending_inputs.put("FIN")
        except Exception as e:
            print("Caught exception in relation analysis loop: " + str(e))
            print(str(e))
            print("-" * 60)
            traceback.print_exc(file=sys.stdout)
            print("-" * 60)
        sender_receiver_t.join()

        self.sort_and_output_results()

        b = time.time()
        print("[ra] took " + str(b-a))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--use_cache', dest='use_cache', action='store_true')
    parser.set_defaults(use_cache=False)
    args = parser.parse_args()

    limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()

    _, _, _, other_relations_file, other_indices_file = parse_relation_analysis_inputs()
    ra = ParallelRelationAnalysis(starting_events, program, program_args, program_path, limit,
                                  starting_insn_to_weight,
                                  other_indices_file=other_indices_file,
                                  other_relations_file=other_relations_file)
    ra.analyze(args.use_cache)
