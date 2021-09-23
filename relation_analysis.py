import time
import heapq
import numpy as np
from scipy.stats import norm
import subprocess
import socketserver
import threading
import queue
from dynamic_dep_graph import *
from relations import *

DEBUG = True
Weight_Threshold = 0
worker_addresses = [("10.1.0.21", 15000), ("10.1.0.22", 15000), ("10.1.0.23", 15000), ("10.10.0.33", 15000)]

def sender(q, results_q):
    sockets = []
    for addr in worker_addresses:
        for _ in range(16):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("[client] Connecting to {}".format(addr), flush=True)
            s.connect(addr)
            print("[client] Connected to {}".format(addr), flush=True)
            sockets.append(s)

    print("[client] Sending initial tasks", flush=True)
    closed_sockets = set()
    for s in sockets:
        while q.empty():
            continue
        line = q.get()

        if line.startswith("FIN"):
            print("[client] Received FIN", flush=True)
            s.close()
            q.put(line)
            closed_sockets.add(s)
            continue

        print("[client] Sending task {}".format(line), flush=True)
        s.send(line.encode())
        print("[client] Sent task {}".format(line), flush=True)
    sockets = [s for s in sockets if s not in closed_sockets]

    print("[client] Waiting for results", flush=True)
    while len(sockets) > 0:
        read_sockets, _, _ = select.select(sockets, [], [])

        for s in read_sockets:
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
                sockets.remove(s)
                continue
            ret = json.loads(ret)
            print("[client] Receiving result for task {}".format(list(ret.keys())[0] if (len(ret) > 0) else ""), flush=True)
            results_lock.acquire()
            results_q.put(ret)
            #TODO, start a connection and send to relation_analysis

            while q.empty():
                continue
            line = q.get()
            print("[client] Get task {}".format(line))
            if line.startswith("FIN"):
                print("[client] Received FIN", flush=True)
                s.close()
                q.put(line)
                sockets.remove(s)
                break

            print("[client] Sending task {}".format(line), flush=True)
            s.send(line.encode())
            print("[client] Sent task {}".format(line), flush=True)

class RelationAnalysis:
    #negative_event_map = {}
    def __init__(self, starting_events, insn, func, prog, arg, path):
        self.starting_insn = insn
        self.starting_func = func
        self.prede_node_to_invariant_rel = {}
        self.node_counts = {}
        self.static_node_to_weight = {}

        self.received_results = queue.Queue()
        self.received_cache = {}
        self.pending_inputs = queue.Queue()

        preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'count_node')
        pp_process = subprocess.Popen([preprocessor_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = pp_process.communicate()
        print(stdout)
        print(stderr)
        self.load_node_counts(self.dd.trace_path + ".count")
        self.relation_groups = {} #results

    def add_to_explained_variant_relation(self, rgroup):
        for rel in rgroup.relations.values():
            if isinstance(rel.forward, Invariance) and \
                isinstance(rel.backward, Invariance):
                #self.invariant_predes.add(rel.prede_node)

                if rel.prede_node not in self.prede_node_to_invariant_rel:
                    self.prede_node_to_invariant_rel[rel.prede_node] = []
                self.prede_node_to_invariant_rel[rel.prede_node].append(rel)

    def explained_by_invariant_relation(self, prede_node):
        if prede_node not in self.prede_node_to_invariant_rel:
            return False
        print(self.node_counts)
        full_count = self.node_counts[prede_node.insn]
        for rel in self.prede_node_to_invariant_rel[prede_node]:
            print("[ra] Testing if " + prede_node.hex_insn + "@" + prede_node.function + " is fully explained... "
                  + " full count: " + str(full_count) + " count in relation: " + str(rel.prede_count))
            if full_count == rel.prede_count:
                return True
        return False
    
    def load_node_counts(self, count_file_path):
        print("[ra] Loading node counts from file: " + str(count_file_path))
        with open(count_file_path, 'r') as f: #TODO
            for l in f.readlines():
                insn = int(l.split()[0], 16)
                count = int(l.split()[1])
                self.node_counts[insn] = count

    def setup(self):
        sender_receiver_t = threading.Thread(target=sender,
                                    args=(self.pending_inputs, self.received_results, self.received_results_lock))
        sender_receiver_t.start()

        self.dd.prepare_to_build_dynamic_dependencies(10000)
        #TODO, do below in the static graph logic
        StaticDepGraph.build_postorder_list()
        StaticDepGraph.build_postorder_ranks()
        #print(len(StaticDepGraph.postorder_list))
        #print(len(StaticDepGraph.postorder_ranks))

    def print_wavelet(self, weight, starting_node, type):
        print("[ra] "
                        # + " weight " + str("{:.2f}".format(weight.contrib)) + " " + str("{:.2f}".format(weight.corr))
                        + str(weight)
                        + " " + str(type) + " pending node: " + starting_node.hex_insn
                        + "@" + starting_node.function
                        + " lines " + (str(starting_node.bb.lines) if isinstance(starting_node.bb, BasicBlock) else str(
            starting_node.bb)))

    def update_weights(self, rgroup):
        for prede_node in rgroup.relations:
            weight = rgroup.relations[prede_node].weight
            if prede_node in static_node_to_weight:
                if self.static_node_to_weight[prede_node] < weight:
                    self.static_node_to_weight[prede_node] = weight
                    print("[ra] Updating weight for node: " + prede_node.hex_insn + "@" + prede_node.function)
            else:
                self.static_node_to_weight[prede_node] = weight

    def get_weighted_wavefront(self, curr_wavefront):
        curr_weighted_wavefront = []
        for wavelet in curr_wavefront:
            if wavelet in unique_wavefront:
                continue
            unique_wavefront.add(wavelet)
            if wavelet not in static_node_to_weight:
                print("[ra][warn] no weight " + str(wavelet.hex_insn))
            else:
                weight = self.static_node_to_weight[wavelet]
                curr_weighted_wavefront.append((weight, wavelet))
        curr_weighted_wavefront = sorted(curr_weighted_wavefront, key=lambda weight_and_node: weight_and_node[0])
        return curr_weighted_wavefront

    def analyze(self):
        self.setup()
        insn = self.starting_insn
        func = self.starting_func
        visited = set()
        wavefront = deque()

        iteration = 0
        max_contrib = 0

        wavefront.append((StaticDepGraph.func_to_graph[func].insn_to_node[insn], None))
        while len(wavefront) > 0:
            curr_weight, starting_node = wavefront.popleft()
            insn = next.insn
            func = next.function

            if self.explained_by_invariant_relation(starting_node):
                print("\n" + hex(insn) + "@" + func + " has a node forward and backward invariant already explained...")
                continue

            iteration += 1
            print("\n=======================================================================", flush=True)
            print("Relational analysis, pass number: " + str(iteration) + " weight: " +
                  str(100 if curr_weight is None else curr_weight.total_contrib) +
                  " max weight: " + str(max_contrib))
            starting_node.print_node("[ra] starting static node: ", flush=True)

            while starting_node.insn not in self.received_cache:
                ret = self.received_cache.get()
                for (key, value) in ret.items():
                    self.received_cache[key] = value
            (curr_wavefront, rgroup) = self.received_cache[key]

            if rgroup is None:
                continue

            if rgroup.base_contrib is None or rgroup.base_contrib != self.static_node_to_weight[starting_node]:
                #TODO print
                rgroup.add_base_contrib(self.static_node_to_weight[starting_node])

            if rgroup.weight < (max_contrib * 0.01):
                print("[ra] Base weight is less than 1% of the max weight, ignore the node "
                      + starting_node.hex_insn + "@" + starting_node.function)
                continue

            rgroup.sorted_relations()
            self.relation_groups[starting_node] = rgroup
            self.add_to_explained_variant_relation(rgroup)

            self.update_weights(rgroup)
            if rgroup.weight > max_contrib: max_contrib = rgroup.weight

            curr_weighted_wavefront = self.get_weighted_wavefront(curr_wavefront)
            print("=======================================================================")
            for weight, starting_node in curr_weighted_wavefront:
                if starting_node in visited:
                    print("\n" + hex(starting_node.insn) + "@" + starting_node.func + " already visited...")
                    continue
                visited.add(starting_node)
                if self.explained_by_invariant_relation(starting_node):
                    print("\n" + hex(starting_node.insn) + "@" + starting_node.func + " has a node forward and backward invariant already explained...")
                    continue

                wavefront.append((weight, wavelet))
                starting_weight = 0 if weight is None else weight.total_weight,
                self.pending_inputs.put(starting_node.hex_insn + "|" + starting_node.func + "|" + str(starting_weight) + "|" + str(max_contrib))
                self.print_wavelet(weight, starting_node, "NEW")

            print("=======================================================================")
            #wavefront = sorted(wavefront, key=lambda weight_and_node: weight_and_node[0])
            for weight, starting_node in wavefront:
                self.print_wavelet(weight, starting_node, "ALL")

            #break #TODO
        self.relation_groups = sorted(self.relation_groups, key=lambda rg: rg.weight)
        num_rels = 0
        for relation_group in reversed(self.relation_groups):
            num_rels += len(relation_group.relations)
            assert len(relation_group.relations) == len(relation_group.sorted_relations)
            print(relation_group)
        print("[ra] Total number of relations groups: " + str(len(self.relation_groups)))
        print("[ra] Total number of relations: " + str(num_rels))


if __name__ == "__main__":
    starting_events = []
    starting_events.append(["rdi", 0x409daa, "sweep"])
    starting_events.append(["rbx", 0x407240, "runtime.mallocgc"])
    starting_events.append(["rdx", 0x40742b, "runtime.mallocgc"])
    starting_events.append(["rcx", 0x40764c, "runtime.free"])

    ra = RelationAnalysis(starting_events, 0x409daa, "sweep", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")
    ra.analyze()
