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
from parallelizable_relation_analysis import *
from relations import *

DEBUG = True
Weight_Threshold = 0

class RelationAnalysis:
    #negative_event_map = {}
    def __init__(self, starting_events, insn, func, prog, arg, path):
        self.starting_insn = insn
        self.starting_func = func
        self.prog = prog
        self.path = path
        self.prede_node_to_invariant_rel = {}
        self.node_counts = {}
        self.static_node_to_weight = {}

        self.dd = DynamicDependence(starting_events, prog, arg, path)
        self.dd.prepare_to_build_dynamic_dependencies(10000)
        print("[ra] Getting the counts of each unique node in the dynamic trace")
        if not os.path.exists(self.dd.trace_path + ".count"):
            preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'count_node')
            pp_process = subprocess.Popen([preprocessor_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = pp_process.communicate()
            print(stdout)
            print(stderr)
        self.load_node_counts(self.dd.trace_path + ".count")
        print("[ra] Finished getting the counts of each unique node in the dynamic trace")
        self.relation_groups = [] #results

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
        if prede_node.insn not in self.node_counts:
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
            if prede_node in self.static_node_to_weight:
                if self.static_node_to_weight[prede_node] < weight:
                    self.static_node_to_weight[prede_node] = weight
                    print("[ra] Updating weight for node: " + prede_node.hex_insn + "@" + prede_node.function)
            else:
                self.static_node_to_weight[prede_node] = weight

    def get_weighted_wavefront(self, curr_wavefront):
        unique_wavefront = set()
        curr_weighted_wavefront = []
        for wavelet in curr_wavefront:
            if wavelet in unique_wavefront:
                continue
            unique_wavefront.add(wavelet)
            if wavelet not in self.static_node_to_weight:
                print("[ra][warn] no weight " + str(wavelet.hex_insn))
            else:
                weight = self.static_node_to_weight[wavelet]
                curr_weighted_wavefront.append((weight, wavelet))
        curr_weighted_wavefront = sorted(curr_weighted_wavefront, key=lambda weight_and_node: weight_and_node[0])
        return curr_weighted_wavefront

    def analyze(self, use_cache=False):
        print(use_cache)
        a = time.time()
        cache_file = os.path.join(self.path, "cache", self.prog, "rgroups.json")
        print(cache_file)
        if use_cache is True:
            if os.path.exists(cache_file):
                with open(cache_file) as f:
                    json_rgroups = json.load(f)
                    rgroups = []
                    for json_rgroup in json_rgroups:
                        rgroups.append(RelationGroup.fromJSON(json_rgroup, self.prog))
                    self.print_rgroups(rgroups)
                return

        self.dd.prepare_to_build_dynamic_dependencies(10000)
        #TODO, do below in the static graph logic
        StaticDepGraph.build_postorder_list()
        StaticDepGraph.build_postorder_ranks()
        #print(len(StaticDepGraph.postorder_list))
        #print(len(StaticDepGraph.postorder_ranks))

        insn = self.starting_insn
        func = self.starting_func
        visited = set()
        wavefront = deque()

        iteration = 0
        max_contrib = 0

        wavefront.append((None, StaticDepGraph.func_to_graph[func].insn_to_node[insn], 0))
        while len(wavefront) > 0:
            curr_weight, starting_node, curr_max_contrib = wavefront.popleft()
            if starting_node is not None:
                insn = starting_node.insn
                func = starting_node.function

            if self.explained_by_invariant_relation(starting_node):
                print("\n" + hex(insn) + "@" + func + " has a node forward and backward invariant already explained...")
                continue

            iteration += 1
            print("\n=======================================================================", flush=True)
            print("[ra] Relational analysis, pass number: " + str(iteration) + " insn: " + hex(insn) + " weight: " +
                  str(100 if curr_weight is None else curr_weight.total_weight) +
                  " max weight: " + str(max_contrib))
            starting_node.print_node("[ra] starting static node: ")

            try:
                dgraph = self.dd.build_dynamic_dependencies(insn=insn)
            except Exception as e:
                print("Caught exception in building dynamic graph for " + str(insn) + ": " + str(e))
                print(str(e))
                print("-" * 60)
                traceback.print_exc(file=sys.stdout)
                print("-" * 60)

            curr_wavefront, rgroup = ParallelizableRelationAnalysis.one_pass(dgraph, starting_node, (0 if curr_weight is None else curr_weight.total_weight), curr_max_contrib, self.prog)
            print("[ra] Got results for: " + hex(starting_node.insn))
            if rgroup is None:
                continue

            updated_weight = rgroup.weight
            if starting_node in self.static_node_to_weight:
                updated_weight = self.static_node_to_weight[starting_node].total_weight
                if rgroup.weight is None: # or rgroup.weight != self.static_node_to_weight[starting_node].total_weight:
                    #TODO print
                    rgroup.add_base_weight(self.static_node_to_weight[starting_node].total_weight)

            if updated_weight < (max_contrib * 0.01):
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

                wavefront.append((weight, wavelet, max_contrib))
                starting_weight = 0 if weight is None else weight.total_weight
                self.print_wavelet(weight, wavelet, "NEW")

            print("=======================================================================")
            #wavefront = sorted(wavefront, key=lambda weight_and_node: weight_and_node[0])
            for weight, starting_node, _ in wavefront:
                self.print_wavelet(weight, starting_node, "ALL")

        self.relation_groups = sorted(self.relation_groups, key=lambda rg: rg.weight)
        self.relation_groups = self.relation_groups[::-1] #reverse the list
        self.print_rgroups(self.relation_groups)
        b = time.time()
        print("[ra] took " + str(b-a))
        json_rgroups = []
        for relation_group in self.relation_groups:
            json_rgroups.append(relation_group.toJSON())
        with open(cache_file, 'w') as f:
            json.dump(json_rgroups, f, indent=4)

    def print_rgroups(self, relation_groups):
        num_rels = 0
        for relation_group in relation_groups:
            num_rels += len(relation_group.relations)
            assert len(relation_group.relations) == len(relation_group.sorted_relations)
            print(relation_group)
        print("[ra] Total number of relations groups: " + str(len(relation_groups)))
        print("[ra] Total number of relations: " + str(num_rels))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--use_cache', dest='use_cache', action='store_true')
    parser.set_defaults(use_cache=False)
    args = parser.parse_args()

    starting_events = []
    starting_events.append(["rdi", 0x409daa, "sweep"])
    starting_events.append(["rbx", 0x407240, "runtime.mallocgc"])
    starting_events.append(["rdx", 0x40742b, "runtime.mallocgc"])
    starting_events.append(["rcx", 0x40764c, "runtime.free"])

    ra = RelationAnalysis(starting_events, 0x409daa, "sweep", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool_dev_jenny/")
    ra.analyze(args.use_cache)
