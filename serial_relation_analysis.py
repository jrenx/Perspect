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
import itertools
from util import *
from relation_analysis import *

DEBUG = True
Weight_Threshold = 0
curr_dir = os.path.dirname(os.path.realpath(__file__))
RECURSIVE = False

class SerialRelationAnalysis(RelationAnalysis):
    def analyze(self):
        a = time.time()
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
            wavefront.append((None, graph.insn_to_node[insn], 0))
        while len(wavefront) > 0:
            curr_weight, starting_node, curr_max_contrib = wavefront.popleft()
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
            print("[ra] Relational analysis, pass number: " + str(iteration) + " insn: " + hex(insn) + " weight: " +
                  str(100 if curr_weight is None else curr_weight.total_weight) +
                  " max weight: " + str(max_contrib))
            starting_node.print_node("[ra] starting static node: ")

            try:
                dgraph = self.dd.build_dynamic_dependencies(insn=insn)
            except Exception as e:
                print("Caught exception in building dynamic graph for " + hex(insn) + ": " + str(e))
                print(str(e))
                print("-" * 60)
                traceback.print_exc(file=sys.stdout)
                print("-" * 60)
                continue

            curr_wavefront, rgroup = ParallelizableRelationAnalysis.one_pass(dgraph, starting_node, \
                                          (0 if curr_weight is None else curr_weight.total_weight), \
                                                                       curr_max_contrib, self.prog, \
                                                                             self.other_indices_map, \
                                                                             self.other_indices_map_inner,
                                                                             self.other_simple_relation_groups,\
                                                                             self.node_avg_timestamps)
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
                    print("\nwavelet " + hex(wavelet.insn) + "@" + wavelet.function + " already visited...")
                    continue
                visited.add(wavelet)
                if self.explained_by_invariant_relation(wavelet):
                    print("\nwavelet " + hex(wavelet.insn) + "@" + wavelet.function + " has a node forward and backward invariant already explained...")
                    continue


                if RECURSIVE is True:
                    wavefront.append((weight, wavelet, max_contrib))
                starting_weight = 0 if weight is None else weight.total_weight
                self.print_wavelet(weight, wavelet, "NEW")

            print("=======================================================================")
            #wavefront = sorted(wavefront, key=lambda weight_and_node: weight_and_node[0])
            for weight, starting_node, _ in wavefront:
                self.print_wavelet(weight, starting_node, "ALL")

        self.sort_and_output_results()

        b = time.time()
        print("[ra] took " + str(b-a))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--use_cache', dest='use_cache', action='store_true')
    parser.set_defaults(use_cache=False)
    args = parser.parse_args()

    limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()
    _, _, _, other_relations_file, other_indices_file = parse_relation_analysis_inputs()
    ra = SerialRelationAnalysis(starting_events, program, program_args, program_path, limit,
                          starting_insn_to_weight,
                          other_indices_file=other_indices_file,
                          other_relations_file=other_relations_file)

    if args.use_cache is True:
        StaticDepGraph.build_dependencies(starting_events, program, limit=limit)
        rgroup_file = os.path.join(curr_dir, 'cache', program, "rgroups.json")
        ra.relation_groups = RelationAnalysis.fetch_cached_rgroup(rgroup_file, program)
        ra.sort_and_output_results()
    else:
        ra.cleanup()
        ra.analyze()
