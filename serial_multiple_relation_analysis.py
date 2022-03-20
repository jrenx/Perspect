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

class SerialMultipleRelationAnalysis(RelationAnalysis):
    def analyze(self, insns, use_cache=False):
        print(use_cache)
        a = time.time()

        #print(self.rgroup_file)
        #if use_cache is True:
        #    file_exists = self.fetch_cached_rgroup()
        #    if file_exists:
        #        return

        try:
            starting_insn_to_dynamic_graph = self.dd.build_multiple_dynamic_dependencies(insns)
        except Exception as e:
            print("Caught exception in building multiple dynamic graphs.")
            print(str(e))
            print("-" * 60)
            traceback.print_exc(file=sys.stdout)
            print("-" * 60)
            return

        for insn in starting_insn_to_dynamic_graph.keys():
            dgraph = starting_insn_to_dynamic_graph[insn]
            dynamic_node = next(iter(dgraph.insn_to_dyn_nodes[insn]))
            func = dynamic_node.static_node.function
            print("[ra] function is: " + str(func) + " insn is: " + hex(insn))
            graph = StaticDepGraph.get_graph(func, insn)
            starting_node = graph.insn_to_node[insn]
            curr_wavefront, rgroup = ParallelizableRelationAnalysis.one_pass(dgraph, starting_node, 100, 100, self.prog, \
                                                                             None, None, None, None)
            print("[ra] Got results for: " + hex(starting_node.insn))
            assert rgroup is not None
            rgroup.sort_relations()
            self.relation_groups.append(rgroup)


        self.rgroup_file = os.path.join(curr_dir, 'cache', self.prog, "multiple_rgroups.json")
        self.simple_rgroup_file = os.path.join(curr_dir, "cache", self.prog, "multiple_rgroups_simple_" + self.dd.key + ".json")

        self.print_rgroups(self.relation_groups)

        json_rgroups = []
        json_rgroups_simple = []
        for relation_group in self.relation_groups:
            json_rgroups.append(relation_group.toJSON())
            json_rgroups_simple.append(SimpleRelationGroup.toJSON(relation_group))

        print("[ra] Writing to " + self.simple_rgroup_file)
        with open(self.simple_rgroup_file, 'w') as f:
            json.dump(json_rgroups_simple, f, indent=4)

        print("[ra] Writing to " + self.rgroup_file)
        with open(self.rgroup_file, 'w') as f:
            json.dump(json_rgroups, f, indent=4)

        #self.sort_and_output_results()

        b = time.time()
        print("[ra] took " + str(b-a))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--use_cache', dest='use_cache', action='store_true')
    parser.add_argument('-if', '--multiple_insns_file', dest='multiple_insns_file', type=str)
    parser.set_defaults(use_cache=False)
    args = parser.parse_args()

    limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()
    _, _, _, other_relations_file, other_indices_file = parse_relation_analysis_inputs()
    ra = SerialMultipleRelationAnalysis(starting_events, program, program_args, program_path, limit,
                          starting_insn_to_weight,
                          other_indices_file=other_indices_file,
                          other_relations_file=other_relations_file)
    multiple_insns = []
    with open(args.multiple_insns_file, "r") as f:
        for l in f.readlines():
            multiple_insns.append(int(l.strip()))
    ra.analyze(multiple_insns, args.use_cache)
