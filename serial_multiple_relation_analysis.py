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
    def analyze(self, insns, use_cache=False, parent_insn=None):
        print(use_cache)
        a = time.time()

        #print(self.rgroup_file)
        #if use_cache is True:
        #    file_exists = self.fetch_cached_rgroup()
        #    if file_exists:
        #        return

        try:
            if parent_insn is None:
                #Identify instead all the successors of these nodes.
                succe_insns = set()
                for insn in insns:
                    print("[ra] instruction: " + hex(insn))
                    node = self.dd.insn_to_static_node[insn]
                    for succe in itertools.chain(node.cf_succes, node.df_succes):
                        print("[ra]     succe: " + hex(succe.insn))
                        succe_insns.add(succe.insn)
                print(len(succe_insns))
                starting_insn_to_dynamic_graph = self.dd.build_multiple_dynamic_dependencies(succe_insns)
            else:
                starting_insn_to_dynamic_graph = self.dd.build_multiple_dynamic_dependencies_in_context(parent_insn, insns)
        except Exception as e:
            print("Caught exception in building multiple dynamic graphs.")
            print(str(e))
            print("-" * 60)
            traceback.print_exc(file=sys.stdout)
            print("-" * 60)
            return

        for insn in starting_insn_to_dynamic_graph.keys():
            dgraph = starting_insn_to_dynamic_graph[insn]
            if len(dgraph.insn_to_dyn_nodes) == 0:
                print("[ra/warn] dynamic graph starting with insn " + hex(insn) + " has zero nodes, skip!")
                continue
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


        if parent_insn is None:
            self.rgroup_file = os.path.join(curr_dir, 'cache', self.prog, "multiple_rgroups.json")
            self.simple_rgroup_file = os.path.join(curr_dir, "cache", self.prog, "multiple_rgroups_simple_" + self.dd.key + ".json")
        else:
            self.rgroup_file = os.path.join(curr_dir, 'cache', self.prog, "multiple_context_rgroups.json")
            self.simple_rgroup_file = os.path.join(curr_dir, "cache", self.prog, "multiple_context_rgroups_simple_" + self.dd.key + ".json")

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

    def generate_pass_rates(self):
        node_to_succe_pass_rates = {}
        for node in self.dd.insn_to_static_node.values():
            if node.insn not in self.node_counts:
                continue
            total_counts = self.node_counts[node.insn]
            if total_counts == 0:
                continue
            pass_rates = {}
            for succe in itertools.chain(node.cf_succes, node.df_succes):
                if succe.insn not in self.node_counts:
                    continue
                pass_rate = self.node_counts[succe.insn]/total_counts
                if pass_rate == 0:
                    continue
                pass_rates[succe.insn] = pass_rate
            node_to_succe_pass_rates[node.insn] = pass_rates
        pass_rates_file = os.path.join(curr_dir, "cache", self.prog, "pass_rates_" + self.dd.key + ".json")
        with open(pass_rates_file, 'w') as f:
            json.dump(node_to_succe_pass_rates, f, indent=4, ensure_ascii=False)

        def_to_use_site_pass_rates = {}
        for node in self.dd.insn_to_static_node.values():
            if node.insn not in self.node_counts:
                continue
            total_counts = self.node_counts[node.insn]
            if total_counts == 0:
                continue
        
            succe_pass_rates = {}
            for df_succe in node.df_succes:
                visited = set()
                pass_rates = {}
                df_succes = deque()
                df_succes.append(df_succe)
                while len(df_succes) > 0:
                    curr = df_succes.popleft()
                    if curr.insn in visited:
                        continue
                    visited.add(curr.insn)
                    if curr.insn not in node_to_succe_pass_rates:
                        continue
                    #if curr.insn not in self.node_counts:
                    #    continue
                    #curr_counts = self.node_counts[curr.insn]
                    #if curr_counts == 0:
                    #    continue

                    for curr_df_succe in curr.df_succes:
                        df_succes.append(curr_df_succe)
                    for cf_succe in curr.cf_succes:
                        if cf_succe.insn not in node_to_succe_pass_rates[curr.insn]:
                            continue
                        pass_rate = node_to_succe_pass_rates[curr.insn][cf_succe.insn]
                        key = hex(curr.insn) + "_" + hex(cf_succe.insn)
                        assert key not in pass_rates
                        pass_rates[key] = pass_rate
                succe_pass_rates[df_succe.insn] = pass_rates
                
            if len(succe_pass_rates) > 0:
                def_to_use_site_pass_rates[node.insn] = succe_pass_rates
 
        def_to_use_site_pass_rates_file = os.path.join(curr_dir, "cache", self.prog, "pass_rates_def_to_use_site_" + self.dd.key + ".json")
        with open(def_to_use_site_pass_rates_file, 'w') as f:
            json.dump(def_to_use_site_pass_rates, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--use_cache', dest='use_cache', action='store_true')
    parser.set_defaults(use_cache=False)
    parser.add_argument('-if', '--multiple_insns_file', dest='multiple_insns_file', type=str)
    parser.add_argument('-i', '--parent_instruction', dest='parent_insn')
    parser.add_argument('-p', '--generate_pass_rates', dest='generate_pass_rates', action='store_true')
    parser.set_defaults(generate_pass_rates=False)
    args = parser.parse_args()

    limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()
    _, _, _, other_relations_file, other_indices_file = parse_relation_analysis_inputs()
    ra = SerialMultipleRelationAnalysis(starting_events, program, program_args, program_path, limit,
                          starting_insn_to_weight,
                          other_indices_file=other_indices_file,
                          other_relations_file=other_relations_file)
    if args.generate_pass_rates is True:
        ra.generate_pass_rates()
    else:
        multiple_insns = []
        insns_file = args.multiple_insns_file + ("_" + args.parent_insn if args.parent_insn is not None else "")
        print("[ra] Reading from insns file: " + insns_file)
        with open(insns_file, "r") as f:
            for l in f.readlines():
                multiple_insns.append(int(l.strip()))
        ra.analyze(multiple_insns, args.use_cache, int(args.parent_insn, 16) if args.parent_insn is not None else None)
