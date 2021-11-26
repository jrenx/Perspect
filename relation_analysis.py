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
from ra_util import *

DEBUG = True
Weight_Threshold = 0
curr_dir = os.path.dirname(os.path.realpath(__file__))

class RelationAnalysis:
    #negative_event_map = {}
    def __init__(self, starting_events,
                 prog, arg, path, steps, starting_insn_to_weight, other_indices_file=None, other_relations_file=None):
        self.starting_events = starting_events
        self.prog = prog
        self.path = path
        self.prede_node_to_invariant_rel = {}
        self.static_node_to_weight = {}
        self.other_indices_map = None
        self.other_indices_map_inner = None
        self.other_simple_relation_groups = None
        self.relation_groups = []  # results
        self.steps = steps

        self.dd = DynamicDependence(starting_events, prog, arg, path, starting_insn_to_weight)
        self.dd.prepare_to_build_dynamic_dependencies(self.steps)

        print("[ra] Getting the counts of each unique node in the dynamic trace")
        if not os.path.exists(self.dd.trace_path + ".count"):
            preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'count_node')
            pp_process = subprocess.Popen([preprocessor_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = pp_process.communicate()
            print(stdout)
            print(stderr)
        self.node_counts = load_node_info(self.dd.trace_path + ".count")
        print("[ra] Finished getting the counts of each unique node in the dynamic trace")

        print("[ra] Getting the average timestamp of each unique node in the dynamic trace")
        if not os.path.exists(self.dd.trace_path + ".avg_timestamp"):
            preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'count_node')
            pp_process = subprocess.Popen([preprocessor_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = pp_process.communicate()
            print(stdout)
            print(stderr)
        self.node_avg_timestamps = load_node_info(self.dd.trace_path + ".avg_timestamp")
        print("[ra] Finished getting the average timestamp of each unique node in the dynamic trace")

        if other_indices_file is not None:
            other_indices_file_path = os.path.join(curr_dir, "cache", self.prog, other_indices_file)
            print("[ra] Other indices file is: " + other_indices_file_path)
            self.other_indices_map = load_indices(other_indices_file_path)

        if other_indices_file is not None:
            other_indices_file_path_inner = os.path.join(curr_dir, "cache", self.prog, other_indices_file + "_inner")
            print("[ra] Other inner indices file is: " + other_indices_file_path_inner)
            self.other_indices_map_inner = load_indices(other_indices_file_path_inner)

        if other_relations_file is not None:
            other_relations_file_path = os.path.join(curr_dir, "cache", self.prog, other_relations_file)
            print("[ra] Other relations file is: " + other_relations_file_path)
            self.other_simple_relation_groups = RelationAnalysis.load_simple_relations(other_relations_file_path)

        self.rgroup_file = os.path.join(curr_dir, 'cache', self.prog, "rgroups.json")
        self.simple_rgroup_file = os.path.join(curr_dir, "cache", self.prog, "rgroups_simple_" + self.dd.key + ".json")
        if os.path.exists(self.simple_rgroup_file):
            os.remove(self.simple_rgroup_file)
        if os.path.exists(self.rgroup_file):
            os.remove(self.rgroup_file)

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

    def parse_index_quad(self, index_quad):
        return index_quad[0], index_quad[1], index_quad[2], index_quad[3]

    @staticmethod
    def load_simple_relations(relations_file_path):
        simple_relation_groups = None
        if os.path.exists(relations_file_path):
            with open(relations_file_path, 'r') as f:
                simple_relation_groups = SimpleRelationGroups.fromJSON(json.load(f))
            print(simple_relation_groups)
        return simple_relation_groups

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

    def print_rgroups(self, relation_groups):
        num_rels = 0
        for relation_group in relation_groups:
            num_rels += len(relation_group.relations)
            assert len(relation_group.relations) == len(relation_group.sorted_relations)
            print(relation_group)
        print("[ra] Total number of relations groups: " + str(len(relation_groups)))
        print("[ra] Total number of relations: " + str(num_rels))

    def sort_and_output_results(self):
        self.relation_groups = sorted(self.relation_groups, key=lambda rg: rg.weight)
        self.relation_groups = self.relation_groups[::-1] #reverse the list
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

    @staticmethod
    def fetch_cached_rgroup(rgroup_file, prog):
        if os.path.exists(rgroup_file):
            with open(rgroup_file) as f:
                content = f.read().decode("utf-8", "ignore")
                json_rgroups = json.loads(content)
                rgroups = []
                for json_rgroup in json_rgroups:
                    rgroups.append(RelationGroup.fromJSON(json_rgroup, prog))
                self.print_rgroups(rgroups)
            return True
        return False
