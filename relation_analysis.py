from dynamic_dep_graph import *
import time
import itertools
import heapq
import numpy as np
from scipy.stats import norm
import subprocess
import traceback

DEBUG = True
Weight_Threshold = 0

class Invariance:
    def __init__(self, ratio, conditional_proportion=None): #TODO, in the future, replace with actual conditions
        self.ratio = ratio
        self.is_conditional = False
        self.conditional_proportion = None
        if conditional_proportion is not None:
            self.is_conditional = True
            self.conditional_proportion = conditional_proportion

    def __str__(self):
        s = "INVARIANT with ratio: " + str(self.ratio)
        if self.is_conditional is True:
            s += " conditional with proportion: {:.2f}%".format(self.conditional_proportion*100)
        s += "\n"
        return s

    @staticmethod
    def is_irrelevant(counts):
        return len(counts) == 1 and 0 in counts

    @staticmethod
    def is_invariant(counts):
        return len(counts) == 1 and 0 not in counts

    @staticmethod
    def is_conditionally_invariant(counts):
        return len(counts) == 2 and 0 in counts

    @staticmethod
    def get_conditional_proportion(count_list):
        assert(Invariance.is_conditionally_invariant(set(count_list)) == True)
        none_zero_count = 0
        for c in count_list:
            if c != 0:
                none_zero_count += 1
        return none_zero_count/len(count_list)

class Proportion:
    def __init__(self, distribution, weighted_distribution):
        #print(distribution)
        self.distribution = distribution
        self.mu, self.std = norm.fit(distribution)
        #print(weighted_distribution)
        if len(weighted_distribution) > 0:
            self.weighted_distribution = weighted_distribution
            self.w_mu, self.w_std = norm.fit(weighted_distribution)
        else:
            self.weighted_distribution = None
            self.w_mu = None
            self.w_std = None

    def __str__(self):
        s = "VARIABLE "
        s += "with distrib (mean: {:.2f}".format(self.mu) + ", std: {:.2f}".format(self.std) + ") "
        if self.weighted_distribution is not None:
            s += "and weighted distrib (mean: {:.2f}".format(self.w_mu) + ", std: {:.2f}".format(self.w_std) + ")"
        s += "\n"
        return s

class Relation:
    def __init__(self, target_node, prede_node, prede_count, weight):
        self.target_node = target_node
        self.prede_node = prede_node
        self.prede_count = prede_count
        self.weight = weight
        self.forward = None
        self.backward = None

    def __str__(self):
        s = ""
        s += "  >>> " + self.prede_node.hex_insn + "@" + self.prede_node.function + " <<<\n"
        s += "  " + str(self.weight) + "\n"
        s += "  => forward:  " + str(self.forward)
        s += "  => backward: " + str(self.backward)
        s += "-----------------\n"
        return s

class RelationGroup:
    relation_groups = []
    prede_node_to_invariant_rel = {}
    node_counts = {}

    @staticmethod
    def load_node_counts(count_file_path):
        print("[ra] Loading node counts from file: " + str(count_file_path))
        with open(count_file_path, 'r') as f: #TODO
            for l in f.readlines():
                insn = int(l.split()[0], 16)
                count = int(l.split()[1])
                RelationGroup.node_counts[insn] = count

    @staticmethod
    def explained_by_invariant_relation(prede_node):
        if prede_node not in RelationGroup.prede_node_to_invariant_rel:
            return False
        print(RelationGroup.node_counts)
        full_count = RelationGroup.node_counts[prede_node.insn]
        for rel in RelationGroup.prede_node_to_invariant_rel[prede_node]:
            print("[ra] Testing if " + prede_node.hex_insn + "@" + prede_node.function + " is fully explained... "
                  + " full count: " + str(full_count) + " count in relation: " + str(rel.prede_count))
            if full_count == rel.prede_count:
                return True
        return False

    def __init__(self, starting_node, weight):
        self.starting_node = starting_node
        self.weight = weight
        self.relations = {}
        self.sorted_relations = []
        #self.invariant_predes = set()
        self.finished = False

    def __str__(self):
        assert(self.finished)
        s =  "================ Relation Group =================\n"
        s += "Starting event: " + self.starting_node.hex_insn + "@" + self.starting_node.function
        s += " weight: " + str(self.weight) + "\n"
        s += " Total number of relations: " + str(len(self.sorted_relations)) + "\n"
        for rel in reversed(self.sorted_relations):
            s += str(rel)
        s += "=================================================\n"
        return s

    def finish_invariant_group(self):
        RelationGroup.relation_groups.append(self)

        to_remove = set()
        for prede in self.relations:
            if not isinstance(self.relations[prede].forward, Proportion):
                continue
            if not isinstance(self.relations[prede].backward, Proportion):
                continue
            has_only_proportion_succe = True
            for n in itertools.chain(prede.cf_succes, prede.df_succes):
                if n == self.starting_node:
                    has_only_proportion_succe = False
                    break
                if n not in self.relations:
                    continue
                if not isinstance(self.relations[n].forward, Proportion):
                    has_only_proportion_succe = False
                    break
                if not isinstance(self.relations[n].backward, Proportion):
                    has_only_proportion_succe = False
                    break
            if has_only_proportion_succe is False:
                continue
            to_remove.add(prede)
        for prede in to_remove:
            print("[ra] Removing a variable relation whose successors all have variable relations: ")
            print(self.relations[prede])
            del self.relations[prede]

        for rel in self.relations.values():
            if isinstance(rel.forward, Invariance) and \
                isinstance(rel.backward, Invariance):
                #self.invariant_predes.add(rel.prede_node)

                if rel.prede_node not in RelationGroup.prede_node_to_invariant_rel:
                    RelationGroup.prede_node_to_invariant_rel[rel.prede_node] = []
                RelationGroup.prede_node_to_invariant_rel[rel.prede_node].append(rel)
        self.sorted_relations = sorted(list(self.relations.values()), key=lambda relation: relation.weight)
        self.finished = True

    def get_or_make_relation(self, prede_node, prede_count, weight):
        if prede_node in self.relations:
            return self.relations[prede_node]
        else:
            r = Relation(self.starting_node, prede_node, prede_count, weight)
            self.relations[prede_node] = r
            return r
        """
        self.starting_node = starting_node
        self.conditionally_forward_invariant_nodes = set()
        self.forward_invariant_nodes = set()
        self.conditionally_backward_invariant_nodes = set()
        self.backward_invariant_nodes = set()
        self.wave_front = set() #TODO is this really useful?
        #TODO, what if we just include the invariant nodes at the edgraphes
        # and simplify when there is an OR? makes verification easier too
        """


class Weight:
    def __init__(self, base_contrib, contrib, corr, order):
        self.base_contrib = base_contrib
        assert(contrib <= 100)
        self.contrib = contrib
        self.total_contrib = base_contrib * contrib/100
        #remainder = 10
        #if self.total_contrib % 10 > 0:
        #    remainder = self.total_contrib % 10
        #self.round_contrib = self.total_contrib - remainder
        self.corr = corr
        self.order = order

    def __str__(self):
        s = ""
        s += "Total contrib:{:20.2f} ".format(self.total_contrib)
        s += "Contrib:{:6.2f}% ".format(self.contrib)
        s += "Corr:{:6.2f}% ".format(self.corr*100)
        #s += "Round:{:.2f} ".format(self.round_contrib)
        s += "order:{:6d} ".format(self.order)
        return s

    def __eq__(self, other):
        return (self.total_contrib == other.total_contrib
                and self.corr == other.corr
                and self.order == other.order)

    def __gt__(self, other):
        if self.total_contrib > other.total_contrib:
            return True
        if self.total_contrib < other.total_contrib:
            return False
        if self.corr > other.corr:
            return True
        if self.corr < other.corr:
            return False
        if self.order > other.order:
            return True
        return False

    def __lt__(self, other):
        if self.total_contrib < other.total_contrib:
            return True
        if self.total_contrib > other.total_contrib:
            return False
        if self.corr < other.corr:
            return True
        if self.corr > other.corr:
            return False
        if self.order < other.order:
            return True
        return False


class RelationAnalysis:
    negative_event_map = {}
    def __init__(self, starting_events, insn, func, prog, arg, path):
        self.starting_insn = insn
        self.starting_func = func
        self.dd = DynamicDependence(starting_events, prog, arg, path)

        preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'count_node')
        pp_process = subprocess.Popen([preprocessor_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = pp_process.communicate()
        print(stdout)
        print(stderr)
        RelationGroup.load_node_counts(self.dd.trace_path + ".count")
        self.relation_groups = {} #results

    #def prepare(self):
    #    mark = StaticDepGraph.func_to_graph["scanblock"].insn_to_node[0x409418]
    #    alloc = StaticDepGraph.func_to_graph["runtime.markallocated"].insn_to_node[0x40a6aa]
    #    RelationAnalysis.negative_event_map[mark] = alloc

    #def prepare1(self, dgraph):
    #    sizes = {}
    #    with open("weight", "r") as f:
    #        lines = f.readlines()
    #        for l in lines:
    #            segs = l.split()
    #            addr = int(segs[0], 16)
    #            if addr in sizes:
    #                if sizes[addr] != segs[1]:
    #                    print(segs[1])
    #                    print(sizes[addr])
    #            #print("HERE1 " + hex(addr))
    #            sizes[addr] = segs[1]
    #    node_to_weight = {}
    #    for n in dgraph.target_nodes:
    #        #print("HERE2 " + hex(n.mem_load_addr))
    #        if n.mem_load_addr not in sizes:
    #            print("MISSING")
    #        else:
    #            #print("FOUND")
    #            node_to_weight[n] = sizes[n.mem_load_addr]
    #    #mark = StaticDepGraph.func_to_graph["scanblock"].insn_to_node[0x409418]
    #    #alloc = StaticDepGraph.func_to_graph["runtime.markallocated"].insn_to_node[0x40a6aa]
    #    #RelationAnalysis.negative_event_map[mark] = alloc
    #    self.node_to_weight = node_to_weight


    def analyze(self):
        self.dd.prepare_to_build_dynamic_dependencies(10000)
        #TODO, do below in the static graph logic
        StaticDepGraph.build_postorder_list()
        StaticDepGraph.build_postorder_ranks()
        #self.prepare()
        #print(len(StaticDepGraph.postorder_list))
        #print(len(StaticDepGraph.postorder_ranks))
        insn = self.starting_insn
        func = self.starting_func
        starting_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]
        visited = set() #TODO, think if it makes sense...
        #wavefront = set()
        wavefront = deque()

        static_node_to_weight = {}
        iteration = 0
        curr_weight = None
        max_contrib = 0
        while True:
            unique_wavefront = set()
            #if iteration > 2:
            #    break
            if starting_node in visited:
                print()
                print(hex(insn) + "@" + func + " already visited...")
            elif RelationGroup.explained_by_invariant_relation(starting_node):
                print()
                print(hex(insn) + "@" + func + " has a node forward and backward invariant already explained...")
            else:
                iteration += 1
                print()
                print("=======================================================================", flush=True)
                print("Relational analysis, pass number: " + str(iteration) + " weight: " +
                      str(100 if curr_weight is None else curr_weight.total_contrib) +
                      " max weight: " + str(max_contrib))
                starting_node.print_node("[ra] starting static node: ")
                print("", flush=True)

                visited.add(starting_node)
                #TODO: need to tell dynamic dependence to not do static slicing again
                #TODO also not rewatch pin
                a = time.time()
                try:
                    dgraph = self.dd.build_dynamic_dependencies(insn)
                except Exception as e:
                    print("[ra] Building dynamic dependence graph failed for insn "
                          + starting_node.hex_insn + "@" + starting_node.function)
                    print(str(e))
                    print("-" * 60)
                    traceback.print_exc(file=sys.stdout)
                    print("-" * 60)
                    raise e

                    if len(wavefront) > 0:
                        curr_weight, next = wavefront.pop()
                        insn = next.insn
                        func = next.function
                        starting_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]
                        continue
                    else:
                        break
                #self.prepare1(dgraph)
                print("Number of nodes in postorder_list: " + str(len(dgraph.postorder_list)))
                print("Number of nodes in reverse_postorder_list: " + str(len(dgraph.reverse_postorder_list)))
                assert dgraph is not None
                b = time.time()
                print("Building dynamic graph took: " + str(b - a))

                a = time.time()

                curr_wavefront, rgroup = self.one_pass(dgraph, starting_node,
                                                   static_node_to_weight,
                                                   None if curr_weight is None else curr_weight.total_contrib,
                                                    max_contrib)
                b = time.time()
                print("pass took: " + str(b - a))
                print("---------------------------------------------")

                if rgroup is not None:
                    if rgroup.weight > max_contrib:
                        max_contrib = rgroup.weight

                curr_weighted_wavefront = []
                for wavelet in curr_wavefront:
                    if wavelet in unique_wavefront:
                        continue
                    unique_wavefront.add(wavelet)
                    if wavelet not in static_node_to_weight:
                        print("[ra][warn] no weight " + str(wavelet.hex_insn))
                    else:
                        weight = static_node_to_weight[wavelet]
                        wavefront.append((weight, wavelet))
                        curr_weighted_wavefront.append((weight, wavelet))
                print("=======================================================================")
                curr_weighted_wavefront = sorted(curr_weighted_wavefront, key=lambda weight_and_node: weight_and_node[0])
                for weight, starting_node in curr_weighted_wavefront:
                    if DEBUG: print("[ra] "
                          #+ " weight " + str("{:.2f}".format(weight.contrib)) + " " + str("{:.2f}".format(weight.corr))
                          + str(weight)
                          + " NEW pending node: " + starting_node.hex_insn
                          + "@" + starting_node.function
                          + " lines " + (str(starting_node.bb.lines) if isinstance(starting_node.bb, BasicBlock) else str(starting_node.bb)))
                print("=======================================================================")
                #wavefront = sorted(wavefront, key=lambda weight_and_node: weight_and_node[0])
                for weight, starting_node in wavefront:
                    if DEBUG: print("[ra] "
                          #+ " weight " + str("{:.2f}".format(weight.contrib)) + " " + str("{:.2f}".format(weight.corr))
                          + str(weight)
                          + " ALL pending node: " + starting_node.hex_insn
                          + "@" + starting_node.function
                          + " lines " + (str(starting_node.bb.lines) if isinstance(starting_node.bb, BasicBlock) else str(starting_node.bb)))

                #break #TODO
            if len(wavefront) > 0:
                curr_weight, next = wavefront.popleft()
                insn = next.insn
                func = next.function
                starting_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]
            else:
                break
        RelationGroup.relation_groups = sorted(RelationGroup.relation_groups, key=lambda rg: rg.weight)
        num_rels = 0
        for relation_group in reversed(RelationGroup.relation_groups):
            num_rels += len(relation_group.relations)
            assert len(relation_group.relations) == len(relation_group.sorted_relations)
            print(relation_group)
        print("[ra] Total number of relations groups: " + str(len(RelationGroup.relation_groups)))
        print("[ra] Total number of relations: " + str(num_rels))

    def calculate_base_weight(self, dgraph, starting_weight):
        base_weight = 0
        use_weight = True
        valid_count = 0
        for node in dgraph.target_nodes:
            if node.is_valid_weight is False:
                continue
            valid_count += 1
            base_weight += node.weight

        if valid_count/len(dgraph.target_nodes) < 0.99:
            print("[ra][warn] Too many invalid weights to use weights ...")
            use_weight = False
            base_weight = starting_weight#len(dgraph.target_nodes)

        print("[ra] Base weight is: " + str(base_weight))
        return base_weight, use_weight

    def do_forward_propogation(self, dgraph):
        for node in dgraph.target_nodes:
            node.output_set.add(node)

        for node in dgraph.postorder_list: #a node will be visited only if its successors have all been visited
            if node in dgraph.target_nodes:
                continue
            node_insn = node.static_node.insn
            #print("[ra] Forward propogating for node: " + hex(node_insn) + " " + str(node.id))
            #backedge_sources = node.static_node.backedge_sources
            for cf_succe in node.cf_succes:
                cf_succe_insn = cf_succe.static_node.insn

                if cf_succe_insn in node.static_node.backedge_sources:
                    for output_node in cf_succe.output_set:
                        if node_insn in output_node.input_sets and len(output_node.input_sets[node_insn]) > 0:
                            #print("[ra] Node already attributed to the input of some output node: " + str(output_node.id))
                            node.output_exclude_set.add(output_node)
                #    wavefront.add(cf_succe.static_node)
                #    print("[ra] insn: " + cf_succe.static_node.hex_insn + " added to pending list because of cycles...")
                #    continue
                node.output_set = node.output_set.union(cf_succe.output_set)
                node.output_exclude_set = node.output_exclude_set.union(cf_succe.output_exclude_set)
            #if len(node.output_exclude_set) > 0:
            #    print("[ra] include outputs: " + str([n.id for n in node.output_set]))
            #    print("[ra] exclude outputs: " + str([n.id for n in node.output_exclude_set]))

            for df_succe in node.df_succes:
                #df_succe_insn = df_succe.static_node.insn
                #if df_succe_insn in backedge_sources:
                #    wavefront.add(df_succe.static_node)
                #    print("[ra] insn: " + df_succe.static_node.hex_insn + " added to pending list because of cycles...")
                #    continue
                node.output_set = node.output_set.union(df_succe.output_set)
                if df_succe.static_node.is_df is False:
                    node.output_exclude_set = node.output_exclude_set.union(df_succe.output_exclude_set) #TODO, never referenced?

            for output_node in node.output_set:
                if output_node in node.output_exclude_set:
                    continue
                if node_insn not in output_node.input_sets:
                    output_node.input_sets[node_insn] = set()
                output_node.input_sets[node_insn].add(node)


            #if node.static_node.group_ids is not None:
            #    for i in range(len(node.static_node.group_ids)):
            #        group_id = node.static_node.group_ids[i]
            #        group_insn = node.static_node.group_insns[i]
            #        if group_id in StaticDepGraph.insn_to_node:
            #            virtual_static_node = StaticDepGraph.insn_to_node[group_id]
            #        else:
            #            virtual_static_node = StaticNode(group_id, None, hex(group_insn))
            #            virtual_static_node.explained = True
            #            StaticDepGraph.insn_to_node[group_id] = virtual_static_node
            #        node.static_node.print_node("Child node: ")
            #        virtual_static_node.print_node("Creating virtual static node: ")
            #        node.static_node.virtual_nodes.append(virtual_static_node)
            #        virtual_node = DynamicNode(group_id, virtual_static_node)
            #        if group_id not in dgraph.insn_to_dyn_nodes:
            #            dgraph.insn_to_dyn_nodes[group_id] = []
            #        dgraph.insn_to_dyn_nodes[group_id].append(virtual_node)
            #
            #        virtual_node.output_set = virtual_node.output_set.union(node.output_set)
            #        for output_node in node.output_set:
            #            if group_id not in output_node.input_sets:
            #                output_node.input_sets[group_id] = set()
            #            output_node.input_sets[group_id].add(virtual_node)

        for node in dgraph.postorder_list: #a node will be visited only if its successors have all been visited
            if node in dgraph.target_nodes:
                continue
            #node_insn = node.static_node.insn
            node.output_set = node.output_set.difference(node.output_exclude_set)

    def do_backward_propogation(self, dgraph, starting_node):
        # all the starting nodes
        # insert starting node in the input set of the starting node
        for node in dgraph.insn_to_dyn_nodes[starting_node.insn]:
            # special handle starting nodes
            node_insn = node.static_node.insn #fixme: change to starting_node.insn
            if node_insn not in node.input_sets:
                node.input_sets[node_insn] = set()
            node.input_sets[node_insn].add(node)
            # special handle starting nodes

    def calculate_individual_weight(self, dgraph, reachable_output_events, starting_node, prede_node, use_weight, base_weight, starting_weight):
        #FIXME give base_weight & starting_weight better names
        if use_weight is False:
            contribution = len(reachable_output_events) / len(dgraph.insn_to_dyn_nodes[starting_node.insn]) * 100
        else:
            curr_weight = 0
            miss = 0
            for output in reachable_output_events:
                if output.is_valid_weight is False:
                    miss += 1
                    continue
                curr_weight += output.weight
            print("Missed " + str(miss))
            contribution = curr_weight / base_weight * 100

        ratio = 0
        if len(reachable_output_events) > 0:
            ratio = len(dgraph.insn_to_dyn_nodes[prede_node.insn]) / len(reachable_output_events)

        specificity = ratio
        if ratio > 1:
            specificity = 1 / ratio

        order_rank = 0
        if prede_node in StaticDepGraph.postorder_ranks:
            order_rank = StaticDepGraph.postorder_ranks[prede_node]

        weight = Weight(base_weight if use_weight is True else starting_weight, contribution, specificity, order_rank)
        return weight

    def build_relation_with_predecessor(self, dgraph, starting_node, prede_node, rgroup, wavefront,
                                                 use_weight, base_weight, starting_weight, static_node_to_weight):
        #insn = prede_node.insn
        #hex_insn = prede_node.hex_insn
        if DEBUG: print("-------")
        ########## Calculate output sets ##########
        output_set_counts = set()
        output_set_count_list = []
        weighted_output_set_count_list = []
        reachable_output_events = set()
        output_set_count_to_nodes = {} #for debugging
        for node in dgraph.insn_to_dyn_nodes[prede_node.insn]:
            output_set_count = len(node.output_set)
            output_set_counts.add(output_set_count)
            output_set_count_list.append(output_set_count)
            if output_set_count not in output_set_count_to_nodes:
                output_set_count_to_nodes[output_set_count] = []
            output_set_count_to_nodes[output_set_count].append(node)
            reachable_output_events = reachable_output_events.union(node.output_set)
            if use_weight is True:
                output_weight = 0
                for output in node.output_set:
                    if output.is_valid_weight is False:
                        continue
                    output_weight += output.weight
                weighted_output_set_count_list.append(output_weight)

        ########## Calculate input sets ###########
        input_set_counts = set()
        input_set_count_list = []
        weighted_input_set_count_list = []
        for node in dgraph.insn_to_dyn_nodes[starting_node.insn]:
            if prede_node.insn not in node.input_sets:
                input_set_counts.add(0)
                input_set_count_list.append(0)
                if use_weight is True:
                    weighted_input_set_count_list.append(0)
            else:
                input_set_counts.add(len(node.input_sets[prede_node.insn]))
                input_set_count_list.append(len(node.input_sets[prede_node.insn]))
                if use_weight is True:
                    output_weight = 0
                    if node.is_valid_weight is True:
                        output_weight = len(node.input_sets[prede_node.insn]) * node.weight
                    weighted_input_set_count_list.append(output_weight)

        ############ Calculate weights ############
        weight = self.calculate_individual_weight(dgraph, reachable_output_events, starting_node, prede_node,
                                                  use_weight, base_weight, starting_weight)
        #static_node_to_weight[prede_node] = weight

        if prede_node in static_node_to_weight:
            if static_node_to_weight[prede_node] < weight:
                static_node_to_weight[prede_node] = weight
                print("[ra] Updating weight for node: " + prede_node.hex_insn + "@" + prede_node.function)
        else:
            static_node_to_weight[prede_node] = weight


        """
        print("[ra] insn: " + insn
              + " df successors are: " + str([s.hex_insn for s in prede_node.df_succes]))
        print("[ra] insn: " + insn
              + " cf successors are: " + str([s.hex_insn for s in prede_node.cf_succes]))
        """
        node_count = len(dgraph.insn_to_dyn_nodes[prede_node.insn])
        if DEBUG:
            print("[ra] insn: " + prede_node.hex_insn
                        + "@" + prede_node.function
                        + " lines "
                        + (str(prede_node.bb.lines) if isinstance(prede_node.bb, BasicBlock) else str(prede_node.bb))
                        # + " weight: " + "{:.2f}".format(simple_weight)
                        + " contrib: " + "{:.2f}".format(weight.contrib)
                        + " corr: " + "{:.2f}".format(weight.corr)
                        + " total number of nodes: " + str(node_count)
                        + " output set counts: " + str(output_set_counts)
                        + " " + str(output_set_count_list))

            for output_set_count in output_set_count_to_nodes:
                print("[ra]  nodes with output count " + str(output_set_count)
                      + " are: " + str([node.id for node in output_set_count_to_nodes[output_set_count]]))

            print("[ra] insn: " + prede_node.hex_insn
                        + "@" + prede_node.function
                        + " lines "
                        + (str(prede_node.bb.lines) if isinstance(prede_node.bb, BasicBlock) else str(prede_node.bb))
                        + " total number of nodes: " + str(node_count)
                        + " input set counts: " + str(input_set_counts)
                        + " " + str(input_set_count_list))

        if weight.contrib < 1:
            if DEBUG: print("[ra] insn: " + prede_node.hex_insn + " only has a "
                            + str(weight.contrib) + "% contribution to the output event, ignore ...")
            return

        if Invariance.is_irrelevant(output_set_counts) and Invariance.is_irrelevant(input_set_counts):
            if DEBUG: print("[ra] insn: " + prede_node.hex_insn + " is irrelevant  the output event, ignore ...")
            return

        ################ build relations ################
        relation = rgroup.get_or_make_relation(prede_node, len(dgraph.insn_to_dyn_nodes[prede_node.insn]), weight)
        ############ detect forward relations ############
        if Invariance.is_invariant(output_set_counts):
            if DEBUG: print("[ra] insn: " + prede_node.hex_insn + " is forward invariant with the output event")
            relation.forward = Invariance(max(output_set_counts))
            # FIXME: could be conditionally invariant too!
        elif Invariance.is_conditionally_invariant(output_set_counts):
            if DEBUG: print("[ra] insn: "
                            + prede_node.hex_insn + " is conditionally forward invariant with the output event")
            relation.forward = Invariance(max(output_set_counts),
                                          Invariance.get_conditional_proportion(output_set_count_list))
        elif not Invariance.is_irrelevant(output_set_counts):
            if DEBUG: print("[ra] NO INVARIANCE DETECTED")
            # It really only makes sense to consider every ratio there is ...
            wavefront.append(prede_node)
            relation.forward = Proportion(output_set_count_list, weighted_output_set_count_list)
            if DEBUG: print("[ra] insn: "
                            + prede_node.hex_insn + "'s forward proportion with the output event is considered")
        ############ detect backward relations ###########
        if Invariance.is_invariant(input_set_counts):
            if DEBUG: print("[ra] insn: "
                            + prede_node.hex_insn + " is backward invariant with the output event")
            # backward_invariant = True
            relation.backward = Invariance(max(input_set_counts))
            # FIXME: could be conditionally invariant too!
        elif Invariance.is_conditionally_invariant(input_set_counts):
            if DEBUG: print("[ra] insn: "
                            + prede_node.hex_insn + " is conditionally backward invariant with the output event")
            # backward_invariant = True
            relation.backward = Invariance(max(input_set_counts),
                                           Invariance.get_conditional_proportion(input_set_count_list))
        elif not Invariance.is_irrelevant(input_set_counts):
            if DEBUG: print("[ra] NO INVARIANCE DETECTED")
            # It really only makes sense to consider every ratio there is ...
            if prede_node not in wavefront:
                wavefront.append(prede_node)
            relation.backward = Proportion(input_set_count_list, weighted_input_set_count_list)
            if DEBUG: print("[ra] insn: "
                            + prede_node.hex_insn + "'s backward proportion with the output event is considered")

    def one_pass(self, dgraph, starting_node, static_node_to_weight, starting_weight, max_contrib):
        print("Starting forward and backward pass")
        wavefront = []
        #base_weight = len(dgraph.target_nodes)
        if starting_node.insn not in dgraph.insn_to_dyn_nodes:
            print("[ra] Node not found in the dynamic graph...")
            return wavefront, None

        # tests for forward invariance
        ################# Calculate base weight ######################
        ##############################################################
        base_weight, use_weight = self.calculate_base_weight(dgraph, starting_weight)

        if base_weight < (max_contrib*0.01):
            print("[ra] Base weight is less than 1% of the max weight, ignore the node "
                  + starting_node.hex_insn + "@" + starting_node.function)
            return wavefront, None
        ################ Do forward propogation ######################
        ########## and backward propogation in the meanwhile #########
        self.do_forward_propogation(dgraph)

        ############## Setup for backward propogation ################
        ##############################################################
        self.do_backward_propogation(dgraph, starting_node)

        ################### Calculate relations ######################
        ##############################################################
        rgroup = RelationGroup(starting_node, base_weight)
        self.relation_groups[starting_node] = rgroup

        worklist = deque()
        worklist.append(starting_node)
        visited = set() #TODO, ideally wanna propogate all the way, for now don't do that
        #invariant_group = set()
        while(len(worklist) > 0):
            static_node = worklist.popleft()
            if static_node in visited:
                continue
            visited.add(static_node) #TODO, optimize by using the insn?

            if static_node.explained is False:
                continue#TODO handle more carefully
            if static_node.insn not in dgraph.insn_to_dyn_nodes:
                #if DEBUG: print("-------")
                #print("[ra][warn] insn not in dynamic graph??? " + hex(insn))
                continue
            # assert insn in dgraph.insn_to_dyn_nodes, hex(insn)
            self.build_relation_with_predecessor(dgraph, starting_node, static_node, rgroup, wavefront,
                                                 use_weight, base_weight, starting_weight, static_node_to_weight)

            for p in static_node.cf_predes:
                worklist.append(p)
            for p in static_node.df_predes:
                worklist.append(p)
            for v in static_node.virtual_nodes:
                worklist.append(v)
        """
        for static_node in wavefront:
            print("[ra] pending node: " + static_node.hex_insn
                  + "@" + static_node.function
                  + " lines " + str(static_node.bb.lines))
            #TODO, change: only include those that are on the edgraphe of invariant and variant?
            #only include the original ones?
        """
        rgroup.finish_invariant_group()
        return wavefront, rgroup

if __name__ == "__main__":
    starting_events = []
    starting_events.append(["rdi", 0x409daa, "sweep"])
    starting_events.append(["rbx", 0x407240, "runtime.mallocgc"])
    starting_events.append(["rdx", 0x40742b, "runtime.mallocgc"])
    starting_events.append(["rcx", 0x40764c, "runtime.free"])

    ra = RelationAnalysis(starting_events, 0x409daa, "sweep", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")
    ra.analyze()
