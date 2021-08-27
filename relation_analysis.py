from dynamic_dep_graph import *
import time
import itertools
import heapq

DEBUG = True
Weight_Threshold = 0

class Invariance:
    def __init__(self, ratio, is_conditional): #TODO, in the future, replace with actual conditions
        self.ratio = ratio
        self.is_conditional = is_conditional

    @staticmethod
    def is_irrelevant(counts):
        return len(counts) == 1 and 0 in counts

    @staticmethod
    def is_invariant(counts):
        return len(counts) == 1 and 0 not in counts

    @staticmethod
    def is_conditionally_invariant(counts):
        return len(counts) == 2 and 0 in counts

class Proportion:
    def __init__(self, distribution):
        self.distribution = distribution

class Relation:
    def __init__(self, target_node, prede_node, prede_count):
        self.target_node = target_node
        self.prede_node = prede_node
        self.prede_count = prede_count
        self.forward = None
        self.backward = None
        self.weight = None

class RelationGroup:
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

    def __init__(self, starting_node):
        self.starting_node = starting_node
        self.relations = {}
        self.invariant_predes = set()

    def build_invariant_group(self):
        for rel in self.relations.values():
            if isinstance(rel.forward, Invariance) and \
                isinstance(rel.backward, Invariance):
                self.invariant_predes.add(rel.prede_node)

                if rel.prede_node not in RelationGroup.prede_node_to_invariant_rel:
                    RelationGroup.prede_node_to_invariant_rel[rel.prede_node] = []
                RelationGroup.prede_node_to_invariant_rel[rel.prede_node].append(rel)

    def get_or_make_relation(self, prede_node, prede_count):
        if prede_node in self.relations:
            return self.relations[prede_node]
        else:
            r = Relation(self.starting_node, prede_node, prede_count)
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
        self.contrib = contrib
        self.total_contrib = base_contrib * contrib
        #remainder = 10
        #if self.total_contrib % 10 > 0:
        #    remainder = self.total_contrib % 10
        #self.round_contrib = self.total_contrib - remainder
        self.corr = corr
        self.order = order

    def __str__(self):
        s = ""
        s += "Total contrib:{:20.2f} ".format(self.total_contrib)
        s += "Contrib:{:6.2f} ".format(self.contrib)
        s += "Corr:{:6.2f} ".format(self.corr*100)
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
        static_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]
        visited = set() #TODO, think if it makes sense...
        #wavefront = set()
        wavefront = deque()

        static_node_to_weight = {}
        iteration = 0
        curr_weight = None
        while True:
            unique_wavefront = set()
            #if iteration > 2:
            #    break
            if static_node in visited:
                print()
                print(hex(insn) + "@" + func + " already visited...")
            elif RelationGroup.explained_by_invariant_relation(static_node):
                print()
                print(hex(insn) + "@" + func + " has a node forward and backward invariant already explained...")
            else:
                iteration += 1
                print()
                print("=======================================================================", flush=True)
                print("Relational analysis, pass number: " + str(iteration) + " weight:" +
                      str(100 if curr_weight is None else curr_weight.total_contrib))
                static_node.print_node("[ra] starting static node: ")
                print("", flush=True)

                visited.add(static_node)
                rgroup = RelationGroup(static_node)
                self.relation_groups[static_node] = rgroup
                #TODO: need to tell dynamic dependence to not do static slicing again
                #TODO also not rewatch pin
                a = time.time()
                try:
                    dgraph = self.dd.build_dyanmic_dependencies(insn)
                except:
                    if len(wavefront) > 0:
                        curr_weight, next = wavefront.pop()
                        insn = next.insn
                        func = next.function
                        static_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]
                    else:
                        break
                #self.prepare1(dgraph)
                print("Number of nodes in postorder_list: " + str(len(dgraph.postorder_list)))
                print("Number of nodes in reverse_postorder_list: " + str(len(dgraph.reverse_postorder_list)))
                assert dgraph is not None
                b = time.time()
                print("Building dynamic graph took: " + str(b - a))

                a = time.time()

                curr_wavefront = self.one_pass(dgraph, static_node, rgroup,
                                                   static_node_to_weight,
                                                   100 if curr_weight is None else curr_weight.total_contrib)
                b = time.time()
                print("pass took: " + str(b - a))
                print("---------------------------------------------")
                rgroup.build_invariant_group()

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
                for weight, static_node in curr_weighted_wavefront:
                    if DEBUG: print("[ra] "
                          #+ " weight " + str("{:.2f}".format(weight.contrib)) + " " + str("{:.2f}".format(weight.corr))
                          + str(weight)
                          + " NEW pending node: " + static_node.hex_insn
                          + "@" + static_node.function
                          + " lines " + (str(static_node.bb.lines) if isinstance(static_node.bb, BasicBlock) else str(static_node.bb)))
                print("=======================================================================")
                #wavefront = sorted(wavefront, key=lambda weight_and_node: weight_and_node[0])
                for weight, static_node in wavefront:
                    if DEBUG: print("[ra] "
                          #+ " weight " + str("{:.2f}".format(weight.contrib)) + " " + str("{:.2f}".format(weight.corr))
                          + str(weight)
                          + " ALL pending node: " + static_node.hex_insn
                          + "@" + static_node.function
                          + " lines " + (str(static_node.bb.lines) if isinstance(static_node.bb, BasicBlock) else str(static_node.bb)))

                #break #TODO
            if len(wavefront) > 0:
                curr_weight, next = wavefront.popleft()
                insn = next.insn
                func = next.function
                static_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]
            else:
                break

    def one_pass(self, dgraph, starting_node, rgroup, static_node_to_weight, starting_weight):
        print("Starting forward pass")
        wavefront = []
        base_weight = len(dgraph.target_nodes)

        # tests for forward invariance
        ################# Calculate base weight ######################
        ##############################################################
        base_weight = 0
        valid_count = 0
        use_weight = True
        for node in dgraph.target_nodes:
            if node.is_valid_weight is False:
                continue
            valid_count += 1
            base_weight += node.weight

        if valid_count/len(dgraph.target_nodes) < 0.99:
            print("[warn] Too many invalid weights to use weights ...")
            use_weight = False
            base_weight = len(dgraph.target_nodes)
        print("Base weight: " + str(base_weight))

        ################ Do forward propogation ######################
        ########## and backward propogation in the meanwhile #########
        for node in dgraph.target_nodes:
            node.output_set.add(node)

        for node in dgraph.postorder_list: #a node will be visited only if its successors have all been visited
            if node in dgraph.target_nodes:
                continue
            node_insn = node.static_node.insn
            #print("[ra] Forward propogating for node: " + hex(node_insn))
            backedge_sources = node.static_node.backedge_sources
            for cf_succe in node.cf_succes:
                #cf_succe_insn = cf_succe.static_node.insn
                #if cf_succe_insn in backedge_sources:
                #    wavefront.add(cf_succe.static_node)
                #    print("[ra] insn: " + cf_succe.static_node.hex_insn + " added to pending list because of cycles...")
                #    continue
                node.output_set = node.output_set.union(cf_succe.output_set)

            for df_succe in node.df_succes:
                #df_succe_insn = df_succe.static_node.insn
                #if df_succe_insn in backedge_sources:
                #    wavefront.add(df_succe.static_node)
                #    print("[ra] insn: " + df_succe.static_node.hex_insn + " added to pending list because of cycles...")
                #    continue
                node.output_set = node.output_set.union(df_succe.output_set)

            for output_node in node.output_set:
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

        ############## Setup for backward propogation ################
        ##############################################################
        # all the starting nodes
        starting_dynamic_nodes = []
        # insert starting node in the input set of the starting node
        if starting_node.insn in dgraph.insn_to_dyn_nodes:
            for node in dgraph.insn_to_dyn_nodes[starting_node.insn]:
                # special handle starting nodes
                node_insn = node.static_node.insn #fixme: change to starting_node.insn
                if node_insn not in node.input_sets:
                    node.input_sets[node_insn] = set()
                node.input_sets[node_insn].add(node)
                # special handle starting nodes
                starting_dynamic_nodes.append(node)

        ################### Calculate relations ######################
        ##############################################################
        worklist = deque()
        worklist.append(starting_node)
        visited = set() #TODO, ideally wanna propogate all the way, for now don't do that
        invariant_group = set()
        while(len(worklist) > 0):
            static_node = worklist.popleft()
            if static_node in visited:
                continue
            visited.add(static_node) #TODO, optimize by using the insn?

            if static_node.explained is False:
                #TODO handle more carefully
                continue

            insn = static_node.insn
            hex_insn = static_node.hex_insn
            if insn not in dgraph.insn_to_dyn_nodes:
                #if DEBUG: print("-------")
                #print("[ra][warn] insn not in dynamic graph??? " + hex(insn))
                continue
            # assert insn in dgraph.insn_to_dyn_nodes, hex(insn)

            if DEBUG: print("-------")
            ########## Calculate output sets ##########
            output_set_counts = set()
            output_set_count_list = []
            all_output = set()
            for node in dgraph.insn_to_dyn_nodes[insn]:
                output_set_counts.add(len(node.output_set))
                output_set_count_list.append(len(node.output_set))
                all_output = all_output.union(node.output_set)

            ########## Calculate input sets ###########
            input_set_counts = set()
            input_set_count_list = []
            for node in starting_dynamic_nodes:
                if static_node.insn not in node.input_sets:
                    input_set_counts.add(0)
                    input_set_count_list.append(0)
                else:
                    input_set_counts.add(len(node.input_sets[static_node.insn]))
                    input_set_count_list.append(len(node.input_sets[static_node.insn]))

            ############ Calculate weights ############
            node_count = len(dgraph.insn_to_dyn_nodes[insn])
            output_count = len(all_output)

            if use_weight is False:
                curr_weight = output_count
            else:
                curr_weight = 0
                miss = 0
                for output in all_output:
                    if output.is_valid_weight is False:
                        miss += 1
                        continue
                    curr_weight += output.weight
                print("Missed " + str(miss))

            contribution = curr_weight/base_weight * 100

            ratio = 0
            if len(all_output) > 0:
                ratio = node_count/output_count

            specificity = ratio
            if ratio > 1:
                specificity = 1/ratio

            order_rank = 0
            if static_node in StaticDepGraph.postorder_ranks:
                order_rank = StaticDepGraph.postorder_ranks[static_node]

            weight = Weight(base_weight if use_weight is True else starting_weight, contribution, specificity, order_rank)
            #simple_weight = specificity * contribution
            """
            if static_node in static_node_to_weight:
                if static_node_to_weight[static_node] < weight:
                    static_node_to_weight[static_node] = weight
                    print("[ra] Updating weight for node: " + static_node.hex_insn + "@" + static_node.function)
            else:
                static_node_to_weight[static_node] = weight
            """
            static_node_to_weight[static_node] = weight
            """
            print("[ra] insn: " + insn
                  + " df successors are: " + str([s.hex_insn for s in static_node.df_succes]))
            print("[ra] insn: " + insn
                  + " cf successors are: " + str([s.hex_insn for s in static_node.cf_succes]))
            """
            if DEBUG: print("[ra] insn: " + hex_insn
                  + "@" + static_node.function
                  + " lines " + (str(static_node.bb.lines) if isinstance(static_node.bb, BasicBlock) else str(static_node.bb))
                  #+ " weight: " + "{:.2f}".format(simple_weight)
                  + " contrib: " + "{:.2f}".format(contribution)
                  + " corr: " + "{:.2f}".format(specificity)
                  + " total number of nodes: " + str(node_count)
                  + " output set counts: " + str(output_set_counts)
                  + " " + str(output_set_count_list))

            if DEBUG: print("[ra] insn: " + hex_insn
                  + "@" + static_node.function
                  + " lines " + (str(static_node.bb.lines) if isinstance(static_node.bb, BasicBlock) else str(static_node.bb))
                  + " total number of nodes: " + str(node_count)
                  + " input set counts: " + str(input_set_counts)
                  + " " + str(input_set_count_list))

            if contribution < 1:
                if DEBUG: print("[ra] insn: " + hex_insn + " only has a "
                                + str(contribution) + "% contribution to the output event, ignore ...")
                continue

            prede_count = len(dgraph.insn_to_dyn_nodes[insn])
            ############ detect forward relations ############
            if Invariance.is_irrelevant(output_set_counts):
                if DEBUG: print("[ra] insn: " + hex_insn + " is irrelevant to the output event, ignore ...")
                continue
            if Invariance.is_invariant(output_set_counts):
                if DEBUG: print("[ra] insn: " + hex_insn + " is forward invariant with the output event")
                relation = rgroup.get_or_make_relation(static_node, prede_count)
                relation.forward = Invariance(max(output_set_counts), False)
                relation.weight = weight
                #FIXME: could be conditionally invariant too!
            elif Invariance.is_conditionally_invariant(output_set_counts):
                if DEBUG: print("[ra] insn: "
                  + hex_insn + " is conditionally forward invariant with the output event")
                relation = rgroup.get_or_make_relation(static_node, prede_count)
                relation.forward = Invariance(max(output_set_counts), True)
                relation.weight = weight
            else:
                if DEBUG: print("[ra] NO INVARIANCE DETECTED")
                #It really only makes sense to consider every ratio there is ...
                wavefront.append(static_node)
                relation = rgroup.get_or_make_relation(static_node, prede_count)
                relation.forward = Proportion(output_set_counts)
                relation.weight = weight
                if DEBUG: print("[ra] insn: "
                      + hex_insn + "'s forward proportion with the output event is considered")

            ############ detect backward relations ###########
            if Invariance.is_irrelevant(input_set_counts):
                if DEBUG: print("[ra] insn: "
                      + hex_insn + " is irrelevant to the output event, ignore...")
                continue
            if Invariance.is_invariant(input_set_counts):
                if DEBUG: print("[ra] insn: "
                      + hex_insn + " is backward invariant with the output event")
                backward_invariant = True
                relation = rgroup.get_or_make_relation(static_node, prede_count)
                relation.backward = Invariance(max(input_set_counts), False)
                # FIXME: could be conditionally invariant too!
            elif Invariance.is_conditionally_invariant(input_set_counts):
                if DEBUG: print("[ra] insn: "
                      + hex_insn + " is conditionally backward invariant with the output event")
                backward_invariant = True
                relation = rgroup.get_or_make_relation(static_node, prede_count)
                relation.backward = Invariance(max(input_set_counts), True)
            else:
                if DEBUG: print("[ra] NO INVARIANCE DETECTED")
                #It really only makes sense to consider every ratio there is ...
                if static_node not in wavefront:
                    wavefront.append(static_node)
                relation = rgroup.get_or_make_relation(static_node, prede_count)
                relation.backward = Proportion(input_set_counts)
                if DEBUG: print("[ra] insn: "
                      + hex_insn + "'s backward proportion with the output event is considered")

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
        return wavefront

if __name__ == "__main__":
    starting_events = []
    starting_events.append(["rdi", 0x409daa, "sweep"])
    starting_events.append(["rbx", 0x407240, "runtime.mallocgc"])
    starting_events.append(["rdx", 0x40742b, "runtime.mallocgc"])
    starting_events.append(["rcx", 0x40764c, "runtime.free"])

    ra = RelationAnalysis(starting_events, 0x409daa, "sweep", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")
    ra.analyze()
