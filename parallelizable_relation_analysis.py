from dynamic_dep_graph import *
from relations import *
import itertools
import time

class ParallelizableRelationAnalysis:

    @staticmethod
    def calculate_base_weight(dgraph):
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
            base_weight = None

        print("[ra] Base weight is: " + str(base_weight))
        return base_weight, use_weight

    def predes_all_visited(node, visited):
        for prede in itertools.chain(node.cf_predes, node.df_predes):
            if prede not in visited:
                return False
        return True

    @staticmethod
    def do_forward_propogation(dgraph, use_weight, reachable_output_events_per_static_node):
        print("[ra] starting forward propogation")
        a = time.time()
        for node in dgraph.target_nodes:
            node.output_set.add(node)

        visited = set()
        for node in dgraph.postorder_list: #a node will be visited only if its successors have all been visited
            assert node not in visited
            visited.add(node)
            #if len(visited)%1000 == 0:
            #    print("[ra] visited " + str(len(visited)) + " nodes")
            if node in dgraph.target_nodes:
                continue
            node_insn = node.static_node.insn
            node_id = node.static_node.id
            #print("[ra] Forward propogating for node: " + hex(node_insn) + " " + str(node.id))
            #backedge_sources = node.static_node.backedge_sources
            num_succes = len(node.cf_succes) + len(node.df_succes)
            seen_sets = set()
            for cf_succe in node.cf_succes:
                cf_succe_insn = cf_succe.static_node.insn

                exclude_set_modified = False
                if cf_succe_insn in node.static_node.backedge_sources:
                    for output_node in cf_succe.output_set:
                        if output_node.input_sets.get(node_id, 0) > 0:
                            #print("[ra] Node already attributed to the input of some output node: " + str(output_node.id))
                            node.output_exclude_set.add(output_node)
                            exclude_set_modified = True
                if num_succes == 1 and exclude_set_modified is False:
                    node.output_set = cf_succe.output_set
                    node.output_exclude_set = cf_succe.output_exclude_set
                    break
                #    wavefront.add(cf_succe.static_node)
                #    print("[ra] insn: " + cf_succe.static_node.hex_insn + " added to pending list because of cycles...")
                #    continue
                if cf_succe.output_set not in seen_sets:
                    node.output_set = node.output_set.union(cf_succe.output_set)
                    seen_sets.add(cf_succe.output_set)
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
                exclude_set_same = False
                if df_succe.static_node.is_df is False:
                    exclude_set_same = True
                    if num_succes == 1:
                        node.output_exclude_set = df_succe.output_exclude_set
                    else:
                        node.output_exclude_set = node.output_exclude_set.union(df_succe.output_exclude_set) #TODO, never referenced?
                if num_succes == 1 and (exclude_set_same is True or len(node.output_exclude_set) == len(df_succe.output_exclude_set)):
                    node.output_set = df_succe.output_set
                    break

                if df_succe.output_set not in seen_sets:
                    node.output_set = node.output_set.union(df_succe.output_set)
                    seen_sets.add(df_succe.output_set)

            #if len(visited)%100 == 0:
            #    print("[ra] output set size " + str(len(node.output_set)) + " nodes")

            #for output_node in node.output_set:
            #    if output_node in node.output_exclude_set:
            #        continue
            #    count = output_node.input_sets.get(node_insn,0)
            #    output_node.input_sets[node_insn] = count + 1

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

            for node in itertools.chain(node.cf_succes, node.df_succes):
                if not ParallelizableRelationAnalysis.predes_all_visited(node, visited):
                    continue

                #if node in dgraph.target_nodes:
                #    continue
                #node_insn = node.static_node.insn
                if node.output_exclude_set is None: #already seen
                    continue
                node_insn = node.static_node.insn
                node_id = node.static_node.id
                if len(node.output_exclude_set) > 0:
                    node.output_set = node.output_set.difference(node.output_exclude_set)
                for output_node in node.output_set:
                    count = output_node.input_sets.get(node_id, 0)
                    output_node.input_sets[node_id] = count + 1

                node.output_set_count = len(node.output_set)
                reachable_output_events = reachable_output_events_per_static_node.get(node_id, set())
                reachable_output_events = reachable_output_events.union(node.output_set)
                reachable_output_events_per_static_node[node_id] = reachable_output_events

                if use_weight is True:
                    output_weight = 0
                    for output in node.output_set:
                        if output.is_valid_weight is False:
                            continue
                        output_weight += output.weight
                    node.output_weight = output_weight
                node.output_exclude_set = None
                node.output_set = None
        b = time.time()
        print("[ra] forward propogation part1 took " + str(b - a))
        # For the leftover nodes who have no predecessors
        for node in dgraph.postorder_list: #a node will be visited only if its successors have all been visited
            #if node in dgraph.target_nodes:
            #    continue
            #node_insn = node.static_node.insn
            if node.output_exclude_set is None: #already seen
                continue
            node_insn = node.static_node.insn
            node_id = node.static_node.id
            if len(node.output_exclude_set) > 0:
                node.output_set = node.output_set.difference(node.output_exclude_set)
            for output_node in node.output_set:
                count = output_node.input_sets.get(node_id, 0)
                output_node.input_sets[node_id] = count + 1
            node.output_set_count = len(node.output_set)

            reachable_output_events = reachable_output_events_per_static_node.get(node_id, set())
            reachable_output_events = reachable_output_events.union(node.output_set)
            reachable_output_events_per_static_node[node_id] = reachable_output_events

            if use_weight is True:
                output_weight = 0
                for output in node.output_set:
                    if output.is_valid_weight is False:
                        continue
                    output_weight += output.weight
                node.output_weight = output_weight
            node.output_exclude_set = None
            node.output_set = None
        c = time.time()
        print("[ra] forward propogation part2 took " + str(c - b))

    @staticmethod
    def do_backward_propogation(dgraph, starting_node):
        # all the starting nodes
        # insert starting node in the input set of the starting node
        for node in dgraph.insn_to_dyn_nodes[starting_node.insn]:
            # special handle starting nodes
            node_insn = node.static_node.insn #fixme: change to starting_node.insn
            node_id = node.static_node.id
            count = node.input_sets.get(node_id, 0)
            node.input_sets[node_id] = count + 1
            # special handle starting nodes

    def calculate_individual_weight(dgraph, reachable_output_events, starting_node, prede_node, use_weight, base_weight):
        #FIXME give base_weight & starting_weight better names
        total_weight = None
        if use_weight is False:
            perc_contribution = len(reachable_output_events) / len(dgraph.insn_to_dyn_nodes[starting_node.insn]) * 100
        else:
            total_weight = 0
            miss = 0
            for output in reachable_output_events:
                if output.is_valid_weight is False:
                    miss += 1
                    continue
                total_weight += output.weight
            print("Missed " + str(miss))
            perc_contribution = total_weight / base_weight * 100

        ratio = 0
        if len(reachable_output_events) > 0:
            ratio = len(dgraph.insn_to_dyn_nodes[prede_node.insn]) / len(reachable_output_events)

        specificity = ratio
        if ratio > 1:
            specificity = 1 / ratio

        order_rank = 0
        if prede_node in StaticDepGraph.postorder_ranks:
            order_rank = StaticDepGraph.postorder_ranks[prede_node]

        weight = Weight(total_weight, base_weight, perc_contribution, specificity, order_rank)
        return weight

    @staticmethod
    def setup_bit_array(dgraph):
        target_node_to_id = {}
        id_to_target_node = {}
        id = 0
        for node in dgraph.target_nodes:
            target_node_to_id[node] = id
            id_to_target_node[id] = node
            id += 1
        # if use more than 10G then we don't use bit array
        estimated_mem = len(dgraph.target_nodes) * len(dgraph.dynamic_nodes) / 8 / 1024 / 1024 / 1024
        if estimated_mem < 10:
            global use_bit_array
            use_bit_array = True
            print("[ra] Use bit array because memory usage is " + str(estimated_mem) + "GB")

    @staticmethod
    def build_relation_with_predecessor(dgraph, starting_node, prede_node, rgroup, wavefront,
                                                 use_weight, base_weight, reachable_output_events_per_static_node):
        #insn = prede_node.insn
        #hex_insn = prede_node.hex_insn
        if DEBUG: print("-------")
        ########## Calculate output sets ##########
        output_set_counts = set()
        output_set_count_list = []
        weighted_output_set_count_list = []
        reachable_output_events = reachable_output_events_per_static_node[prede_node.id]
        output_set_count_to_nodes = {} #for debugging
        for node in dgraph.insn_to_dyn_nodes[prede_node.insn]:
            output_set_count = node.output_set_count
            output_set_counts.add(output_set_count)
            output_set_count_list.append(output_set_count)
            if output_set_count not in output_set_count_to_nodes:
                output_set_count_to_nodes[output_set_count] = []
            output_set_count_to_nodes[output_set_count].append(node)

            #reachable_output_events = reachable_output_events.union(node.output_set)
            if use_weight is True:
                #output_weight = 0
                #for output in node.output_set:
                #    if output.is_valid_weight is False:
                #        continue
                #    output_weight += output.weight
                weighted_output_set_count_list.append(node.output_weight)

        ########## Calculate input sets ###########
        input_set_counts = set()
        input_set_count_list = []
        weighted_input_set_count_list = []
        for node in dgraph.insn_to_dyn_nodes[starting_node.insn]:
            if prede_node.id not in node.input_sets:
                input_set_counts.add(0)
                input_set_count_list.append(0)
                if use_weight is True:
                    weighted_input_set_count_list.append(0)
            else:
                prede_count = node.input_sets[prede_node.id]
                input_set_counts.add(prede_count)
                input_set_count_list.append(prede_count)
                if use_weight is True:
                    output_weight = 0
                    if node.is_valid_weight is True:
                        output_weight = prede_count * node.weight
                    weighted_input_set_count_list.append(output_weight)

        ############ Calculate weights ############
        weight = ParallelizableRelationAnalysis.calculate_individual_weight(dgraph, reachable_output_events, starting_node, prede_node,
                                                  use_weight, base_weight)
        #static_node_to_weight[prede_node] = weight

        #if prede_node in static_node_to_weight:
        #    if static_node_to_weight[prede_node] < weight:
        #        static_node_to_weight[prede_node] = weight
        #    #    print("[ra] Updating weight for node: " + prede_node.hex_insn + "@" + prede_node.function)
        #else:
        #    static_node_to_weight[prede_node] = weight


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
                        + " contrib: " + "{:.2f}".format(weight.perc_contrib)
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

        if weight.perc_contrib < 1:
            if DEBUG: print("[ra] insn: " + prede_node.hex_insn + " only has a "
                            + str(weight.perc_contrib) + "% contribution to the output event, ignore ...")
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

    @staticmethod
    def one_pass(dgraph, starting_node, starting_weight, max_contrib):
        a = time.time()
        print("Starting forward and backward pass")
        wavefront = []
        #base_weight = len(dgraph.target_nodes)
        if starting_node.insn not in dgraph.insn_to_dyn_nodes:
            print("[ra] Node not found in the dynamic graph...")
            return wavefront, None

        # tests for forward invariance
        ################# Calculate base weight ######################
        ##############################################################
        base_weight, use_weight = ParallelizableRelationAnalysis.calculate_base_weight(dgraph)

        if base_weight is None:
            base_weight = starting_weight
        if base_weight < (max_contrib*0.01):
            print("[ra] Base weight is less than 1% of the max weight, ignore the node "
                  + starting_node.hex_insn + "@" + starting_node.function)
            return wavefront, None
        ################ Do forward propogation ######################
        ########## and backward propogation in the meanwhile #########
        reachable_output_events_per_static_node = {}
        ParallelizableRelationAnalysis.do_forward_propogation(dgraph, use_weight, reachable_output_events_per_static_node)

        ############## Setup for backward propogation ################
        ##############################################################
        ParallelizableRelationAnalysis.do_backward_propogation(dgraph, starting_node)

        ################### Calculate relations ######################
        ##############################################################
        rgroup = RelationGroup(starting_node, base_weight)

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
            ParallelizableRelationAnalysis.build_relation_with_predecessor(dgraph, starting_node, static_node, rgroup, wavefront,
                                                 use_weight, base_weight, reachable_output_events_per_static_node)

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
        rgroup.trim_invariant_group()
        b = time.time()
        print("[ra] One pass of relational analysis took: " + str(b - a))
        return wavefront, rgroup

if __name__ == "__main__":
    starting_events = []
    starting_events.append(["rdi", 0x409daa, "sweep"])
    starting_events.append(["rbx", 0x407240, "runtime.mallocgc"])
    starting_events.append(["rdx", 0x40742b, "runtime.mallocgc"])
    starting_events.append(["rcx", 0x40764c, "runtime.free"])
    prog = "909_ziptest_exe9"
    arg = "test.zip"
    path = "/home/anygroup/perf_debug_tool/"
    dd = DynamicDependence(starting_events, prog, arg, path)
    dd.prepare_to_build_dynamic_dependencies(10000)
    dgraph = dd.build_dynamic_dependencies(insn=0x409daa, pa_id=0)
    node = StaticDepGraph.func_to_graph["sweep"].insn_to_node[0x409daa]
    wavefront, rgroup = ParallelizableRelationAnalysis.one_pass(dgraph, node, 0, 0)
    print([(str(w.insn) + "@" + w.function) for w in wavefront], rgroup.toJSON())
