from dynamic_dep_graph import *
from relations import *
import itertools
import time
from util import *
from relation_analysis import *

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
    def do_forward_propogation(dgraph, use_weight):
        print("[ra] starting forward propogation")
        a = time.time()
        uid = 0
        for node in dgraph.target_nodes:
            node.output_set.add(node)
            node.output_set_uid = uid
            uid += 1

        visited = set()
        #same = 0
        #diff = 0
        #total1 = 0
        #total2 = 0
        for node in dgraph.postorder_list: #a node will be visited only if its successors have all been visited
            assert node not in visited
            visited.add(node)
            #if len(visited)%1000 == 0:
            #    print("[ra] visited " + str(len(visited)) + " nodes")
            if node in dgraph.target_nodes:
                continue
            #a1 = time.time()
            #node_insn = node.static_node.insn
            node_id = node.static_node.id
            #print("[ra] Forward propogating for node: " + hex(node_insn) + " " + str(node.id))
            #backedge_sources = node.static_node.backedge_sources
            seen_output_set = {}
            seen_output_exclude_set = {}
            exclude_set_updated = False
            for cf_succe in node.cf_succes:
                cf_succe_insn = cf_succe.static_node.insn
                if cf_succe_insn in node.static_node.backedge_sources:
                    for output_node in cf_succe.output_set:
                        if output_node.input_sets.get(node_id, 0) > 0:
                            #print("[ra] Node already attributed to the input of some output node: " + str(output_node.id))
                            node.output_exclude_set.add(output_node)
                            exclude_set_updated = True

                if cf_succe.output_set_uid not in seen_output_set:
                    seen_output_set[cf_succe.output_set_uid] = cf_succe.output_set
                    seen_output_exclude_set[cf_succe.output_set_uid] = cf_succe.output_exclude_set

            for df_succe in node.df_succes:
                if df_succe.static_node.is_df is False:
                    if df_succe.output_set_uid not in seen_output_exclude_set:
                        seen_output_exclude_set[df_succe.output_set_uid] = df_succe.output_exclude_set
                else:
                    if len(df_succe.output_exclude_set) > 0:
                        exclude_set_updated = True

                if df_succe.output_set_uid not in seen_output_set:
                    seen_output_set[df_succe.output_set_uid] = df_succe.output_set

            if exclude_set_updated is False and len(seen_output_set) == 1:
                assert(len(seen_output_exclude_set) <= 1)
                #same += 1
                for k in seen_output_set:
                    node.output_set_uid = k
                    node.output_set = seen_output_set[k]
                    break
                for k in seen_output_exclude_set:
                    assert node.output_set_uid == k
                    node.output_exclude_set = seen_output_exclude_set[k]
            else:
                #diff += 1
                for k in seen_output_set:
                    node.output_set = node.output_set.union(seen_output_set[k])
                for k in seen_output_exclude_set:
                    node.output_exclude_set = node.output_exclude_set.union(seen_output_exclude_set[k])

            if node.output_set_uid is None:
                node.output_set_uid = uid
                uid += 1
            #if len(visited)%100 == 0:
            #    print("[ra] output set size " + str(len(node.output_set)) + " nodes " + str([len(s.output_set) for s in itertools.chain(node.cf_succes, node.df_succes)]))
            #    print("[ra] same: " + str(same))
            #    print("[ra] diff: " + str(diff))
            #    print("[ra]total1 " + str(total1))
            #    print("[ra]total2 " + str(total2))
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

            #a2 = time.time()
            #total1 += (a2-a1)
            for node in itertools.chain(node.cf_succes, node.df_succes):
                if node.output_exclude_set is None: #already seen
                    continue
                if not ParallelizableRelationAnalysis.predes_all_visited(node, visited):
                    continue

                #if node in dgraph.target_nodes:
                #    continue
                #node_insn = node.static_node.insn
                #node_insn = node.static_node.insn
                node_id = node.static_node.id
                if len(node.output_exclude_set) > 0:
                    node.output_set = node.output_set.difference(node.output_exclude_set)
                for output_node in node.output_set:
                    count = output_node.input_sets.get(node_id, 0)
                    output_node.input_sets[node_id] = count + 1

                node.output_set_count = len(node.output_set)
                reachable_output_events = dgraph.reachable_output_events_per_static_node.get(node_id, set())
                reachable_output_events = reachable_output_events.union(node.output_set)
                dgraph.reachable_output_events_per_static_node[node_id] = reachable_output_events

                if use_weight is True:
                    output_weight = 0
                    for output in node.output_set:
                        if output.is_valid_weight is False:
                            continue
                        output_weight += output.weight
                    node.output_weight = output_weight
                node.output_exclude_set = None
                node.output_set = None
            #a3 = time.time()
            #total2 += (a3-a2)
        #print("[ra]total1 " + str(total1))
        #print("[ra]total2 " + str(total2))
        #print("[ra] same: " + str(same))
        #print("[ra] diff: " + str(diff))
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

            reachable_output_events = dgraph.reachable_output_events_per_static_node.get(node_id, set())
            reachable_output_events = reachable_output_events.union(node.output_set)
            dgraph.reachable_output_events_per_static_node[node_id] = reachable_output_events

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
                                                 use_weight, base_weight, prog, indices_not_found, timestamp, other_predes, ignore_low_weight=False):
        #insn = prede_node.insn
        #hex_insn = prede_node.hex_insn
        if DEBUG: print("-------")
        ########## Calculate output sets ##########
        output_set_counts = set()
        output_set_count_list = []
        weighted_output_set_count_list = []
        reachable_output_events = dgraph.reachable_output_events_per_static_node.get(prede_node.id, {})
        output_set_count_to_nodes = {} #for debugging
        for node in dgraph.insn_to_dyn_nodes[prede_node.insn]:
            output_set_count = node.output_set_count
            assert output_set_count is not None, str(node)
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

            #for output_set_count in output_set_count_to_nodes:
            #    print("[ra]  nodes with output count " + str(output_set_count)
            #          + " are: " + str([node.id for node in output_set_count_to_nodes[output_set_count]]))

            print("[ra] insn: " + prede_node.hex_insn
                        + "@" + prede_node.function
                        + " lines "
                        + (str(prede_node.bb.lines) if isinstance(prede_node.bb, BasicBlock) else str(prede_node.bb))
                        + " total number of nodes: " + str(node_count)
                        + " input set counts: " + str(input_set_counts)
                        + " " + str(input_set_count_list))

        key = other_predes.get_indices(prede_node) if other_predes is not None else None
        if ignore_low_weight is True:
            if key is None and weight.perc_contrib < 1:
                if DEBUG: print("[ra] insn: " + prede_node.hex_insn + " only has a "
                                + str(weight.perc_contrib) + "% contribution to the output event, ignore ...")
                return False
        #else:
        #    #FIXME: Not sure how this is possible...
        #    if key is None and round(weight.perc_contrib, 1) == 0.0:
        #        if DEBUG: print("[ra] insn: " + prede_node.hex_insn + " only has a "
        #                        + str(weight.perc_contrib) + "% contribution to the output event, ignore ...")
        #        return False
 
        if Invariance.is_irrelevant(output_set_counts) and Invariance.is_irrelevant(input_set_counts):
            if DEBUG: print("[ra] insn: " + prede_node.hex_insn + " is irrelevant  the output event, ignore ...")
            return False

        ################ build relations ################
        relation = rgroup.get_or_make_relation(prede_node, len(dgraph.insn_to_dyn_nodes[prede_node.insn]), weight, prog)
        relation.timestamp = timestamp
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
            relation.forward = Proportion(output_set_count_list, weighted_output_set_count_list)
            if DEBUG: print("[ra] insn: "
                            + prede_node.hex_insn + "'s forward proportion with the output event is considered")
            duplicate = False
            for s in itertools.chain(prede_node.cf_succes, prede_node.df_succes):
                if s in rgroup.relations and rgroup.relations[s] == relation:
                    duplicate = True
                    print("[ra] Duplicate, do not add to wavefront")
                    break
            if duplicate is False and indices_not_found is False:
                wavefront.append(prede_node)
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
            relation.backward = Proportion(input_set_count_list, weighted_input_set_count_list)
            if DEBUG: print("[ra] insn: "
                            + prede_node.hex_insn + "'s backward proportion with the output event is considered")
            if prede_node not in wavefront:
                duplicate = False
                for s in itertools.chain(prede_node.cf_succes, prede_node.df_succes):
                    if s in rgroup.relations and rgroup.relations[s] == relation:
                        duplicate = True
                        print("[ra] Duplicate, do not add to wavefront")
                        break
                if duplicate is False and indices_not_found is False:
                    wavefront.append(prede_node)

        return True

    @staticmethod
    def one_pass(dgraph, starting_node, starting_weight, max_contrib, prog, \
                 indices_map=None, indices_map_inner=None, other_simple_relation_groups=None, node_avg_timestamps=None, ignore_low_weight=False):
        a = time.time()
        print("Starting forward and backward pass for starting insn: " + hex(starting_node.insn))
        wavefront = []
        #base_weight = len(dgraph.target_nodes)
        if starting_node.insn not in dgraph.insn_to_dyn_nodes:
            print("[ra] Node not found in the dynamic graph...")
            return wavefront, None
        # tests for forward invariance
        ################# Calculate base weight ######################
        ##############################################################
        base_weight, use_weight = ParallelizableRelationAnalysis.calculate_base_weight(dgraph)

        other_used_weight = True
        other_predes = None
        other_wavefront = None
        curr_key = str(starting_node.file) + "_" + str(starting_node.line) + "_" + str(starting_node.total_count) + "_" + str(starting_node.index)
        if other_simple_relation_groups is not None:
            key = other_simple_relation_groups.indices.get_indices(starting_node)
            if key is not None:
                simple_relation_group = other_simple_relation_groups.relations_map.get(key)
                other_used_weight = simple_relation_group.used_weight
                other_predes = simple_relation_group.predes
                other_wavefront = simple_relation_group.wavefront
            print("[ra] same relation group in the other set of relations used weight? " + str(other_used_weight))
        #if other_used_weight is False:
        #    use_weight = False
        #    base_weight = None
        if base_weight is None:
            assert use_weight is False
            base_weight = starting_weight
        else:
            assert use_weight is True
        if ignore_low_weight is True:
            if (base_weight if other_used_weight is True else starting_weight) < (max_contrib*0.01):
                print("[ra] Base weight is less than 1% of the max weight, ignore the node "
                      + starting_node.hex_insn + "@" + starting_node.function)
                return wavefront, None

        if dgraph.reachable_output_events_per_static_node is None:
            dgraph.reachable_output_events_per_static_node = {}
            ################ Do forward propogation ######################
            ########## and backward propogation in the meanwhile #########
            ParallelizableRelationAnalysis.do_forward_propogation(dgraph, use_weight)

            ############## Setup for backward propogation ################
            ##############################################################
            ParallelizableRelationAnalysis.do_backward_propogation(dgraph, starting_node)
            with open(dgraph.result_file, 'w') as f:
                json.dump(dgraph.toJSON(), f, indent=4, ensure_ascii=False)
        ################### Calculate relations ######################
        ##############################################################
        rgroup = RelationGroup(starting_node, base_weight, prog)
        rgroup.use_weight = use_weight

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
            indices_not_found = False
            if indices_map is not None:
                if indices_map.indices_not_found(static_node):
                    indices_not_found = True
                    print("\n" + hex(static_node.insn) + "@" + static_node.function + " is not found in the other repro's static slice...")
                    succe_explained = False
                    if indices_map_inner is not None:
                        for p in itertools.chain(static_node.df_succes, static_node.cf_succes):
                            if indices_map_inner.get_indices(p) is not None:
                                succe_explained = True
                                break
                    if succe_explained is False:
                        print("\n" + hex(static_node.insn) + "@" + static_node.function + "'s succes are also not found in the other repro's inner static slice...")
                        continue

            analyzed = ParallelizableRelationAnalysis.build_relation_with_predecessor(dgraph, starting_node, static_node,
                                                                           rgroup, wavefront,
                                                                            use_weight, base_weight, prog, indices_not_found,
                                                                           node_avg_timestamps[static_node.insn] if node_avg_timestamps is not None else 0,
                                                                                      other_predes, ignore_low_weight)

            if indices_not_found is True or analyzed is False:
                continue
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
        rgroup.trim_invariant_group(other_wavefront)
        rgroup.weight = base_weight if other_used_weight is True else starting_weight
        rgroup.wavefront = wavefront
        b = time.time()
        print("[ra] One pass of relational analysis took: " + str(b - a))
        if other_wavefront is None:
            print("[ra] Other wavefront not found: " + str(curr_key))
            assert other_predes is None
            return wavefront, rgroup
        else:
            trimmed_wavefront = []
            print("[ra] Other wavefront found: " )
            #print(other_predes)
            #print(other_wavefront)
            for w in wavefront:
                k1 = other_predes.get_indices(w)
                k2 = other_wavefront.get_indices(w)
                if k1 is not None and k2 is None:
                    print("[ra] Remove wavelet " + w.hex_insn \
                          + " because it exists in the relations of the other repro but not in its wavefront")
                    continue
                if k1 is None and k2 is None:
                    print("[ra/warn] Wavelet " + w.hex_insn \
                          + " does not exist in the relations of the other repro or its wavefront")
                    continue
                trimmed_wavefront.append(w)
            return trimmed_wavefront, rgroup

if __name__ == "__main__":
    limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()
    dd = DynamicDependence(starting_events, program, program_args, program_path)
    dd.prepare_to_build_dynamic_dependencies(limit)

    func = "sweep"
    insn = 0x409daa
    dgraph = dd.build_dynamic_dependencies(insn=insn, pa_id=0)
    graph = StaticDepGraph.get_graph(func, insn)
    node = graph.insn_to_node[insn]
    wavefront, rgroup = ParallelizableRelationAnalysis.one_pass(dgraph, node, 0, 0, program)
    print([(str(w.insn) + "@" + w.function) for w in wavefront], rgroup.toJSON())
    print(rgroup)
