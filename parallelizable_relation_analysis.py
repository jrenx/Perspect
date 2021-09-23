from dynamic_dep_graph import *
from relations import *

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

    @staticmethod
    def do_forward_propogation(dgraph):
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

    @staticmethod
    def do_backward_propogation(dgraph, starting_node):
        # all the starting nodes
        # insert starting node in the input set of the starting node
        for node in dgraph.insn_to_dyn_nodes[starting_node.insn]:
            # special handle starting nodes
            node_insn = node.static_node.insn #fixme: change to starting_node.insn
            if node_insn not in node.input_sets:
                node.input_sets[node_insn] = set()
            node.input_sets[node_insn].add(node)
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

    def build_relation_with_predecessor(self, dgraph, starting_node, prede_node, rgroup, wavefront,
                                                 use_weight, base_weight):
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

    @staticmethod
    def one_pass(dgraph, starting_node, starting_weight, max_contrib):
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
        ParallelizableRelationAnalysis.do_forward_propogation(dgraph)

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
            self.build_relation_with_predecessor(dgraph, starting_node, static_node, rgroup, wavefront,
                                                 use_weight, base_weight)

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
        return wavefront, rgroup

if __name__ == "__main__":
    #need to get the starting node, the max contrib
    pass