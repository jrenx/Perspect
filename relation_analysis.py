from dynamic_dep_graph import *
import time
import itertools
import heapq

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
    def __init__(self, target_node, prede_node):
        self.target_node = target_node
        self.prede_node = prede_node
        self.forward = None
        self.backward = None
        self.weight = -1

class RelationGroup:
    def __init__(self, starting_node):
        self.starting_node = starting_node
        self.relations = {}

    def get_or_make_relation(self, prede_node):
        if prede_node in self.relations:
            return self.relations[prede_node]
        else:
            r = Relation(self.starting_node, prede_node)
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
class RelationAnalysis:
    def __init__(self, insn, func, prog, arg, path):
        self.starting_insn = insn
        self.starting_func = func
        self.dd = DynamicDependence(insn, func, prog, arg, path)
        self.invariant_groups = {} #results

    def analyze(self):
        self.dd.prepare_to_build_dynamic_dependencies(10000)
        insn = self.starting_insn
        func = self.starting_func
        assert StaticDepGraph.starting_node.insn == insn
        static_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]
        visited = set()
        wavefront = set()
        iteration = 0
        while True:
            iteration += 1
            print()
            print("=====================================================")
            print("Relational analysis, pass number: " + str(iteration))
            static_node.print_node("[invariant_analysis] starting static node: ")
            #if iteration > 2:
            #    break
            if static_node not in visited:
                visited.add(static_node)
                rgroup = RelationGroup(static_node)
                self.invariant_groups[static_node] = rgroup
                #TODO: need to tell dynamic dependence to not do static slicing again
                #TODO also not rewatch pin
                a = time.time()
                dgraph = self.dd.build_dyanmic_dependencies(insn)
                print("Number of nodes in postorder_list: " + str(len(dgraph.postorder_list)))
                print("Number of nodes in reverse_postorder_list: " + str(len(dgraph.reverse_postorder_list)))
                assert dgraph is not None
                b = time.time()
                print("Building dynamic graph took: " + str(b - a))

                a = time.time()
                curr_wavefront = self.forward_pass(dgraph, static_node, rgroup)
                wavefront = wavefront.union(curr_wavefront)
                b = time.time()
                print("Forward pass took: " + str(b - a))
                print("=============================================")

                a = time.time()
                curr_wavefront = self.backward_pass(dgraph, static_node, rgroup)
                wavefront = wavefront.union(curr_wavefront)
                b = time.time()
                print("Backward pass took: " + str(b - a))
                #break #TODO remove
                if len(wavefront) == 0:
                    break
            else:
                print("Already visited...")
            if len(wavefront) > 0:
                next = wavefront.pop()
                insn = next.insn
                func = next.function
                static_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]

    def backward_pass(self, dgraph, starting_node, rgroup):
        print("Starting backward pass")
        wavefront = set()
        #for static_node in curr_wavefront:
        """
        entry_insns = set()
        for dyn_node in dgraph.entry_nodes: #TODO, ensure the entry nodes make sense...
            entry_insns.add(dyn_node.static_node.insn)
        for insn in entry_insns:
            for node in dgraph.insn_to_dyn_nodes[insn]:
                if insn not in node.input_sets:
                    node.input_sets[insn] = set()
                node.input_sets[insn].add(node)
        
        for node in dgraph.reverse_postorder_list:
            #TODO: do new reverse post order traversal to start from the wavefronts!
            #FIXME: dataflow dependencies cycles already detected, so we don't need to check again rrgroupht?
            #print("CHECKING: " + str(node.id))
            backedge_targets = node.static_node.backedge_targets
            for cf_prede in node.cf_predes:
                if cf_prede in dgraph.target_nodes:
                    continue
                if cf_prede.static_node.insn in backedge_targets:
                    #TODO?
                    #pending_wavefront.add(cf_prede.static_node)
                    print("[invariant_analysis] instruction: " + cf_prede.static_node.hex_insn + " added to pending list because of cycles...")
                    continue
                for insn in cf_prede.input_sets:
                    if insn not in node.input_sets:
                        node.input_sets[insn] = set()
                    node.input_sets[insn] = node.input_sets[insn].union(cf_prede.input_sets[insn])
                    node.input_sets[insn].add(cf_prede)

            for df_prede in node.df_predes:
                #print("    df prede:　" + str(df_prede.id))
                if df_prede in dgraph.target_nodes:
                    continue
                if df_prede.static_node.insn in backedge_targets:
                    # TODO?
                    #pending_wavefront.add(df_prede.static_node)
                    print("[invariant_analysis] instruction: " + df_prede.static_node.hex_insn + " added to pending list because of cycles...")
                    continue
                #print("        aggregating")
                for insn in df_prede.input_sets:
                    if insn not in node.input_sets:
                        node.input_sets[insn] = set()
                    node.input_sets[insn] = node.input_sets[insn].union(df_prede.input_sets[insn])
                    node.input_sets[insn].add(df_prede)

            if len(node.input_sets) > 0:
                insn = node.static_node.insn
                if insn not in node.input_sets:
                    node.input_sets[insn] = set()
                node.input_sets[insn].add(node)
        """

        # all the starting nodes
        starting_dynamic_nodes = []
        for node in dgraph.insn_to_dyn_nodes[starting_node.insn]:
            # special handle starting nodes
            node_insn = node.static_node.insn
            if node_insn not in node.input_sets:
                node.input_sets[node_insn] = set()
            node.input_sets[node_insn].add(node)
            # special handle starting nodes
            starting_dynamic_nodes.append(node)

        worklist = deque()
        worklist.append(starting_node)
        visited = set()  # TODO, ideally wanna propogate all the way, for now don't do that
        invariant_group = set()
        while (len(worklist) > 0):
            static_node = worklist.popleft()
            if static_node in visited:
                continue
            visited.add(static_node)  # TODO, optimize by using the insn?
            if static_node.explained is False:
                # TODO handle more carefully
                continue
            insn = static_node.insn
            hex_insn = static_node.hex_insn
            input_set_counts = set()
            input_set_count_list = []

            # assert insn in dgraph.insn_to_dyn_nodes, hex(insn)
            if insn not in dgraph.insn_to_dyn_nodes:
                #print("[warn] insn not in dynamic graph???" + hex(insn))
                continue
            print("-------")
            node_count = len(dgraph.insn_to_dyn_nodes[insn])
            for node in starting_dynamic_nodes:
                if static_node.insn not in node.input_sets:
                    input_set_counts.add(0)
                    input_set_count_list.append(0)
                else:
                    input_set_counts.add(len(node.input_sets[static_node.insn]))
                    input_set_count_list.append(len(node.input_sets[static_node.insn]))
            """
            print("[invariant_analysis] instruction: " + insn
                  + " df successors are: " + str([s.hex_insn for s in static_node.df_succes]))
            print("[invariant_analysis] instruction: " + insn
                  + " cf successors are: " + str([s.hex_insn for s in static_node.cf_succes]))
            """
            print("[invariant_analysis] instruction: " + hex_insn
                  + " func  " + static_node.function
                  + " lines " + (str(static_node.bb.lines) if isinstance(static_node.bb, BasicBlock) else str(static_node.bb))
                  + " input set counts: " + str(input_set_counts)
                  + " total number of nodes: " + str(node_count)
                  + " " + str(input_set_count_list))

            backward_invariant = False
            if Invariance.is_irrelevant(input_set_counts):
                print("[invariant_analysis] instruction: "
                      + hex_insn + " is irrelevant to the output event, ignore...")
                continue
            elif Invariance.is_invariant(input_set_counts):
                print("[invariant_analysis] instruction: "
                      + hex_insn + " is backward invariant with the output event")
                backward_invariant = True
                relation = rgroup.get_or_make_relation(static_node)
                relation.backward = Invariance(max(input_set_counts), False)
                # FIXME: could be conditionally invariant too!
            elif Invariance.is_conditionally_invariant(input_set_counts):
                print("[invariant_analysis] instruction: "
                      + hex_insn + " is conditionally backward invariant with the output event")
                backward_invariant = True
                relation = rgroup.get_or_make_relation(static_node)
                relation.backward = Invariance(max(input_set_counts), True)
            else:
                print("[invariant_analysis] NO INVARIANCE DETECTED")

            if backward_invariant is True:
                invariant_group.add(static_node)
            else:
                is_wavefront = False
                for s in itertools.chain(static_node.cf_succes, static_node.df_succes):
                    if s in invariant_group:
                        is_wavefront = True
                        break
                if is_wavefront:
                    wavefront.add(static_node)
                    relation = rgroup.get_or_make_relation(static_node)
                    relation.backward = Proportion(input_set_counts)
                    print("[invariant_analysis] instruction: "
                          + hex_insn + "'s backward proportion with the output event is considered")

            for p in static_node.cf_predes:
                worklist.append(p)
            for p in static_node.df_predes:
                worklist.append(p)
        for static_node in wavefront:
            print("[invariant_analysis] pending node: " + static_node.hex_insn
                  + " func  " + static_node.function
                  + " lines " + (str(static_node.bb.lines) if isinstance(static_node.bb, BasicBlock) else str(static_node.bb)))
        return wavefront

    def forward_pass(self, dgraph, starting_node, rgroup):
        print("Starting forward pass")
        wavefront = set()

        # tests for forward invariance
        #print("[invariant_analysis] total number of target nodes: " + str(len(dgraph.target_nodes)))
        for node in dgraph.target_nodes:
            node.output_set.add(node)

        for node in dgraph.postorder_list: #a node will be visited only if its successors have all been visited
            if node in dgraph.target_nodes:
                continue
            backedge_sources = node.static_node.backedge_sources
            for cf_succe in node.cf_succes:
                cf_succe_insn = cf_succe.static_node.insn
                if cf_succe_insn in backedge_sources:
                    wavefront.add(cf_succe.static_node)
                    #print("[invariant_analysis] instruction: " + cf_succe.static_node.hex_insn + " added to pending list because of cycles...")
                    continue
                node.output_set = node.output_set.union(cf_succe.output_set)

            for df_succe in node.df_succes:
                df_succe_insn = df_succe.static_node.insn
                if df_succe_insn in backedge_sources:
                    wavefront.add(df_succe.static_node)
                    #print("[invariant_analysis] instruction: " + df_succe.static_node.hex_insn + " added to pending list because of cycles...")
                    continue
                node.output_set = node.output_set.union(df_succe.output_set)
            for output_node in node.output_set:
                node_insn = node.static_node.insn
                if node_insn not in output_node.input_sets:
                    output_node.input_sets[node_insn] = set()
                output_node.input_sets[node_insn].add(node)

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
            output_set_counts = set()
            output_set_count_list = []
            total_output = set()

            #assert insn in dgraph.insn_to_dyn_nodes, hex(insn)
            if insn not in dgraph.insn_to_dyn_nodes:
                #print("[warn] insn not in dynamic graph???" + hex(insn))
                continue
            print("-------")
            node_count = len(dgraph.insn_to_dyn_nodes[insn])
            for node in dgraph.insn_to_dyn_nodes[insn]:
                output_set_counts.add(len(node.output_set))
                output_set_count_list.append(len(node.output_set))
                total_output = total_output.union(node.output_set)

            weight = len(total_output)
            """
            print("[invariant_analysis] instruction: " + insn
                  + " df successors are: " + str([s.hex_insn for s in static_node.df_succes]))
            print("[invariant_analysis] instruction: " + insn
                  + " cf successors are: " + str([s.hex_insn for s in static_node.cf_succes]))
            """
            print("[invariant_analysis] instruction: " + hex_insn
                  + " func  " + static_node.function
                  + " lines " + (str(static_node.bb.lines) if isinstance(static_node.bb, BasicBlock) else str(static_node.bb))
                  + " output set counts: " + str(output_set_counts)
                  + " weight: " + str(weight)
                  + " total number of nodes: " + str(node_count)
                  + " " + str(output_set_count_list))

            forward_invariant = False
            if Invariance.is_irrelevant(output_set_counts):
                print("[invariant_analysis] instruction: "
                      + hex_insn + " is irrelevant to the output event, ignore ...")
                continue
            elif Invariance.is_invariant(output_set_counts):
                print("[invariant_analysis] instruction: "
                      + hex_insn + " is forward invariant with the output event")
                forward_invariant = True
                relation = rgroup.get_or_make_relation(static_node)
                relation.forward = Invariance(max(output_set_counts), False)
                relation.weight = weight
                #FIXME: could be conditionally invariant too!
            elif Invariance.is_conditionally_invariant(output_set_counts):
                print("[invariant_analysis] instruction: "
                  + hex_insn + " is conditionally forward invariant with the output event")
                forward_invariant = True
                relation = rgroup.get_or_make_relation(static_node)
                relation.forward = Invariance(max(output_set_counts), True)
                relation.weight = weight
            else:
                print("[invariant_analysis] NO INVARIANCE DETECTED")

            if forward_invariant is True:
                invariant_group.add(static_node)
            else:
                is_wavefront = False
                for s in itertools.chain(static_node.cf_succes, static_node.df_succes):
                    if s in invariant_group:
                        is_wavefront = True
                        break
                if is_wavefront:
                    wavefront.add(static_node)
                    relation = rgroup.get_or_make_relation(static_node)
                    relation.forward = Proportion(output_set_counts)
                    relation.weight = weight
                    print("[invariant_analysis] instruction: "
                          + hex_insn + "'s forward proportion with the output event is considered")

            for p in static_node.cf_predes:
                worklist.append(p)
            for p in static_node.df_predes:
                worklist.append(p)
        for static_node in wavefront:
            print("[invariant_analysis] pending node: " + static_node.hex_insn
                  + " func  " + static_node.function
                  + " lines " + str(static_node.bb.lines))
            #TODO, change: only include those that are on the edgraphe of invariant and variant?
            #only include the original ones?
        return wavefront

if __name__ == "__main__":
    ra = RelationAnalysis(0x409daa, "sweep", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")
    ra.analyze()