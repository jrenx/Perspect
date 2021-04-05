from dynamic_dep_graph import *
import time

class RelationAnalysis:
    def __init__(self):
        pass

    def analyze(self, insn, func, prog, arg, path):
        dd = DynamicDependence(insn, func, prog, arg, path)
        dd.prepare_to_build_dynamic_dependencies(3)
        assert StaticDepGraph.starting_node.insn == insn
        static_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]
        wavefront = set()
        iteration = 0
        while True:
            iteration += 1
            print()
            print("=====================================================")
            print("Relational analysis, pass number: " + str(iteration))
            #if iteration > 2:
            #    break
            #TODO: need to tell dynamic dependence to not do static slicing again
            #TODO also not rewatch pin
            dg = dd.build_dyanmic_dependencies(insn)
            self.one_pass(dg, static_node, wavefront)
            if len(wavefront) == 0:
                break
            next = wavefront.pop()
            insn = next.insn
            func = next.function
            static_node = StaticDepGraph.func_to_graph[func].insn_to_node[insn]

    def one_pass(self, dg, starting_node, wavefront):
        assert dg is not None
        # tests for forward invariance
        #print("[invariant_analysis] total number of target nodes: " + str(len(dg.target_nodes)))
        starting_node.print_node("[invariant_analysis] starting static node: ")

        a = time.time()
        for node in dg.target_nodes:
            node.output_set.add(node)
        #get the postorder list, and check index

        #TODO, use int as index where applicable?
        for node in dg.postorder_list:
            backedge_sources = node.static_node.backedge_sources
            for cf_succe in node.cf_succes:
                cf_succe_insn = cf_succe.static_node.insn
                if cf_succe_insn in backedge_sources:
                    wavefront.add(cf_succe.static_node)
                    continue
                node.output_set = node.output_set.union(cf_succe.output_set)

            for df_succe in node.df_succes:
                df_succe_insn = df_succe.static_node.insn
                if df_succe_insn in backedge_sources:
                    wavefront.add(df_succe.static_node)
                    continue
                node.output_set = node.output_set.union(df_succe.output_set)

        #for insn in self.dg.insn_to_dyn_nodes:  # TODO, is this the right data structure?
        worklist = deque()
        worklist.append(starting_node)
        visited = set() #TODO, ideally wanna propogate all the way, for now don't do that
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
            print("-------")
            #assert insn in dg.insn_to_dyn_nodes, hex(insn)
            if insn not in dg.insn_to_dyn_nodes:
                print("[warn] insn not in dynamic graph???" + hex(insn))
                continue
            node_count = len(dg.insn_to_dyn_nodes[insn])
            for node in dg.insn_to_dyn_nodes[insn]:
                if node.output_set is None:
                    #TODO, handle this case carefully
                    continue
                output_set_counts.add(len(node.output_set))
                static_node = node.static_node
            """
            print("[invariant_analysis] instruction: " + insn
                  + " df successors are: " + str([s.hex_insn for s in static_node.df_succes]))
            print("[invariant_analysis] instruction: " + insn
                  + " cf successors are: " + str([s.hex_insn for s in static_node.cf_succes]))
            """
            print("[invariant_analysis] instruction: " + hex_insn
                  + " func  " + static_node.function
                  + " lines " + str(static_node.bb.lines)
                  + " output set counts: " + str(output_set_counts) \
                  + " total number of nodes: " + str(node_count))
            forward_invariant = False
            if len(output_set_counts) == 1:
                print("[invariant_analysis] instruction: "
                      + hex_insn + " is forward invariant with the output event")
                forward_invariant = True
                #FIXME: could be conditionally invariant too!
            if len(output_set_counts) == 2:
                if 0 in output_set_counts:
                    print("[invariant_analysis] instruction: "
                      + hex_insn + " is conditionally forward invariant with the output event")
                    forward_invariant = True
            if forward_invariant is True:
                for p in static_node.cf_predes:
                    worklist.append(p)
                for p in static_node.df_predes:
                    worklist.append(p)
            else:
                wavefront.add(static_node)
        b = time.time()
        for static_node in wavefront:
            print("[invariant_analysis] pending node: " + static_node.hex_insn
                  + " func  " + static_node.function
                  + " lines " + str(static_node.bb.lines))
        print("One pass traversal took: " + str(b-a))

if __name__ == "__main__":
    ra = RelationAnalysis()
    ra.analyze(0x409daa, "sweep", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")