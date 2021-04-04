from dynamic_dep_graph import *
import time

class RelationAnalysis:
    def __init__(self):
        self.dg = None

    def analyze(self, insn, func, prog, arg, path):
        dd = DynamicDependence()
        self.dg = dd.build_dynamic_dependencies(insn, func, prog, arg, path, 1)
        assert self.dg is not None
        # tests for forward invariance
        print("[invariant_analysis] total number of target nodes: " + str(len(self.dg.target_nodes)))

        a = time.time()
        for node in self.dg.target_nodes:
            node.output_set.add(node)
        #get the postorder list, and check index

        i = 0
        static_postorder_map = {}
        for sn in StaticDepGraph.postorder_list:
            static_postorder_map[sn.insn] = i
            i += 1

        #TODO, use int as index where applicable?
        for node in self.dg.postorder_list:
            backedge_sources = node.static_node.backedge_sources
            node_insn = node.static_node.insn
            lines = node.static_node.bb.lines
            print("Visiting " + hex(node_insn) + " " + str(lines) + " order " + str(static_postorder_map[node_insn]))
            for cf_succe in node.cf_succes:
                cf_succe_insn = cf_succe.static_node.insn
                if cf_succe_insn in backedge_sources:
                    continue
                node.output_set = node.output_set.union(cf_succe.output_set)

            for df_succe in node.df_succes:
                df_succe_insn = df_succe.static_node.insn
                if df_succe_insn in backedge_sources:
                    continue
                node.output_set = node.output_set.union(df_succe.output_set)
        #add stack for cycle detection...
        #OK to be conditionally invariant~
        for insn in self.dg.insn_to_dyn_nodes:  # TODO, is this the right data structure?
            output_set_counts = set([])
            node_count = len(self.dg.insn_to_dyn_nodes[insn])
            for node in self.dg.insn_to_dyn_nodes[insn]:
                if node.output_set is None:
                    continue
                output_set_counts.add(len(node.output_set))
                static_node = node.static_node
            """
            print("[invariant_analysis] instruction: " + insn
                  + " df successors are: " + str([s.hex_insn for s in static_node.df_succes]))
            print("[invariant_analysis] instruction: " + insn
                  + " cf successors are: " + str([s.hex_insn for s in static_node.cf_succes]))
            """
            print("[invariant_analysis] instruction: " + insn
                  + " func  " + static_node.function
                  + " lines " + str(static_node.bb.lines)
                  + " output set counts: " + str(output_set_counts) \
                  + " total number of nodes: " + str(node_count))
            if len(output_set_counts) == 1:
                print("[invariant_analysis] instruction: "
                      + insn + " is forward invariant with the output event")
        b = time.time()
        print("One pass traversal took: " + str(b-a))

if __name__ == "__main__":
    ra = RelationAnalysis()
    ra.analyze(0x409daa, "sweep", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")