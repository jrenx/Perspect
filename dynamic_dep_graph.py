import json
import os
from sa_util import *
from rr_util import *
from pin_util import *
from collections import deque
from collections import OrderedDict
import shutil
from static_dep_graph import *
from pin.instruction_trace import *

curr_dir = os.path.dirname(os.path.realpath(__file__))
target_dir = os.path.join(curr_dir, 'dynamicGraph')
if os.path.exists(target_dir):
    shutil.rmtree(target_dir)
os.makedirs(target_dir)


class DynamicNode:
    id = 0

    def __init__(self, instance_number, staticNode):
        self.id = DynamicNode.id
        DynamicNode.id += 1
        self.instance_number = instance_number
        self.staticNode = staticNode
        self.cf_predes = []
        self.cf_success = []
        self.mem_load = None

    def __str__(self):
        s = "===============================================\n"
        s += "   Dynamic Node id: " + str(self.id) + "\n"
        s += "   Instance Number : " + str(self.instance_number) + "\n"
        s += "   Static Node id: " + str(self.staticNode.id) + "\n"
        s += "      insn: " + str(hex(self.staticNode.insn)) + "\n"
        s += "    ------------Basic Block--------------\n"
        if self.staticNode.bb is None:
            s += "\n"
        else:
            s += str(self.staticNode.bb)
        s += "    -------------------------------------\n"
        s += "    dynamic control flow predecessors: ["
        for prede in self.cf_predes:
            s += str(prede.id) + ","
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic control flow successors: ["
        for succe in self.cf_success:
            s += str(succe.id) + ","
        s = s.strip(",")
        s += "] \n"

        if self.mem_load is not None:
            s += "    " + str(self.mem_load)

        return s


class DynamicDependence:
    def __init__(self):
        self.start_insn = None
        self.all_static_nodes = []
        self.dynamicNodes = []
        self.insn_to_nodes = {}
        pass

    def getDynamicExecutable(self):

        instructions = []
        for node in self.all_static_nodes:
            instructions.append(hex(node.insn))

        # invoke PIN. get output of a sequence of insn
        # TODO: what is the successor?
        trace = InsTrace('/home/anygroup/perf_debug_tool/909_ziptest_exe9 /home/anygroup/perf_debug_tool/test.zip',
                         pin='~/pin-3.11/pin')
        trace.run_instruction_trace(instructions)
        executable_path = os.path.join(curr_dir, 'pin', 'instruction_trace.out')
        #executable_path = os.path.join(curr_dir, 'pin', 'result')

        return executable_path

    def getSlice(self, insn, func, prog):

        # Get slice
        static_graph = StaticDepGraph()
        static_graph.buildControlFlowDependencies(insn, func, prog)
        self.all_static_nodes = static_graph.nodes_in_cf_slice

        for node in self.all_static_nodes:
            self.insn_to_nodes[str(hex(node.insn))] = node

    def buildDynamicControlFlowGraph(self, func, prog, executable_path):
        # For each execution:

        with open(executable_path, 'r') as f1:
            insn_seq = f1.readlines()

        self.start_insn = insn_seq[0]

        dividing_line = [i for i, x in enumerate(insn_seq) if x == self.start_insn]

        dividing_line.append(-1)

        start_index = dividing_line[0]
        graph_number = 0
        for index in dividing_line[1:]:
            executable = insn_seq[start_index:index]
            dynamicCFG = DynamicCFG(func, prog, graph_number)
            dynamicCFG.build_dynamicCFG(executable, self.insn_to_nodes)
            start_index = index
            graph_number += 1


    def buildDynamicControlFlowDep(self, insn, func, prog):

        # Get static dep, then invoke pin to get execution results, and build CFG

        self.getSlice(insn, func, prog)
        executable_path = self.getDynamicExecutable()
        self.buildDynamicControlFlowGraph(func, prog, executable_path)




class DynamicCFG:
    def __init__(self, func, prog, graph_number):
        self.func = func
        self.prog = prog
        self.dynamicNodes = []
        self.number = graph_number
        self.target_dir = os.path.join(curr_dir, 'dynamicGraph')


    def build_dynamicCFG(self, executable, insn_to_nodes):

        insn_times = {}
        previous_node = None
        is_first = True
        for insn_line in executable:
            insn = insn_line.rstrip('\n')
            if insn.find("eof") != -1:
                break
            if insn in insn_times:
                insn_times[insn] += 1
            else:
                insn_times[insn] = 1
            time = insn_times[insn]
            node = insn_to_nodes[str(insn)]
            dynamicNode = DynamicNode(time, node)

            # set predecessor and successor
            if not is_first:
                dynamicNode.cf_predes.append(previous_node)
                previous_node.cf_success.append(dynamicNode)
            is_first = False
            previous_node = dynamicNode

            self.dynamicNodes.append(dynamicNode)

        self.print_graph()

    def print_graph(self):

        fname = os.path.join(self.target_dir, 'Graph_No.' + str(self.number))
        staring = "===============================================\n"
        staring += "    ------------Dynamic CFG No." + str(self.number) + "--------------\n"

        with open(fname, 'w') as out:
            out.write(staring)

        for node in self.dynamicNodes:
            with open(fname, 'a') as out:
                out.write(str(node))


if __name__ == '__main__':

    dynamic_graph = DynamicDependence()
    dynamic_graph.buildDynamicControlFlowDep(0x409daa, "sweep", "909_ziptest_exe9")

