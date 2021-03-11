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

    def __init__(self, insn_id, staticNode):
        self.id = DynamicNode.id
        DynamicNode.id += 1
        #self.instance_id = instance_id
        self.insn_id = insn_id
        self.staticNode = staticNode
        self.cf_predes = []
        self.cf_success = []
        self.mem_load = None

    def __str__(self):
        s = "===============================================\n"
        #s += "   Instance id : " + str(self.instance_id) + "\n"
        s += "   Dynamic Node id: " + str(self.id) + "\n"
        s += "   Instruction id : " + str(self.insn_id) + "\n"
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
            s += str(prede.insn_id) + ","
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic control flow successors: ["
        for succe in self.cf_success:
            s += str(succe.insn_id) + ","
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

    def buildDynamicControlFlowGraph(self, func, prog, insn, executable_path):
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
            dynamicCFG = DynamicCFG(func, prog, insn, graph_number)
            dynamicCFG.build_dynamicCFG(executable, self.insn_to_nodes)
            start_index = index
            graph_number += 1


    def buildDynamicControlFlowDep(self, insn, func, prog):

        # Get static dep, then invoke pin to get execution results, and build CFG

        self.getSlice(insn, func, prog)
        executable_path = self.getDynamicExecutable()
        self.buildDynamicControlFlowGraph(func, prog, insn, executable_path)




class DynamicCFG:
    def __init__(self, func, prog, insn, graph_number):
        self.func = func
        self.prog = prog
        self.start_insn = insn
        self.insn_to_id = {str(hex(self.start_insn)): 1}
        self.dynamicNodes = []
        self.number = graph_number
        self.current_root = None
        self.branch_nodes = {}
        self.target_dir = os.path.join(curr_dir, 'dynamicGraph')


    def build_dynamicCFG(self, executable, insn_to_nodes):

        # reverse the executetable, and remove insns beyond the start insn
        executable.reverse()
        index = executable.index(str(hex(self.start_insn)) + '\n')
        executable = executable[index:]

        #init
        insn_times = {}
        previous_node = None
        is_first = True
        insn_id = 2

        #traverse
        for insn_line in executable:
            insn = insn_line.rstrip('\n')
            if insn.find("eof") != -1:
                break

            #mark visited insn
            if insn not in self.insn_to_id:
                self.insn_to_id[insn] = insn_id
                insn_id += 1

            # the leaf
            if insn == str(hex(self.start_insn)):
                dynamicNode = DynamicNode(self.insn_to_id[insn], insn_to_nodes[insn])
                self.dynamicNodes.append(dynamicNode)
                if not is_first:
                    if previous_node.insn_id not in self.branch_nodes:
                        self.branch_nodes[previous_node.insn_id] = previous_node
                else:
                    self.current_root = dynamicNode
                previous_node = dynamicNode

            if not is_first:

                curr_node_id = self.insn_to_id[insn]

                if curr_node_id in self.branch_nodes:
                    if curr_node_id != previous_node.insn_id:
                        previous_node.cf_predes.append(self.branch_nodes[curr_node_id])
                        self.branch_nodes[curr_node_id].cf_success.append(previous_node)
                        previous_node = self.branch_nodes[curr_node_id]

                elif curr_node_id > previous_node.insn_id:
                    dynamicNode = DynamicNode(curr_node_id, insn_to_nodes[insn])
                    self.dynamicNodes.append(dynamicNode)
                    dynamicNode.cf_success.append(previous_node)
                    previous_node.cf_predes.append(dynamicNode)
                    previous_node = dynamicNode

                    if curr_node_id > self.current_root.insn_id:
                        self.current_root = dynamicNode
            else:
                is_first = False

        self.print_graph()
        print(self.insn_to_id)

    def print_graph(self):

        fname = os.path.join(self.target_dir, 'Graph_No.' + str(self.number))
        starting = "===============================================\n"
        starting += "    ------------Dynamic CFG No." + str(self.number) + "--------------\n"
        starting += "   Dynamic Graph Root: \n"
        starting += str(self.current_root)
        starting += "===============================================\n"
        starting += "   Dynamic Graph branch nodes:  \n"

        with open(fname, 'w') as out:
            out.write(starting)

        for key in self.branch_nodes:
            string = "      Instruction id: " + str(key) + "\n"
            string += str(self.branch_nodes[key])
            with open(fname, 'a') as out:
                out.write(string)

        string = "\n===============================================\n"
        string += "    ------------ DynamicNodes in CFG--------------\n"

        with open(fname, 'a') as out:
            out.write(string)

        for node in self.dynamicNodes:
            with open(fname, 'a') as out:
                out.write(str(node))


if __name__ == '__main__':

    dynamic_graph = DynamicDependence()
    dynamic_graph.buildDynamicControlFlowDep(0x409daa, "sweep", "909_ziptest_exe9")


