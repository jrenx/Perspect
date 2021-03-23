import json
import os
from sa_util import *
from rr_util import *
from pin_util import *
from collections import deque
from collections import OrderedDict
import shutil
from static_dep_graph import *
from pin.instruction_reg_trace import *

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
        # self.instance_id = instance_id
        self.insn_id = insn_id
        self.staticNode = staticNode
        self.cf_predes = []
        self.cf_predes_insn_id = []
        self.cf_success = []
        self.df_predes = []
        self.df_success =[]
        self.mem_load = None
        self.mem_load_addr = None
        self.mem_store = None
        self.mem_store_addr = None


    def __str__(self):
        s = "===============================================\n"
        # s += "   Instance id : " + str(self.instance_id) + "\n"
        s += "   Dynamic Node id: " + str(self.id) + "\n"
        s += "   Instruction id : " + str(self.insn_id) + "\n"
        s += "    -------------------------------------\n"
        s += "    ------------Static Node--------------\n"
        s += str(self.staticNode) + "\n"
        s += "    -------------------------------------\n"
        s += "    -------------------------------------\n"
        s += "    dynamic control flow predecessors: ["
        for prede in self.cf_predes:
            s += '[' + str(prede.id) + "," + str(prede.insn_id) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic control flow successors: ["
        for succe in self.cf_success:
            s += '[' + str(succe.id) + "," + str(succe.insn_id) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic data flow predecessors: ["
        for prede in self.df_predes:
            s += '[' + str(prede.id) + "," + str(prede.insn_id) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic data flow successors: ["
        for succe in self.df_success:
            s += '[' + str(succe.id) + "," + str(succe.insn_id) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    mem_load_addr: " + str(self.mem_load_addr) + "\n"
        s += "    mem_store_addr: " + str(self.mem_store_addr) + "\n"

        return s


class DynamicDependence:
    def __init__(self):
        self.start_insn = None
        self.all_static_cf_nodes = []
        self.all_static_df_nodes = []
        self.insn_of_cf_nodes = []
        self.insn_of_df_nodes = []
        self.dynamicNodes = []
        self.insn_to_nodes = {}
        self.insn_of_local_df_nodes = []
        self.insn_of_remote_df_nodes = []


    def getDynamicExecutable(self):

        instructions = {}
        for node in self.all_static_cf_nodes:
            instructions[hex(node.insn)] = 'pc'

        for node in self.all_static_df_nodes:
            # trace local
            if node.mem_load != None:
                instructions[hex(node.insn)] = node.mem_load.reg.lower()
            # trace remote
            elif node.mem_store != None:
                instructions[hex(node.insn)] = node.mem_store.reg.lower()

        # invoke PIN. get output of a sequence of insn
        trace = InsRegTrace('/home/anygroup/perf_debug_tool/909_ziptest_exe9 /home/anygroup/perf_debug_tool/test.zip',
                         pin='~/pin-3.11/pin')
        trace.run_function_trace(instructions)
        executable_path = os.path.join(curr_dir, 'pin', 'instruction_trace.out')
        #executable_path = os.path.join(curr_dir, 'pin', 'result')

        return executable_path

    def getSlice(self, insn, func, prog):

        # Get slice
        static_graph = StaticDepGraph()
        static_graph.buildDependencies(insn, func, prog)
        self.all_static_cf_nodes = static_graph.nodes_in_cf_slice

        for node in self.all_static_cf_nodes:
            self.insn_to_nodes[str(hex(node.insn))] = node
            self.insn_of_cf_nodes.append(str(hex(node.insn)))
            print(node)

        for node in static_graph.nodes_in_df_slice:

            #trace local
            if node.mem_load != None or node.mem_store != None:
                self.all_static_df_nodes.append(node)
                self.insn_to_nodes[str(hex(node.insn))] = node
                self.insn_of_df_nodes.append(str(hex(node.insn)))
                if node.mem_load != None :
                    self.insn_of_local_df_nodes.append(str(hex(node.insn)))
                elif node.mem_store != None:
                    self.insn_of_remote_df_nodes.append(str(hex(node.insn)))

                print(node)


    def buildDynamicGraph(self, func, prog, insn, executable_path):
        # For each execution:

        with open(executable_path, 'r') as f1:
            insn_seq = f1.readlines()

        line_num = 0
        line = insn_seq[line_num]
        start_insn = line.split(": ", 1)[0]
        while start_insn not in self.insn_of_cf_nodes:
            line_num += 1
            line = insn_seq[line_num]
            start_insn = line.split(": ", 1)[0]

        self.start_insn = start_insn

        dividing_line = [i for i, x in enumerate(insn_seq) if x == line]

        dividing_line.append(-1)

        start_index = dividing_line[0]
        graph_number = 0
        for index in dividing_line[1:]:
            executable = insn_seq[start_index:index]
            dynamicGraph = DynamicGraph(func, prog, insn, graph_number)
            dynamicGraph.build_dynamicGraph(executable, self.insn_to_nodes, self.insn_of_cf_nodes,
                                            self.insn_of_df_nodes, self.insn_of_local_df_nodes,
                                            self.insn_of_remote_df_nodes)
            start_index = index
            graph_number += 1

    def buildDynamicDep(self, insn, func, prog):

        # Get static dep, then invoke pin to get execution results, and build CFG

        self.getSlice(insn, func, prog)
        executable_path = self.getDynamicExecutable()
        self.buildDynamicGraph(func, prog, insn, executable_path)


class DynamicGraph:
    #TODO: restructure DynamicGraph
    def __init__(self, func, prog, insn, graph_number):
        self.func = func
        self.prog = prog
        self.start_insn = insn
        self.insn_to_id = {str(hex(self.start_insn)): 1}
        self.dynamicNodes = []
        self.number = graph_number
        self.root = None
        self.branch_nodes = []
        self.target_dir = os.path.join(curr_dir, 'dynamicGraph')

    def build_dynamicGraph(self, executable, insn_to_nodes, insn_of_cf_nodes, insn_of_df_nodes,
                           insn_of_local_df_nodes, insn_of_remote_df_nodes):

        # reverse the executetable, and remove insns beyond the start insn
        executable.reverse()

        target_str = str(hex(self.start_insn)) + ": " + str(hex(self.start_insn)) + '\n'
        if target_str in executable:
            index = executable.index(target_str)
            executable = executable[index:]
        else:
            print("There is no target instruction detected during Execution " + str(self.number))
            return

        # init
        previous_node = None
        is_first = True
        insn_id = 2
        local_df_pred = {}
        current_branch_nodes = {}
        succ_of_df_node = {}
        previous_line = None

        # traverse
        for insn_line in executable:
            if insn_line.find("eof") != -1:
                break

            result = insn_line.split(": ",1)
            insn = result[0]
            reg = result[1].rstrip('\n')

            # mark visited insn
            if insn not in self.insn_to_id:
                self.insn_to_id[insn] = insn_id
                insn_id += 1

            # the leaf
            if insn == str(hex(self.start_insn)):
                dynamicNode = DynamicNode(self.insn_to_id[insn], insn_to_nodes[insn])
                if insn_to_nodes[insn].df_predes and insn not in insn_of_df_nodes:
                    for node in insn_to_nodes[insn].df_predes:
                        node_insn = str(hex(node.insn))
                        if node_insn in insn_of_df_nodes:
                            if node_insn not in succ_of_df_node:
                                succ_of_df_node[node_insn] = [dynamicNode]
                            else:
                                succ_of_df_node[node_insn].append(dynamicNode)

                self.dynamicNodes.append(dynamicNode)

                if not is_first:
                    if previous_node.insn_id not in current_branch_nodes:
                        current_branch_nodes[previous_node.insn_id] = previous_node
                        if previous_node not in self.branch_nodes:
                            self.branch_nodes.append(previous_node)

                previous_node = dynamicNode
                visited_node = []

            elif not is_first:
                curr_node_id = self.insn_to_id[insn]
                if curr_node_id not in visited_node:
                    if curr_node_id in current_branch_nodes:
                        previous_node.cf_predes.append(current_branch_nodes[curr_node_id])
                        current_branch_nodes[curr_node_id].cf_success.append(previous_node)
                        visited_node.append(current_branch_nodes[curr_node_id].insn_id)
                        previous_node = current_branch_nodes[curr_node_id]
                    else:
                        if previous_node.insn_id in current_branch_nodes:
                            del current_branch_nodes[previous_node.insn_id]
                        if curr_node_id not in visited_node:
                            dynamicNode = DynamicNode(curr_node_id, insn_to_nodes[insn])
                            self.dynamicNodes.append(dynamicNode)
                            dynamicNode.cf_success.append(previous_node)

                            if insn in insn_of_cf_nodes:
                                if insn_to_nodes[insn].df_predes:
                                    for node in insn_to_nodes[insn].df_predes:
                                        node_insn = str(hex(node.insn))
                                        if node_insn in insn_of_df_nodes:
                                            if node_insn not in succ_of_df_node:
                                                succ_of_df_node[node_insn] = [dynamicNode]
                                            else:
                                                succ_of_df_node[node_insn].append(dynamicNode)
                                previous_node.cf_predes.append(dynamicNode)
                                previous_node = dynamicNode
                                visited_node.append(dynamicNode.insn_id)

                            if insn in insn_of_df_nodes:

                                if insn in insn_of_local_df_nodes:
                                    dynamicNode.mem_load_addr = self.mem_addr_calculate(reg,
                                                                                        str(dynamicNode.staticNode.mem_load))
                                    if dynamicNode.mem_load_addr not in local_df_pred:
                                        local_df_pred[dynamicNode.mem_load_addr] = []
                                    local_df_pred[dynamicNode.mem_load_addr].append(dynamicNode)

                                elif insn in insn_of_remote_df_nodes:
                                    dynamicNode.mem_store_addr = self.mem_addr_calculate(reg,
                                                                                         str(dynamicNode.staticNode.mem_store))
                                    if dynamicNode.mem_store_addr in local_df_pred:
                                        for node in local_df_pred[dynamicNode.mem_store_addr]:
                                            node.df_predes.append(dynamicNode)
                                            dynamicNode.df_success.append(node)
                                        del local_df_pred[dynamicNode.mem_store_addr]

                                current_node_in_dict = False
                                if insn in succ_of_df_node:
                                    for node in succ_of_df_node[insn]:
                                        if node.id != dynamicNode.id:
                                            node.df_predes.append(dynamicNode)
                                            dynamicNode.df_success.append(node)
                                        else:
                                            current_node_in_dict = True

                                    del succ_of_df_node[insn]
                                    if current_node_in_dict:
                                        succ_of_df_node[insn] = [dynamicNode]


            if is_first:
                is_first = False

        if dynamicNode.staticNode.insn in insn_of_df_nodes:
            self.root = dynamicNode.cf_success[-1]
        else:
            self.root = dynamicNode

        self.print_graph()
        print(self.insn_to_id)

    def mem_addr_calculate(self, reg_addr, expr):
        dict = {}
        json_exprs = []
        dict['insn_addr'] = int(reg_addr, 16)
        dict['expr'] = expr
        json_exprs.append(dict)
        data_points = parseLoadsOrStores(json_exprs)
        data_point = data_points[0]

        if data_point[2] == 0:
            data_point[2] = 1

        res = str(hex(data_point[0] * data_point[2] + data_point[3]))

        return res


    def print_graph(self):

        fname = os.path.join(self.target_dir, 'Graph_No.' + str(self.number))
        starting = "===============================================\n\n\n"
        starting += "    ------------Dynamic CFG No." + str(self.number) + "--------------\n"
        starting += "############## Dynamic Graph Root ############## \n"

        starting += str(self.root)
        starting += "\n\n===============================================\n\n"
        starting += "###########  Dynamic Graph branch nodes ########### \n"

        with open(fname, 'w') as out:
            out.write(starting)

        for node in self.branch_nodes:
            string = "      Instruction id: " + str(node.insn_id) + "\n"
            string += str(node)
            with open(fname, 'a') as out:
                out.write(string)

        string = "\n\n\n===============================================\n\n\n"
        string = "\n\n\n===============================================\n\n\n"
        string += "    ------------ DynamicNodes in CFG--------------\n"

        with open(fname, 'a') as out:
            out.write(string)

        for node in self.dynamicNodes:
            with open(fname, 'a') as out:
                out.write(str(node))


if __name__ == '__main__':
    dynamic_graph = DynamicDependence()
    dynamic_graph.buildDynamicDep(0x409daa, "sweep", "909_ziptest_exe9")
    #dynamic_graph.buildDynamicDep(0x409408, "scanblock", "909_ziptest_exe9")

