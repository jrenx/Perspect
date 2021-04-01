import json
import os
import time
from sa_util import *
from rr_util import *
from pin_util import *
from collections import deque
from collections import OrderedDict
import shutil
from static_dep_graph import *
from pin.instruction_reg_trace import *
from json import JSONEncoder

curr_dir = os.path.dirname(os.path.realpath(__file__))
target_dir = os.path.join(curr_dir, 'dynamicGraph')
if os.path.exists(target_dir):
    shutil.rmtree(target_dir)
os.makedirs(target_dir)

time_record = {}

class DynamicNode(JSONEncoder):
    id = 0

    def __init__(self, insn_id, staticNode, id=None):
        if id is None:
            self.id = DynamicNode.id
            DynamicNode.id += 1
        else:
            self.id = id
        # self.instance_id = instance_id
        self.insn_id = insn_id
        self.staticNode = staticNode
        self.cf_predes = []
        self.cf_predes_insn_id = []
        self.cf_succes = []
        self.df_predes = []
        self.df_succes =[]
        self.mem_load = None
        self.mem_load_addr = None
        self.mem_store = None
        self.mem_store_addr = None
        self.output_set = set([])
        self.input_sets = {}

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
        for succe in self.cf_succes:
            s += '[' + str(succe.id) + "," + str(succe.insn_id) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic data flow predecessors: ["
        for prede in self.df_predes:
            s += '[' + str(prede.id) + "," + str(prede.insn_id) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic data flow successors: ["
        for succe in self.df_succes:
            s += '[' + str(succe.id) + "," + str(succe.insn_id) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    mem_load_addr: " + str(self.mem_load_addr) + "\n"
        s += "    mem_store_addr: " + str(self.mem_store_addr) + "\n"

        return s

    @staticmethod
    def fromJSON(node_info, static_nodes):
        id = node_info["id"]
        insn_id = node_info["insn_id"]
        static_node_id = node_info["static_node_id"]
        node = DynamicNode(insn_id, static_nodes[static_node_id], id)
        node.mem_load = node_info["mem_load"]
        node.mem_load_addr = node_info["mem_load_addr"]
        node.mem_store = node_info["mem_store"]
        node.mem_store_addr = node_info["mem_store_addr"]

class DynamicNodeEncoder(JSONEncoder):
    def default(self, o):
        node_info = {}
        node_info["id"] = o.id
        node_info["insn_id"] = o.insn_id
        node_info["static_node_id"] = o.staticNode.id
        node_info["cf_predes"] = []
        #if self.cf_predes:
        for n in o.cf_predes:
            node_info["cf_predes"].append(n.id)
        node_info["cf_predes_insn_id"] = o.cf_predes_insn_id
        node_info["cf_succes"] = []
        #if self.cf_succes:
        for n in o.cf_succes:
            node_info["cf_succes"].append(n.id)
        node_info["df_predes"] = []
        #if self.df_predes:
        for n in o.df_predes:
            node_info["df_predes"].append(n.id)
        node_info["df_succes"] = []
        #if self.df_succes:
        for n in o.df_succes:
            node_info["df_succes"].append(n.id)
        node_info["mem_load"] = json.dumps(o.mem_load, cls=MemoryAccessEncoder) #if self.mem_load is None else self.mem_load.toJSON()
        node_info["mem_load_addr"] = o.mem_load_addr
        node_info["mem_store"] = json.dumps(o.mem_store, cls=MemoryAccessEncoder) #if self.mem_store is None else self.mem_store.toJSON()
        node_info["mem_store_addr"] = o.mem_store_addr
        return node_info #json.dumps(node_info)

class DynamicDependence:
    def __init__(self):
        self.start_insn = None
        self.all_static_cf_nodes = []
        self.all_static_df_nodes = []
        self.insn_of_cf_nodes = []
        self.insn_of_df_nodes = []
        self.dynamicNodes = []
        self.insn_to_static_node = {}
        self.insn_of_local_df_nodes = []
        self.insn_of_remote_df_nodes = []

    def getDynamicExecutable(self, prog, arg, path):

        instructions = {}
        for node in self.all_static_cf_nodes:
            instructions[hex(node.insn)] = 'pc'

        for node in self.all_static_df_nodes:
            # trace local
            if node.mem_load != None and node.mem_load.reg != '':
                instructions[hex(node.insn)] = node.mem_load.reg.lower()
            # trace remote
            elif node.mem_store != None and node.mem_store.reg != '':
                instructions[hex(node.insn)] = node.mem_store.reg.lower()

        assert instructions[hex(node.insn)] != ''
        # invoke PIN. get output of a sequence of insn
        trace = InsRegTrace(path + prog + ' ' + path + arg,
                         pin='~/pin-3.11/pin')
        trace.run_function_trace(instructions)
        executable_path = os.path.join(curr_dir, 'pin', 'instruction_trace.out')
        #executable_path = os.path.join(curr_dir, 'pin', 'result')

        return executable_path

    def getSlice(self, insn, func, prog):

        # Get slice
        StaticDepGraph.buildDependencies(insn, func, prog)
        for graph in StaticDepGraph.func_to_graph.values():
            for node in graph.nodes_in_cf_slice:
                self.all_static_cf_nodes.append(node)

        for node in self.all_static_cf_nodes:
            self.insn_to_static_node[str(hex(node.insn))] = node
            self.insn_of_cf_nodes.append(str(hex(node.insn)))
            print(node)

        for graph in StaticDepGraph.func_to_graph.values():
            for node in graph.nodes_in_df_slice:

            #trace local
                if node.mem_load != None or node.mem_store != None:
                    self.all_static_df_nodes.append(node)
                    self.insn_to_static_node[str(hex(node.insn))] = node
                    self.insn_of_df_nodes.append(str(hex(node.insn)))
                    if node.mem_load != None :
                        self.insn_of_local_df_nodes.append(str(hex(node.insn)))
                    elif node.mem_store != None:
                        self.insn_of_remote_df_nodes.append(str(hex(node.insn)))

                print(node)


    def buildDynamicGraph(self, func, prog, insn, executable_path, load_from_json=False):
        # For each execution:

        with open(executable_path, 'r') as f1:
            insn_seq = f1.readlines()

        """ 
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
            dynamicGraph.build_dynamicGraph(executable, self.insn_to_static_node, self.insn_of_cf_nodes,
                                            self.insn_of_df_nodes, self.insn_of_local_df_nodes,
                                            self.insn_of_remote_df_nodes)
            start_index = index
            graph_number += 1
        """

        executable = insn_seq[:-1]
        dynamicGraph = DynamicGraph(func, prog, insn, 0)
        dynamicGraph.build_dynamicGraph(executable, self.insn_to_static_node, self.insn_of_cf_nodes,
                                        self.insn_of_df_nodes, self.insn_of_local_df_nodes,
                                        self.insn_of_remote_df_nodes)
        print("[dyn_dep] total number of nodes: " + str(len(dynamicGraph.dynamicNodes)))

        return dynamicGraph

    def buildDynamicDep(self, insn, func, prog, arg, path, load_from_json=False):

        # Get static dep, then invoke pin to get execution results, and build CFG
        if not load_from_json:
            self.getSlice(insn, func, prog)
            time_record["get_slice_start"] = time.time()
            print("[TIME]Get Slice time: ", time.asctime(time.localtime(time_record["get_slice_start"])))
            executable_path = self.getDynamicExecutable(prog, arg, path)
            time_record["invoke_pin"] = time.time()
            print("[TIME]Invoke Pin time: ", time.asctime(time.localtime(time_record["invoke_pin"])))
            dynamicGraph = self.buildDynamicGraph(func, prog, insn, executable_path)
        else:
            dynamicGraph = self.loadDynamicGraphFromJson(func, prog, insn) #TODO, save the json based on the starting point
        dynamicGraph.sanityCheck()
        print("[dyn_dep] total number of dynamic nodes: " + str(len(dynamicGraph.dynamicNodes)))
        dynamicGraph.findEntryNodes()
        dynamicGraph.findExitNodes()
        dynamicGraph.findTargetNodes(insn)
        dynamicGraph.buildPostorderList()
        dynamicGraph.buildReversePostorderList()
        dynamicGraph.groupNodesByInsn()
        return dynamicGraph

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
        self.node_frequence = {}
        self.insn_to_static_node = None
        self.postorder_list = []
        self.reverse_postorder_list = []
        self.entry_nodes = []
        self.exit_nodes = []
        self.target_nodes = []
        self.insn_to_dyn_nodes = {}

    def groupNodesByInsn(self):
        for node in self.dynamicNodes:
            insn = node.staticNode.insn
            if insn not in self.insn_to_dyn_nodes:
                self.insn_to_dyn_nodes[insn] = []
            self.insn_to_dyn_nodes[insn].append(node)

    def reversePostorderTraversalHelper(self, node, visited):
        if node.id in visited:
            #print("Node already visited, returning...")
            return
        visited.add(node.id)
        for cf_prede in node.cf_predes:
            self.reversePostorderTraversalHelper(cf_prede, visited)
        for df_prede in node.df_predes:
            self.reversePostorderTraversalHelper(df_prede, visited)
        #assert node not in self.reverse_postorder_list
        self.reverse_postorder_list.append(node)

    def buildReversePostorderList(self):
        #print("Exit nodes: " + str(len(self.exit_nodes)))
        visited = set([]) #TODO implement equals for dynamic node?
        for node in self.exit_nodes:
            self.reversePostorderTraversalHelper(node, visited)
        print("[dyn_dep] total number of nodes in reverse postorder_list: " + str(len(self.reverse_postorder_list)))

    def postorderTraversalHelper(self, node, visited):
        if node.id in visited:
            #print("Node already visited, returning...")
            return
        visited.add(node.id)
        for cf_succe in node.cf_succes:
            self.postorderTraversalHelper(cf_succe, visited)
        for df_succe in node.df_succes:
            self.postorderTraversalHelper(df_succe, visited)
        #assert node not in self.postorder_list
        self.postorder_list.append(node)

    def buildPostorderList(self):
        #print("Entry nodes: " + str(len(self.entry_nodes)))
        visited = set([]) #TODO implement equals for dynamic node?
        for node in self.entry_nodes:
            self.postorderTraversalHelper(node, visited)
        print("[dyn_dep] total number of nodes in postorder_list: " + str(len(self.postorder_list)))
        dynamicNodeIds = set([])
        for node in self.dynamicNodes:
            dynamicNodeIds.add(node.id)
        mismatch_count = 0
        duplicate_count = 0
        postorder_list_ids = set([])
        for node in self.postorder_list:
            if node.id not in postorder_list_ids:
                postorder_list_ids.add(node.id)
            else:
                duplicate_count += 1
            if node.id not in dynamicNodeIds:
                mismatch_count += 1
        print("[dyn_dep] number of nodes in reverse postorder list that are not in dynamic nodes: " + str(mismatch_count))
        print("[dyn_dep] number of duplicate nodes in reverse postorder list: " + str(duplicate_count))


    def findEntryNodes(self):
        if len(self.entry_nodes) > 0:
            return
        for node in self.dynamicNodes:
            if len(node.cf_predes) == 0 and len(node.df_predes) == 0:
                assert node not in self.entry_nodes
                self.entry_nodes.append(node)
        print("[dyn_dep] total number of entry nodes: " + str(len(self.entry_nodes)))

    def findExitNodes(self):
        if len(self.exit_nodes) > 0:
            return
        for node in self.dynamicNodes:
            if len(node.cf_succes) == 0 and len(node.df_succes) == 0:
                assert node not in self.exit_nodes
                self.exit_nodes.append(node)
        print("[dyn_dep] total number of exit nodes: " + str(len(self.exit_nodes)))

    def findTargetNodes(self, insn):
        if len(self.target_nodes) > 0:
            return

        for node in self.exit_nodes:
            if node.staticNode.insn == insn:
                self.target_nodes.append(node)
        print("[dyn_dep] total number of target nodes: " + str(len(self.target_nodes)))

    def sanityCheck(self):
        bad_count = 0
        for node in self.dynamicNodes:
            for p in node.cf_predes:
                if node not in p.cf_succes:
                    bad_count += 1
                    print("************ Type 1 ******************")
                    print("**************************************")
                    print(node)
                    print(p)
                #assert node in p.cf_succes, str(node) + str(p)
            for p in node.df_predes:
                if node not in p.df_succes:
                    bad_count += 1
                    print("************ Type 2 ******************")
                    print("**************************************")
                    print(node)
                    print(p)
                #assert node in p.df_succes, str(node) + str(p)
            for s in node.cf_succes:
                if node not in s.cf_predes:
                    bad_count += 1
                    print("************ Type 3  *****************")
                    print("**************************************")
                    print(node)
                    print(s)
                #assert node in node.cf_predes, str(node) + str(s)
            for s in node.df_succes:
                if node not in s.df_predes:
                    bad_count += 1
                    print("************ Type 4  *****************")
                    print("**************************************")
                    print(node)
                    print(s)
                #assert node in node.df_predes, str(node) + str(s)
            #print("Total bad count: " + str(bad_count))

    def build_dynamicGraph(self, executable, insn_to_static_node, insn_of_cf_nodes, insn_of_df_nodes,
                           insn_of_local_df_nodes, insn_of_remote_df_nodes):

        print("[TIME]Build Dynamic Graph Start Time: ", time.asctime(time.localtime(time.time())))

        # reverse the executetable, and remove insns beyond the start insn
        executable.reverse()
        self.insn_to_static_node = insn_to_static_node

        target_str = str(hex(self.start_insn)) + ": " + str(hex(self.start_insn)) + '\n'
        if target_str in executable:
            index = executable.index(target_str)
            executable = executable[index:]
        else:
            print("There is no target instruction detected during Execution " + str(self.number))
            return

        insn_id = 2

        addr_to_df_succe_node = {}
        cf_prede_insn_to_succe_node = {}
        df_prede_insn_to_succe_node = {}

        # traverse
        for insn_line in executable:
            if insn_line.find("eof") != -1:
                break

            result = insn_line.split(": ",1)
            insn = result[0]

            # mark visited insn
            if insn not in self.insn_to_id:
                self.insn_to_id[insn] = insn_id
                insn_id += 1

            mem_store_addr = None
            if insn != str(hex(self.start_insn)):
                if insn not in cf_prede_insn_to_succe_node and insn not in df_prede_insn_to_succe_node:
                    continue

                static_node = self.insn_to_static_node[insn]
                if insn in insn_of_remote_df_nodes:
                    reg_value = result[1].rstrip('\n')
                    mem_store_addr = self.mem_addr_calculate(reg_value, static_node.mem_store)
                    if mem_store_addr not in addr_to_df_succe_node:
                        continue
            else:
                static_node = self.insn_to_static_node[insn]

            dynamicNode = DynamicNode(self.insn_to_id[insn], static_node)
            self.dynamicNodes.append(dynamicNode)
            if insn not in self.node_frequence:
                self.node_frequence[insn] = 0
            self.node_frequence[insn] = self.node_frequence[insn] + 1

            if insn in cf_prede_insn_to_succe_node:
                to_remove = set([])
                for succe in cf_prede_insn_to_succe_node[insn]:
                    assert succe.id != dynamicNode.id
                    succe.cf_predes.append(dynamicNode)
                    dynamicNode.cf_succes.append(succe)

                    # Only save the closest pred
                    # TODO, what if actually have 2 predecessors

                    for cf_pred in succe.staticNode.cf_predes:
                        ni = cf_pred.hex_insn
                        assert cf_pred.hex_insn == str(hex(cf_pred.insn))
                        #if ni in cf_prede_insn_to_succe_node and succe in cf_prede_insn_to_succe_node[ni]:
                        #    cf_prede_insn_to_succe_node[ni].remove(succe)
                        to_remove.add(ni)
                if insn in cf_prede_insn_to_succe_node:
                    assert insn in to_remove
                for ni in to_remove:
                    if ni in cf_prede_insn_to_succe_node:
                        del cf_prede_insn_to_succe_node[ni]
                #del cf_prede_insn_to_succe_node[insn]

            if insn in df_prede_insn_to_succe_node:
                if insn in insn_of_remote_df_nodes:
                    dynamicNode.mem_store_addr = mem_store_addr
                    assert mem_store_addr is not None
                    assert mem_store_addr in addr_to_df_succe_node
                    
                    for succe in addr_to_df_succe_node[mem_store_addr]:
                        succe.df_predes.append(dynamicNode)
                        dynamicNode.df_succes.append(succe)
                    del addr_to_df_succe_node[mem_store_addr]

                else:
                    to_remove = set([])
                    for succe in df_prede_insn_to_succe_node[insn]:
                        assert succe.id != dynamicNode.id
                        succe.df_predes.append(dynamicNode)
                        dynamicNode.df_succes.append(succe)

                        # Only save the closest pred
                        # TODO, what if actually have 2 predecessors
                        for df_pred in succe.staticNode.df_predes:
                            ni = df_pred.hex_insn
                            to_remove.add(ni)
                            #if ni in df_prede_insn_to_succe_node and succe in df_prede_insn_to_succe_node[ni]:
                            #    df_prede_insn_to_succe_node[ni].remove(succe)

                    for ni in to_remove:
                        if ni in df_prede_insn_to_succe_node:
                            del df_prede_insn_to_succe_node[ni]

            if static_node.df_predes: # and insn not in insn_of_df_nodes:
                for prede in static_node.df_predes:
                    node_insn = prede.hex_insn
                    if node_insn not in insn_of_df_nodes and node_insn not in insn_of_cf_nodes: #Slice is not always complete
                        continue
                    # When we encounter a dataflow predecessor later,
                    # know which successors to connect to
                    if node_insn not in df_prede_insn_to_succe_node:
                        df_prede_insn_to_succe_node[node_insn] = set([dynamicNode])
                    else:
                        df_prede_insn_to_succe_node[node_insn].add(dynamicNode)
                        
                if static_node.mem_load is not None:
                    reg_value = result[1].rstrip('\n')
                    mem_load_addr = self.mem_addr_calculate(reg_value, static_node.mem_load)
                    dynamicNode.mem_load_addr = mem_load_addr
                    # TODO, do all addresses make sense?
                    if mem_load_addr not in addr_to_df_succe_node:
                        addr_to_df_succe_node[mem_load_addr] = []
                    addr_to_df_succe_node[mem_load_addr].append(dynamicNode)

            if static_node.cf_predes: # and insn not in insn_of_df_nodes:
                for prede in static_node.cf_predes:
                    node_insn = prede.hex_insn
                    if node_insn not in insn_of_df_nodes and node_insn not in insn_of_cf_nodes: #Slice is not always complete
                        continue
                        # When we encounter a control predecessor later,
                        # know which successors to connect to
                    if node_insn not in cf_prede_insn_to_succe_node:
                        cf_prede_insn_to_succe_node[node_insn] = set([dynamicNode])
                    else:
                        cf_prede_insn_to_succe_node[node_insn].add(dynamicNode)

        time_record["build_finsh"] = time.time()
        print("[TIME]Build Dynamic Graph Finish Time: ", time.asctime(time.localtime(time_record["build_finsh"])))
        self.print_graph()
        time_record["print_finsh"] = time.time()
        print("[TIME]Print Dynamic Graph Time: ", time.asctime(time.localtime(time_record["print_finsh"])))
        self.save_static_nodes_as_json(insn_to_static_node, insn_of_cf_nodes, insn_of_df_nodes,)
        time_record["save_static_nodes_as_json"] = time.time()
        print("[TIME] Static Nodes Json Save Time: ", time.asctime(time.localtime(time_record["save_static_nodes_as_json"])))
        self.save_dynamic_graph_as_json()
        time_record["save_dynamic_graph_as_json"] = time.time()
        print("[TIME] Dynamic Graph Json Save Time: ", time.asctime(time.localtime(time_record["save_dynamic_graph_as_json"])))
        print(self.insn_to_id)
        self.report_result()

    def report_result(self):

        print("[Report]There are totally " + str(len(self.dynamicNodes)) + " nodes.")
        print("[Report]the top 5 nodes that appeared the most number of times: ")
        top_five_insn = sorted(self.node_frequence.items(), key=lambda d: d[1], reverse = True)[:5]
        i = 1
        for item in top_five_insn:
            insn = item[0]
            times = item[1]
            node = self.insn_to_static_node[insn]
            string = "  No." + str(i) + ":\n"
            string += "     staticNode id: " + str(node.id) + "\n"
            string += "     frequence: " + str(times) + "\n"
            string += "     insn addr: " + insn + "\n"
            string += "     src line: " + str(node.bb.lines) + "\n\n"
            i = i+1

            print (string)

    def mem_addr_calculate(self, reg_addr, expr):
        """
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
        """
        reg_address = int(reg_addr, 16)
        shift = int(str(expr.shift), 16) #FIXME: why is shift empty sometimes??

        if shift == 0:
            shift = 1

        off = int(str(expr.off), 16)

        res = str(hex(reg_address * shift + off))

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

    def save_static_nodes_as_json(self, insn_to_static_node, insn_of_cf_nodes, insn_of_df_nodes,):

        json_file = os.path.join(target_dir, 'static_nodes_result')
        static_result = {}

        for insn in insn_of_cf_nodes:
            node = insn_to_static_node[insn]
            static_result[node.id] = self.get_static_node_json(node)

        for insn in insn_of_df_nodes:
            node = insn_to_static_node[insn]
            static_result[node.id] = self.get_static_node_json(node)

        with open(json_file, 'w') as out:
            #out.write(json.dumps(static_result))
            json.dump(static_result, out, ensure_ascii=False)


    def get_static_node_json(self, node):

        staticNode = {}

        staticNode["id"] = node.id
        staticNode["insn"] = node.insn  # FIXME, this is long type right
        staticNode["function"] = node.function  # FIXME, maybe rename this to func?
        staticNode["explained"] = node.explained

        staticNode["is_cf"] = node.is_cf
        staticNode["bb"] = None

        if node.bb:
            basicBlock = {}

            basicBlock["id"] = node.bb.id
            basicBlock["start_insn"] = node.bb.start_insn
            basicBlock["last_insn"] = node.bb.last_insn
            basicBlock["lines"] = node.bb.lines
            basicBlock["ends_in_branch"] = node.bb.ends_in_branch
            basicBlock["is_entry"] = node.bb.is_entry
            if node.bb.immed_dom:
                basicBlock["immed_dom"] = node.bb.immed_dom.id
            if node.bb.immed_pdom:
                basicBlock["immed_pdom"] = node.bb.immed_pdom.id
            basicBlock["pdoms"] = []
            if node.bb.pdoms:
                for n in node.bb.pdoms:
                    basicBlock["pdoms"].append(n.id)
            basicBlock["backedge_targets"] = []
            if node.bb.backedge_targets:
                for n in node.bb.backedge_targets:
                    basicBlock["backedge_targets"].append(n.id)
            basicBlock["predes"] = []
            if node.bb.predes:
                for n in node.bb.predes:
                    basicBlock["predes"].append(n.id)
            basicBlock["succes"] = []
            if node.bb.succes:
                for n in node.bb.succes:
                    basicBlock["succes"].append(n.id)

            staticNode["bb"] = json.dumps(basicBlock)

        staticNode["cf_predes"] = []
        if node.cf_predes:
            for n in node.cf_predes:
                staticNode["cf_predes"].append(n.id)
        staticNode["cf_succes"] = []
        if node.cf_succes:
            for n in node.cf_succes:
                staticNode["cf_succes"].append(n.id)

        staticNode["is_df"] = node.is_df
        staticNode["mem_load"] = str(node.mem_load)
        staticNode["reg_load"] = str(node.reg_load)

        staticNode["mem_store"] = str(node.mem_store)
        staticNode["reg_store"] = str(node.reg_store)

        staticNode["df_predes"] = []
        if node.df_predes:
            for n in node.df_predes:
                staticNode["df_predes"].append(n.id)
        staticNode["df_succes"] = []
        if node.df_succes:
            for n in node.df_succes:
                staticNode["df_succes"].append(n.id)

        return json.dumps(staticNode)

    def load_dynamic_graph_from_json(self):
        json_file = os.path.join(target_dir, 'dynamic_graph_result')

        with open(json_file) as infile:
            json_map = json.load(infile)


    def save_dynamic_graph_as_json(self):

        json_file = os.path.join(target_dir, 'dynamic_graph_result')
        dynamic_result = []

        for node in self.dynamicNodes:
            dynamic_result.append(node)

        with open(json_file, 'w') as out:
            #out.write(json.dumps(dynamic_result))
            json.dump(dynamic_result, out, cls=DynamicNodeEncoder, ensure_ascii=False)


if __name__ == '__main__':
    dynamic_graph = DynamicDependence()
    time_record["start_time"] = time.time()
    print("[TIME]Start time: ", time.asctime(time.localtime(time_record["start_time"])))
    dynamic_graph.buildDynamicDep(0x409daa, "sweep", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")

    print("[Summary] Get Slice: ", str(time_record["get_slice_start"]-time_record["start_time"]))
    print("[Summary] Invoke Pin: ", str(time_record["invoke_pin"] - time_record["get_slice_start"]))
    print("[Summary] Build Dynamic Graph: ", str(time_record["build_finsh"] - time_record["invoke_pin"]))
    print("[Summary] Print Dynamic Graph: ", str(time_record["print_finsh"] - time_record["build_finsh"]))
    print("[Summary] Static Nodes Json Saved: ",
          str(time_record["save_static_nodes_as_json"] - time_record["print_finsh"]))
    print("[Summary] Dynamic Graph Json Saved: ", str(time_record["save_dynamic_graph_as_json"] - time_record["save_static_nodes_as_json"]))
    #dynamic_graph.buildDynamicDep(0x409408, "scanblock", "909_ziptest_exe9")





