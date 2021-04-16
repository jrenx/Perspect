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
import subprocess

curr_dir = os.path.dirname(os.path.realpath(__file__))
target_dir = os.path.join(curr_dir, 'dynamicGraph')

time_record = {}
DEBUG_POST_ORDER = False
DEBUG = False


class DynamicNode(JSONEncoder):
    id = 0

    def __init__(self, insn_id, static_node, id=None):
        if id is None:
            self.id = DynamicNode.id
            DynamicNode.id += 1
        else:
            self.id = id
        # self.instance_id = instance_id
        self.insn_id = insn_id
        self.static_node = static_node
        self.cf_predes = []
        self.cf_predes_insn_id = []
        self.cf_succes = []
        self.df_predes = []
        self.df_succes = []
        self.mem_load = None
        self.mem_load_addr = None
        self.mem_store = None
        self.mem_store_addr = None
        self.output_set = set() #TODO, persist these two as well?
        self.input_sets = {}

    def __str__(self):
        s = "===============================================\n"
        # s += "   Instance id : " + str(self.instance_id) + "\n"
        s += "   Dynamic Node id: " + str(self.id) + "\n"
        s += "   Instruction id : " + str(self.insn_id) + "\n"
        s += "    -------------------------------------\n"
        s += "    ------------Static Node--------------\n"
        s += str(self.static_node) + "\n"
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

    def toJSON(self):
        data = {}
        data["id"] = self.id
        data["insn_id"] = self.insn_id
        data["hex_insn"] = self.static_node.hex_insn #for debugging
        data["func"] = self.static_node.function #for debugging
        data["static_node"] = self.static_node.id
        data["cf_predes"] = []
        for n in self.cf_predes:
            data["cf_predes"].append(n.id)
        data["cf_predes_insn_id"] = self.cf_predes_insn_id
        data["cf_succes"] = []
        for n in self.cf_succes:
            data["cf_succes"].append(n.id)
        data["df_predes"] = []
        for n in self.df_predes:
            data["df_predes"].append(n.id)
        data["df_succes"] = []
        for n in self.df_succes:
            data["df_succes"].append(n.id)
        data["mem_load"] = self.mem_load if self.mem_load is None or not isinstance(self.mem_load, MemoryAccess) else \
                                        self.mem_load.toJSON()
        data["mem_load_addr"] = self.mem_load_addr
        data["mem_load_addr_hex"] = None if self.mem_load_addr is None else hex(self.mem_load_addr) #for debugging
        data["mem_store"] = self.mem_store if self.mem_store is None or not isinstance(self.mem_store, MemoryAccess) else \
                                        self.mem_store.toJSON()
        data["mem_store_addr"] = self.mem_store_addr
        data["mem_store_addr_hex"] = None if self.mem_store_addr is None else hex(self.mem_store_addr) #for debugging
        return data

    @staticmethod
    def fromJSON(data):
        id = data["id"]
        insn_id = data["insn_id"]
        static_node = data["static_node"]
        dn = DynamicNode(insn_id, static_node, id)

        dn.mem_load = data["mem_load"]
        if isinstance(dn.mem_load, dict):
            dn.mem_load = MemoryAccess.fromJSON(dn.mem_load)
        dn.mem_load_addr = data["mem_load_addr"]
        dn.mem_store = data["mem_store"]
        if isinstance(dn.mem_store, dict):
            dn.mem_store = MemoryAccess.fromJSON(dn.mem_store)
        dn.mem_store_addr = data["mem_store_addr"]

        dn.cf_predes = data['cf_predes']
        dn.cf_succes = data['cf_succes']
        dn.df_predes = data['df_predes']
        dn.df_succes = data['df_succes']
        dn.cf_predes_insn_id = data["cf_predes_insn_id"]
        return dn

class DynamicDependence:
    def __init__(self, insn, func, prog, arg, path):
        self.prog = prog
        self.arg = arg
        self.path = path
        self.start_insn = insn
        self.start_func = func
        self.key = None
        self.all_static_cf_nodes = []
        self.all_static_df_nodes = []
        self.insn_of_cf_nodes = []
        self.insn_of_df_nodes = []
        self.dynamic_nodes = []
        self.insn_to_static_node = {}
        self.insn_of_local_df_nodes = []
        self.insn_of_remote_df_nodes = []
        self.insn_to_reg_count = {}
        self.code_to_insn = {}
        self.insns_with_regs = set()

    def get_dynamic_trace(self, prog, arg, path, trace_name=""):
        trace_name = trace_name + 'instruction_trace.out'
        trace_path = os.path.join(curr_dir, 'pin', trace_name)
        
        instructions = []
        unique_insns = set()
        i = 0

        for node in self.all_static_df_nodes:
            if node.insn in unique_insns:
                continue
            unique_insns.add(node.insn)

            i += 1
            self.code_to_insn[i] = node.insn

            # trace local
            has_reg = False
            reg_count = 0
            if node.mem_load != None:
                if node.mem_load.reg != None and node.mem_load.reg != '':
                    instructions.append([node.hex_insn, node.mem_load.reg.lower(), i])
                    reg_count += 1
                    has_reg = True
                if node.mem_load.off_reg != None and node.mem_load.off_reg != '':
                    instructions.append([node.hex_insn, node.mem_load.off_reg.lower(), i])
                    reg_count += 1
                    has_reg = True
            # trace remote
            elif node.mem_store != None:
                if node.mem_store.reg != None and node.mem_store.reg != '':
                    instructions.append([node.hex_insn, node.mem_store.reg.lower(), i])
                    reg_count += 1
                    has_reg = True
                if node.mem_store.off_reg != None and node.mem_store.off_reg != '':
                    instructions.append([node.hex_insn, node.mem_store.off_reg.lower(), i])
                    reg_count += 1
                    has_reg = True
            if not has_reg:
                instructions.append([node.hex_insn, 'pc', i])
            if reg_count > 1:
                assert has_reg
                self.insn_to_reg_count[node.insn] = reg_count
            if reg_count >= 1:
                self.insns_with_regs.add(node.insn)

        for node in self.all_static_cf_nodes:
            if node.insn in unique_insns:
                continue
            unique_insns.add(node.insn)

            i += 1
            self.code_to_insn[i] = node.insn

            instructions.append([node.hex_insn, 'pc', i])


        if os.path.isfile(trace_path):
            return trace_path

        # invoke PIN. get output of a sequence of insn
        trace = InsRegTrace(path + prog + ' ' + path + arg,
                            pin='~/pin-3.11/pin', out=trace_name)
        print("[dyn_dep] Total number of instructions watched: " + str(len(instructions)))
        print(instructions)
        trace.run_function_trace(instructions)
        return trace_path

    def build_static_dependencies(self, insn, func, prog, sa_steps=10000):

        # Get slice #TODO, add a cache here
        used_cached_result = StaticDepGraph.build_dependencies(insn, func, prog, sa_steps)

        for graph in StaticDepGraph.func_to_graph.values():
            for node in graph.nodes_in_cf_slice:
                self.all_static_cf_nodes.append(node)

        for node in self.all_static_cf_nodes:
            self.insn_to_static_node[node.insn] = node
            self.insn_of_cf_nodes.append(node.insn)
            #print(node)

        for graph in StaticDepGraph.func_to_graph.values():
            for node in graph.nodes_in_df_slice:

                # trace local
                if node.mem_load != None or node.mem_store != None:
                    self.all_static_df_nodes.append(node)
                    self.insn_to_static_node[node.insn] = node
                    self.insn_of_df_nodes.append(node.insn)
                    if node.mem_load != None:
                        self.insn_of_local_df_nodes.append(node.insn)
                    elif node.mem_store != None:
                        self.insn_of_remote_df_nodes.append(node.insn)

                #print(node)
        return used_cached_result

    def build_dyanmic_dependencies(self, insn):
        result_file = os.path.join(curr_dir, 'cache', 'dynamic_graph_result_' + self.key + "_" + str(insn))
        if os.path.isfile(result_file):
            with open(result_file, 'r') as f:
                in_result = json.load(f)
                static_id_to_node = {}
                for func in StaticDepGraph.func_to_graph:
                    for sn in StaticDepGraph.func_to_graph[func].id_to_node.values():
                        static_id_to_node[sn.id] = sn
                dynamic_graph = DynamicGraph.fromJSON(in_result, static_id_to_node)
                time_record["load_json"] = time.time()
                print("[TIME]Load Slice time: ", time.asctime(time.localtime(time_record["load_json"])))
        else:
            trace_path = self.get_dynamic_trace(self.prog, self.arg, self.path, self.key + "_")
            time_record["invoke_pin"] = time.time()
            print("[TIME]Invoke Pin time: ", time.asctime(time.localtime(time_record["invoke_pin"])), flush=True)
            a = time.time()
            preprocess_data = {
                "trace_file": trace_path,
                "static_graph_file": StaticDepGraph.result_file,
                "start_insn": insn,
                "code_to_insn" : self.code_to_insn,
                "insns_with_regs" : list(self.insns_with_regs),
                "insn_of_cf_nodes" : self.insn_of_cf_nodes,
                "insn_of_df_nodes" : self.insn_of_df_nodes,
                "insn_of_local_df_nodes" : self.insn_of_local_df_nodes,
                "insn_of_remote_df_nodes" : self.insn_of_remote_df_nodes,
                "insn_to_reg_count" : self.insn_to_reg_count
            }
            preprocess_data_file = os.path.join(curr_dir, 'preprocess_data')
            with open(preprocess_data_file, 'w') as f:
                json.dump(preprocess_data, f, indent=4, ensure_ascii=False)
            preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'preprocess')
            rr_process = subprocess.Popen([preprocessor_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = rr_process.communicate()
            print(stdout)
            print(stderr)
            b = time.time()
            print("Preparsing trace took: " + str(b-a), flush=True)

            a = time.time()
            with open(trace_path + ".parsed", 'rb') as f:
                byte_seq = f.read() #more than twice faster than readlines!

            b = time.time()
            print("Loading trace took: " + str(b-a), flush=True)

            dynamic_graph = DynamicGraph(insn)
            dynamic_graph.build_dynamic_graph(byte_seq, self.code_to_insn, self.insns_with_regs, self.insn_to_static_node,
                                              set(self.insn_of_cf_nodes), set(self.insn_of_df_nodes),
                                              set(self.insn_of_local_df_nodes), set(self.insn_of_remote_df_nodes),
                                              self.insn_to_reg_count)

            time_record["build_finish"] = time.time()
            print("[TIME]Build Dynamic Graph Finish Time: ", time.asctime(time.localtime(time_record["build_finish"])))

            dynamic_graph.sanity_check()
            dynamic_graph.find_entry_and_exit_nodes()
            dynamic_graph.find_target_nodes(insn)
            dynamic_graph.build_postorder_list()
            dynamic_graph.build_reverse_postorder_list()

            time_record["graph_traversal"] = time.time()
            print("[TIME] Graph traversal Time: ",
                  time.asctime(time.localtime(time_record["graph_traversal"])))

            with open(result_file, 'w') as f:
                json.dump(dynamic_graph.toJSON(), f, indent=4, ensure_ascii=False)

            time_record["save_dynamic_graph_as_json"] = time.time()
            print("[TIME] Dynamic Graph Json Save Time: ",
                  time.asctime(time.localtime(time_record["save_dynamic_graph_as_json"])))

        print("[dyn_dep] total number of dynamic nodes: " + str(len(dynamic_graph.dynamic_nodes)))
        return dynamic_graph

    def prepare_to_build_dynamic_dependencies(self, sa_steps=10000):
        time_record["start_time"] = time.time()
        print("[TIME]Start time: ", time.asctime(time.localtime(time_record["start_time"])))

        # Get static dep, then invoke pin to get execution results, and build CFG
        #FIXME: convert start instruction to hex
        self.key = str(self.start_insn) + "_" + str(self.start_func) + "_" + str(self.prog) + "_" + str(sa_steps)

        used_cached_result = self.build_static_dependencies(self.start_insn, self.start_func, self.prog, sa_steps)
        time_record["get_slice_start"] = time.time()
        print("[TIME]Get Slice time: ", time.asctime(time.localtime(time_record["get_slice_start"])))


class DynamicGraph:
    # TODO: restructure DynamicGraph
    def __init__(self, insn):
        self.start_insn = insn
        self.insn_to_id = {self.start_insn: 1}
        self.dynamic_nodes = []
        self.target_dir = os.path.join(curr_dir, 'dynamicGraph')
        self.node_frequencies = {}
        self.insn_to_static_node = None
        self.postorder_list = []
        self.reverse_postorder_list = []
        self.entry_nodes = set()
        self.exit_nodes = set()
        self.target_nodes = set()
        self.insn_to_dyn_nodes = {}
        
    def toJSON(self):
        data = {}
        data["start_insn"] = self.start_insn
        data["insn_to_id"] = self.insn_to_id

        data["dynamic_nodes"] = []
        for n in self.dynamic_nodes:
            data["dynamic_nodes"].append(n.toJSON())

        data["node_frequencies"] = self.node_frequencies

        data["postorder_list"] = []
        for n in self.postorder_list:
            data["postorder_list"].append(n.id)

        data["reverse_postorder_list"] = []
        for n in self.reverse_postorder_list:
            data["reverse_postorder_list"].append(n.id)

        data["entry_nodes"] = []
        for n in self.entry_nodes:
            data["entry_nodes"].append(n.id)

        data["exit_nodes"] = []
        for n in self.exit_nodes:
            data["exit_nodes"].append(n.id)

        data["target_nodes"] = []
        for n in self.target_nodes:
            data["target_nodes"].append(n.id)

        return data

    @staticmethod
    def fromJSON(data, static_id_to_node):
        start_insn = data["start_insn"]
        dg = DynamicGraph(start_insn)
        dg.insn_to_id = data["insn_to_id"]

        id_to_node = {}
        for n in data["dynamic_nodes"]:
            dn = DynamicNode.fromJSON(n)
            dg.dynamic_nodes.append(dn)
            id_to_node[dn.id] = dn
            dn.static_node = static_id_to_node[dn.static_node]

        for dn in dg.dynamic_nodes:
            insn = dn.static_node.insn
            if insn not in dg.insn_to_dyn_nodes:
                dg.insn_to_dyn_nodes[insn] = []
            dg.insn_to_dyn_nodes[insn].append(dn)

            cf_predes = []
            for id in dn.cf_predes:
                cf_predes.append(id_to_node[id])
            dn.cf_predes = cf_predes
    
            cf_succes = []
            for id in dn.cf_succes:
                cf_succes.append(id_to_node[id])
            dn.cf_succes = cf_succes
    
            df_predes = []
            for id in dn.df_predes:
                df_predes.append(id_to_node[id])
            dn.df_predes = df_predes
    
            df_succes = []
            for id in dn.df_succes:
                df_succes.append(id_to_node[id])
            dn.df_succes = df_succes
            
        dg.node_frequencies = data["node_frequencies"]

        if "insn_to_static_node" in data:
            dg.insn_to_static_node = {}
            for func in func_to_graph:
                for node in func_to_graph[func].nodes_in_cf_slice:
                    dg.insn_to_static_node[node.insn] = node
                for node in func_to_graph[func].nodes_in_df_slice:
                    dg.insn_to_static_node[node.insn] = node

        for id in data["postorder_list"]:
            dg.postorder_list.append(id_to_node[id])
        for id in data["reverse_postorder_list"]:
            dg.reverse_postorder_list.append(id_to_node[id])
        for id in data["entry_nodes"]:
            dg.entry_nodes.add(id_to_node[id])
        for id in data["exit_nodes"]:
            dg.exit_nodes.add(id_to_node[id])
        for id in data["target_nodes"]:
            dg.target_nodes.add(id_to_node[id])
        return dg

    """
    def groupNodesByInsn(self):
        for node in self.dynamic_nodes:
            insn = node.static_node.insn
            if insn not in self.insn_to_dyn_nodes:
                self.insn_to_dyn_nodes[insn] = []
            self.insn_to_dyn_nodes[insn].append(node)
    """

    def print_node(self, prefix, n):
        print(prefix
              + " d_id: " + str(n.id) + " s_id: " + str(n.static_node.id)
              + " insn: " + n.static_node.hex_insn + " lines: " + str(n.static_node.bb.lines)
              + " cf ps: " + str([pp.id for pp in n.cf_predes])
              + " df ps: " + str([pp.id for pp in n.df_predes])
              + " cf ss: " + str([ps.id for ps in n.cf_succes])
              + " df ss: " + str([ps.id for ps in n.df_succes]))
        
    # a node can be visited if all its predecessors are visited
    def build_reverse_postorder_list(self): #TODO, refactor one day and combine into one function
        self.reverse_postorder_list = []

        prede_to_node = {}
        node_to_pending_prede_count = {}
        all_completed = set()
        visited = set()
        worklist = deque()
        for n in self.entry_nodes:
            worklist.append(n)
            if DEBUG_POST_ORDER: self.print_node("Initial  ", n)

        while len(worklist) > 0:
            curr = worklist.popleft()
            if DEBUG_POST_ORDER: self.print_node("Visiting ", curr)
            assert curr not in visited, str(curr in self.reverse_postorder_list) + " " + str(curr in all_completed)
            visited.add(curr)
            pending_prede_count = 0
            for p in curr.cf_predes:
                if p not in all_completed:
                    pending_prede_count += 1
                    if p not in prede_to_node:
                        prede_to_node[p] = []
                    prede_to_node[p].append(curr)
                    if DEBUG_POST_ORDER: self.print_node("Waiting for cf prede  ", p)
            for p in curr.df_predes:
                if p not in all_completed:
                    pending_prede_count += 1
                    if p not in prede_to_node:
                        prede_to_node[p] = []
                    prede_to_node[p].append(curr)
                    if DEBUG_POST_ORDER: self.print_node("Waiting for df prede  ", p)
            if pending_prede_count == 0:
                completed = curr
                repeat = True
                while repeat:
                    repeat = False
                    self.reverse_postorder_list.append(completed)
                    assert completed not in all_completed
                    all_completed.add(completed)
                    if DEBUG_POST_ORDER: self.print_node("Adding   ", completed)
                    for s in completed.cf_succes:
                        if s in node_to_pending_prede_count:
                            continue
                        if s in worklist:
                            continue
                        assert s not in all_completed
                        worklist.append(s)
                        if DEBUG_POST_ORDER: self.print_node("Queuing  ", s)
                    for s in completed.df_succes:
                        if s in node_to_pending_prede_count:
                            continue
                        if s in worklist:
                            continue
                        assert s not in all_completed
                        if DEBUG_POST_ORDER: self.print_node("Queuing  ", s)
                    if completed in prede_to_node:
                        for n in prede_to_node[completed]:
                            node_to_pending_prede_count[n] = node_to_pending_prede_count[n] - 1
                            if DEBUG_POST_ORDER: self.print_node("Current count: " + str(node_to_pending_prede_count[n]), n)
                        del prede_to_node[completed]
                    for n in node_to_pending_prede_count:
                        assert node_to_pending_prede_count[n] >= 0
                        if node_to_pending_prede_count[n] == 0:
                            completed = n
                            repeat = True
                            break
                    if repeat is True:
                        del node_to_pending_prede_count[completed]
            else:
                node_to_pending_prede_count[curr] = pending_prede_count

        if DEBUG_POST_ORDER: print("Total remaining: " + str(len(node_to_pending_prede_count)))
        if DEBUG_POST_ORDER:
            for n in node_to_pending_prede_count:
                self.print_node("Remaining count: " + str(node_to_pending_prede_count[n]), n)
        #assert len(node_to_pending_prede_count) == 0, str(len(node_to_pending_prede_count))
        #assert len(prede_to_node) == 0, str(len(prede_to_node))
        print("[dyn_dep] total number of nodes in reverse postorder_list: " + str(len(self.reverse_postorder_list)))

    # a node can be visited if all its successors are visited
    def build_postorder_list(self):
        self.postorder_list = []

        succe_to_node = {}
        node_to_pending_succe_count = {}
        all_completed = set()
        visited = set()
        worklist = deque()
        for n in self.exit_nodes:
            worklist.append(n)
            if DEBUG_POST_ORDER: self.print_node("Initial  ", n)

        while len(worklist) > 0:
            curr = worklist.popleft()
            if DEBUG_POST_ORDER: self.print_node("Visiting ", curr)
            assert curr not in visited, str(curr in self.postorder_list) + " " + str(curr in all_completed)
            visited.add(curr)
            pending_succe_count = 0
            for s in curr.cf_succes:
                if s not in all_completed:
                    pending_succe_count += 1
                    if s not in succe_to_node:
                        succe_to_node[s] = []
                    succe_to_node[s].append(curr)
                    if DEBUG_POST_ORDER: self.print_node("Waiting for cf succe  ", s)
            for s in curr.df_succes:
                if s not in all_completed:
                    pending_succe_count += 1
                    if s not in succe_to_node:
                        succe_to_node[s] = []
                    succe_to_node[s].append(curr)
                    if DEBUG_POST_ORDER: self.print_node("Waiting for df succe  ", s)
            if pending_succe_count == 0:
                completed = curr
                repeat = True
                while repeat:
                    repeat = False
                    self.postorder_list.append(completed)
                    assert completed not in all_completed
                    all_completed.add(completed)
                    if DEBUG_POST_ORDER: self.print_node("Adding   ", completed)
                    for p in completed.cf_predes:
                        if p in node_to_pending_succe_count:
                            continue
                        if p in worklist:
                            continue
                        assert p not in all_completed
                        worklist.append(p)
                        if DEBUG_POST_ORDER: self.print_node("Queuing    ", p)
                    for p in completed.df_predes:
                        if p in node_to_pending_succe_count:
                            continue
                        if p in worklist:
                            continue
                        assert p not in all_completed
                        worklist.append(p)
                        if DEBUG_POST_ORDER: self.print_node("Queuing    ", p)
                    if completed in succe_to_node:
                        for n in succe_to_node[completed]:
                            node_to_pending_succe_count[n] = node_to_pending_succe_count[n] - 1
                            if DEBUG_POST_ORDER: self.print_node("Current count: " + str(node_to_pending_succe_count[n]), n)
                        del succe_to_node[completed]
                    for n in node_to_pending_succe_count:
                        assert node_to_pending_succe_count[n] >= 0
                        if node_to_pending_succe_count[n] == 0:
                            completed = n
                            repeat = True
                            break
                    if repeat is True:
                        del node_to_pending_succe_count[completed]
            else:
                node_to_pending_succe_count[curr] = pending_succe_count
        if DEBUG_POST_ORDER:
            print("Total remaining: " + str(len(node_to_pending_succe_count)))
        if DEBUG_POST_ORDER:
            for n in node_to_pending_succe_count:
                self.print_node("Remaining count: " + str(node_to_pending_succe_count[n]), n)
        #assert len(node_to_pending_succe_count) == 0, str(len(node_to_pending_succe_count))
        #assert len(succe_to_node) == 0, str(len(succe_to_node))
        print("[dyn_dep] total number of nodes in postorder_list: " + str(len(self.postorder_list)))

    def find_entry_and_exit_nodes(self):
        #self.entry_nodes = set()
        #self.exit_nodes = set()
        assert len(self.entry_nodes) == 0
        assert len(self.exit_nodes) == 0

        for node in self.dynamic_nodes:
            if len(node.cf_predes) == 0 and len(node.df_predes) == 0:
                assert node not in self.entry_nodes
                self.entry_nodes.add(node)
            if len(node.cf_succes) == 0 and len(node.df_succes) == 0:
                assert node not in self.exit_nodes
                self.exit_nodes.add(node)
        print("[dyn_dep] total number of entry nodes: " + str(len(self.entry_nodes)))
        print("[dyn_dep] total number of exit nodes: " + str(len(self.exit_nodes)))

    def find_target_nodes(self, insn):
        self.target_nodes = []
        #if len(self.target_nodes) > 0:
        #    return
        for node in self.exit_nodes:
            if node.static_node.insn == insn:
                self.target_nodes.append(node)
        print("[dyn_dep] total number of target nodes: " + str(len(self.target_nodes)))

    def sanity_check(self):
        for n in self.dynamic_nodes:
            for p in n.cf_predes:
                assert p.static_node.id != n.static_node.id
            for s in n.cf_succes:
                assert s.static_node.id != n.static_node.id

        bad_count = 0
        for node in self.dynamic_nodes:
            for p in node.cf_predes:
                if node not in p.cf_succes:
                    bad_count += 1
                    print("************ Type 1 ******************")
                    print("**************************************")
                    print(node)
                    print(p)
                # assert node in p.cf_succes, str(node) + str(p)
            for p in node.df_predes:
                if node not in p.df_succes:
                    bad_count += 1
                    print("************ Type 2 ******************")
                    print("**************************************")
                    print(node)
                    print(p)
                # assert node in p.df_succes, str(node) + str(p)
            for s in node.cf_succes:
                if node not in s.cf_predes:
                    bad_count += 1
                    print("************ Type 3  *****************")
                    print("**************************************")
                    print(node)
                    print(s)
                # assert node in node.cf_predes, str(node) + str(s)
            for s in node.df_succes:
                if node not in s.df_predes:
                    bad_count += 1
                    print("************ Type 4  *****************")
                    print("**************************************")
                    print(node)
                    print(s)
                #assert node in node.df_predes, str(node) + str(s)
        print("[dyn_dep]Total inconsistent node count: " + str(bad_count))

    def build_dynamic_graph(self, byte_seq, code_to_insn, insns_with_regs, insn_to_static_node, insn_of_cf_nodes, insn_of_df_nodes,
                           insn_of_local_df_nodes, insn_of_remote_df_nodes, insn_to_reg_count):

        print("[TIME]Build Dynamic Graph Start Time: ", time.asctime(time.localtime(time.time())))

        # reverse the executetable, and remove insns beyond the start insn
        self.insn_to_static_node = dict(insn_to_static_node)

        """
        target_str = str(hex(self.start_insn)) + ": " + str(hex(self.start_insn)) + '\n'
        if target_str in executable:
            index = executable.index(target_str)
            executable = executable[index:]
        else:
            print("There is no target instruction detected during Execution " + str(self.number))
            return
        """
        print(insn_to_reg_count)
        print(insns_with_regs)
        print(code_to_insn)
        insn_id = 2

        addr_to_df_succe_node = {}
        cf_prede_insn_to_succe_node = {}
        local_df_prede_insn_to_succe_node = {}
        remote_df_prede_insn_to_succe_node = {}

        # traverse
        prev_insn = None
        pending_reg_count = 0
        pending_regs = None #TODO, actually can have at most one pending reg????

        index = 0
        length = len(byte_seq)
        ii = 0
        print("START: " + str(self.start_insn))
        while index < length:
            code = int.from_bytes(byte_seq[index:index + 2], byteorder='little')
            #print("Code: " + str(code))
            insn = code_to_insn[code]
            #print("Addr " + str(insn) + " " + hex(insn))
            index += 2

            ok = False
            if insn == self.start_insn:
                ok = True
            elif insn in cf_prede_insn_to_succe_node \
                    or insn in local_df_prede_insn_to_succe_node \
                    or insn in remote_df_prede_insn_to_succe_node: #TODO, could optiimze
                ok = True

            if ok is False:
                if insn in insns_with_regs:
                    index += 8
                continue

            if insn in insns_with_regs:
                reg_value = int.from_bytes(byte_seq[index:index+8], byteorder='little')
                #print("Reg " + hex(reg_value))
                index += 8
            else:
                reg_value = None
            #assert (byte_seq[index] == 58)
            #index -= 1

            if insn in insn_to_reg_count:
                #print(insn_line)
                #print("Insn has more than one reg: " + hex(insn))
                if pending_reg_count == 0:
                    pending_reg_count = insn_to_reg_count[insn]
                    pending_regs = []
                    #print(" first encountering the insn")
                if len(pending_regs) + 1 < pending_reg_count:
                    pending_regs.append(reg_value)
                    #print(" not all regs of the insn are accounted for")
                    continue
                #print(" all regs of the insn are accounted for " + str(pending_regs))
                pending_reg_count = 0
            else:
                pending_regs = None

            static_node = self.insn_to_static_node[insn]
            if insn in remote_df_prede_insn_to_succe_node:

                mem_store_addr = self.calculate_mem_addr(reg_value, static_node.mem_store,
                                                         None if pending_regs is None else pending_regs[0])
                #print("[build] Store " + hex(insn) + " to " + hex(mem_store_addr))
                if (insn != self.start_insn) and (mem_store_addr not in addr_to_df_succe_node):
                    continue

            if insn not in self.insn_to_id:
                self.insn_to_id[insn] = insn_id
                insn_id += 1

            dynamic_node = DynamicNode(self.insn_to_id[insn], static_node)
            if insn not in self.insn_to_dyn_nodes:
                self.insn_to_dyn_nodes[insn] = []
            self.insn_to_dyn_nodes[insn].append(dynamic_node)

            if DEBUG:
                print("[dyn_dep] created Dynamic Node id: " + str(dynamic_node.id) \
                  + " Static Node id: " + str(dynamic_node.static_node.id) \
                  + " insn: " + str(dynamic_node.static_node.hex_insn) \
                  + " lines: " + str(dynamic_node.static_node.bb.lines))
            self.dynamic_nodes.append(dynamic_node)
            """
            if insn not in self.node_frequencies:
                self.node_frequencies[insn] = 0
            self.node_frequencies[insn] = self.node_frequencies[insn] + 1
            """
            if insn in cf_prede_insn_to_succe_node:
                to_remove = set([])
                for succe in cf_prede_insn_to_succe_node[insn]:
                    assert succe.id != dynamic_node.id
                    succe.cf_predes.append(dynamic_node)
                    dynamic_node.cf_succes.append(succe)
                    assert succe.static_node.id != dynamic_node.static_node.id
                    assert succe.static_node.insn != dynamic_node.static_node.insn
                    # Only save the closest pred
                    # TODO, what if actually have 2 predecessors

                    for cf_pred in succe.static_node.cf_predes:
                        ni = cf_pred.insn
                        #assert cf_pred.hex_insn == hex(cf_pred.insn)
                        # if ni in cf_prede_insn_to_succe_node and succe in cf_prede_insn_to_succe_node[ni]:
                        #    cf_prede_insn_to_succe_node[ni].remove(succe)
                        to_remove.add(ni)
                if insn in cf_prede_insn_to_succe_node:
                    assert insn in to_remove
                for ni in to_remove:
                    if ni in cf_prede_insn_to_succe_node:
                        del cf_prede_insn_to_succe_node[ni]
                # del cf_prede_insn_to_succe_node[insn]

            if insn in local_df_prede_insn_to_succe_node:
                to_remove = set()
                for succe in local_df_prede_insn_to_succe_node[insn]:
                    assert succe.id != dynamic_node.id
                    succe.df_predes.append(dynamic_node)
                    dynamic_node.df_succes.append(succe)

                    # Only save the closest pred
                    # TODO, what if actually have 2 predecessors
                    for df_pred in succe.static_node.df_predes:
                        ni = df_pred.insn
                        to_remove.add(ni)
                        # if ni in df_prede_insn_to_succe_node and succe in df_prede_insn_to_succe_node[ni]:
                        #    df_prede_insn_to_succe_node[ni].remove(succe)

                for ni in to_remove:
                    if ni in local_df_prede_insn_to_succe_node:
                        del local_df_prede_insn_to_succe_node[ni]

            if insn in remote_df_prede_insn_to_succe_node:
                dynamic_node.mem_store_addr = mem_store_addr
                assert mem_store_addr is not None, str(insn_line) + "\n" + str(dynamic_node)
                # assert mem_store_addr in addr_to_df_succe_node
                if mem_store_addr in addr_to_df_succe_node:
                    for succe in addr_to_df_succe_node[mem_store_addr]:
                        succe.df_predes.append(dynamic_node)
                        dynamic_node.df_succes.append(succe)
                    del addr_to_df_succe_node[mem_store_addr]
                    # print("[build] Store " + hex(insn) + " to " + hex(mem_store_addr) + " removing from pending nodes")

            loads_memory = True if static_node.mem_load is not None else False
            if static_node.df_predes or (loads_memory and static_node.mem_load.read_same_as_write):  # and insn not in insn_of_df_nodes:
                for prede in static_node.df_predes:
                    node_insn = prede.insn
                    if node_insn not in insn_of_df_nodes and node_insn not in insn_of_cf_nodes:  # Slice is not always complete
                        continue
                    # When we encounter a dataflow predecessor later,
                    # know which successors to connect to
                    if loads_memory is False:
                        if node_insn not in local_df_prede_insn_to_succe_node:
                            local_df_prede_insn_to_succe_node[node_insn] = {dynamic_node}
                        else:
                            local_df_prede_insn_to_succe_node[node_insn].add(dynamic_node)
                    else:
                        if node_insn not in remote_df_prede_insn_to_succe_node:
                            remote_df_prede_insn_to_succe_node[node_insn] = {dynamic_node}
                        else:
                            remote_df_prede_insn_to_succe_node[node_insn].add(dynamic_node)

                if loads_memory is True:
                    #reg_value = result[1].rstrip('\n')
                    mem_load_addr = self.calculate_mem_addr(reg_value, static_node.mem_load,
                                                            None if pending_regs is None else pending_regs[0])
                    dynamic_node.mem_load_addr = mem_load_addr
                    # TODO, do all addresses make sense?
                    if mem_load_addr not in addr_to_df_succe_node:
                        addr_to_df_succe_node[mem_load_addr] = []
                    addr_to_df_succe_node[mem_load_addr].append(dynamic_node)
                    #print("[build] Load " + hex(insn) + " to " + hex(mem_load_addr) + " adding to pending nodes")

            if static_node.cf_predes:  # and insn not in insn_of_df_nodes:
                for prede in static_node.cf_predes:
                    node_insn = prede.insn
                    if node_insn not in insn_of_df_nodes and node_insn not in insn_of_cf_nodes:  # Slice is not always complete
                        continue
                        # When we encounter a control predecessor later,
                        # know which successors to connect to
                    if node_insn not in cf_prede_insn_to_succe_node:
                        cf_prede_insn_to_succe_node[node_insn] = {dynamic_node}
                    else:
                        cf_prede_insn_to_succe_node[node_insn].add(dynamic_node)
            if DEBUG:
                print("[dyn_dep] created Dynamic Node id: " + str(dynamic_node.id) \
                  + " static cf predes: " + str([p.id for p in dynamic_node.static_node.cf_predes]) \
                  + " static cf succes: " + str([s.id for s in dynamic_node.static_node.cf_succes]))
                print("[dyn_dep] created Dynamic Node id: " + str(dynamic_node.id) \
                  + " dynamic cf predes: " + str([p.static_node.id for p in dynamic_node.cf_predes]) \
                  + " dynamic cf succes: " + str([s.static_node.id for s in dynamic_node.cf_succes]))
        self.report_result()

    def report_result(self):
        """
        print("[Report] the top 5 nodes that appeared the most number of times: ")
        top_five_insn = sorted(self.node_frequencies.items(), key=lambda d: d[1], reverse=True)[:5]
        i = 1
        for item in top_five_insn:
            insn = item[0]
            times = item[1]
            node = self.insn_to_static_node[insn]
            string = "  No." + str(i) + ":\n"
            string += "     static_node id: " + str(node.id) + "\n"
            string += "     frequence: " + str(times) + "\n"
            string += "     insn addr: " + insn + "\n"
            string += "     src line: " + str(node.bb.lines) + "\n\n"
            i = i + 1

            print(string)
        """
        print("[Report]There are a total of " + str(len(self.dynamic_nodes)) + " nodes.")

    def calculate_mem_addr(self, reg_value, expr, off_reg_value=None):
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
        #if off_reg_value is not None:
        #    print("Calculating " + reg_value + " " + off_reg_value)

        if expr.reg is not None and expr.reg != '':
            addr = reg_value #int(reg_value, 16)
        else:
            addr = 0

        shift = expr.shift
        assert(not isinstance(shift, str))
        if shift != 0:
            addr = addr * shift

        off = expr.off
        assert(not isinstance(off, str))

        if off_reg_value is None or expr.off_reg is None or expr.off_reg == '':
            addr = addr + off
        else:
            if expr.off_reg.lower() == 'es':
                addr = addr
            else:
                off_reg_address = off_reg_value #int(off_reg_value, 16)
                addr = addr + off * off_reg_address
        #if off_reg_value is not None:
        #    print("[build] Calculated " + hex(addr))
        #print("Calculating " + str(reg_value) + " " + str(off_reg_value) + " " + str(expr) + " to " + hex(addr))

        return addr

    def print_graph(self):

        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
        os.makedirs(target_dir)
        string = "\n\n\n===============================================\n\n\n"
        string += "    ------------ dynamic_nodes in CFG--------------\n"

        with open(fname, 'a') as out:
            out.write(string)

        for node in self.dynamic_nodes:
            with open(fname, 'a') as out:
                out.write(str(node))


if __name__ == '__main__':
    dd = DynamicDependence(0x409daa, "sweep", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")
    #dd.prepare_to_build_dynamic_dependencies(900)
    #dg = dd.build_dyanmic_dependencies(0x441029)

    dd.prepare_to_build_dynamic_dependencies(900)
    dg = dd.build_dyanmic_dependencies(0x409418)
    # dynamic_graph.prepare_to_build_dynamic_dependencies(0x409418, "scanblock", "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")
    #dynamic_graph.prepare_to_build_dynamic_dependencies(0x409408, "scanblock", "909_ziptest_exe9")
    
    print("[Summary] Get Slice: ", str(time_record["get_slice_start"] - time_record["start_time"]))
    if "load_json" in time_record:
        print("[Summary] Json Load: ", str(time_record["load_json"] - time_record["get_slice_start"]))
    else:
        print("[Summary] Invoke Pin: ", str(time_record["invoke_pin"] - time_record["get_slice_start"]))
        print("[Summary] Build Dynamic Graph: ", str(time_record["build_finish"] - time_record["invoke_pin"]))
        print("[Summary] Dynamic Graph Json Saved: ", str(time_record["graph_traversal"] - time_record["build_finish"]))
        print("[Summary] Graph Traversal: ", str(time_record["save_dynamic_graph_as_json"] - time_record["graph_traversal"]))

    addr_not_explained = set()
    addr_explained = set()
    prede_found = 0
    prede_not_found = 0
    connected_predes = set()
    for n in dg.insn_to_dyn_nodes[4232057]:
        if len(n.df_predes) == 0:
            prede_not_found += 1
            addr_not_explained.add(hex(n.mem_load_addr))
        else:
            prede_found += 1
            addr_explained.add(hex(n.mem_load_addr))
            for p in n.df_predes:
                connected_predes.add(p.static_node)
    print(" Total count " + str(len(dg.insn_to_dyn_nodes[4232057])))
    print(" Total count with prede " + str(prede_found) + " " + str(len(addr_explained)))
    print(" Total count with no prede " + str(prede_not_found) + " " + str(len(addr_not_explained)))
    for addr in addr_explained:
        print("FOUND: " + addr)
    for addr in addr_not_explained:
        print("MISSING: " + addr)


    print("==============================")
    sn = StaticDepGraph.func_to_graph['scanblock'].insn_to_node[4232057]
    predes = []
    for p in sn.df_predes:
        assert p.explained
        assert p.mem_store is not None
        print(p.mem_store)
        predes.append(p.toJSON())
        p.print_node(" all predes: ")
    print("==============================")
    for p in connected_predes:
        print(p.mem_store)
        p.print_node(" connected:  ")
    print("==============================")
    for p in sn.df_predes:
        if p in connected_predes:
            continue
        print(p.mem_store)
        p.print_node(" not found:  ")
    with open(os.path.join(curr_dir, 'predes'), 'w') as f:
        json.dump(predes, f, indent=4, ensure_ascii=False)