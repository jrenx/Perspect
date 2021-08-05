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

reg_size_map = dict(al=1,   ah=1, ax=2,   eax=4,  rax=8,
					bl=1,   bh=1, bx=2,   ebx=4,  rbx=8,
					cl=1,   ch=1, cx=2,   ecx=4,  rcx=8,
					dl=1,   dh=1, dx=2,   edx=4,  rdx=8,
					sil=1,        si=2,   esi=4,  rsi=8,
					dil=1,        di=2,   edi=4,  rdi=8,
					bpl=1,        bp=2,   ebp=4,  rbp=8,
					spl=1,        sp=2,   esp=4,  rsp=8,
					r8b=1,        r8w=2,  r8d=4,  r8=8,
					r9b=1,        r9w=2,  r9d=4,  r9=8,
					r10b=1,       r10w=2, r10d=4, r10=8,
					r11b=1,       r11w=2, r11d=4, r11=8,
					r12b=1,       r12w=2, r12d=4, r12=8,
					r13b=1,       r13w=2, r13d=4, r13=8,
					r14b=1,       r14w=2, r14d=4, r14=8,
					r15b=1,       r15w=2, r15d=4, r15=8)

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
        self.mem_load_addr = None
        self.mem_store_addr = None
        self.bit_ops = None
        self.remaining_load_bit_mask = None
        self.load_bit_mask = None
        self.store_bit_mask = None
        self.output_set = set() #TODO, persist these two as well?
        self.output_set1 = set()
        self.input_sets = {}
        self.weight = -1
        self.weight_origins = set()
        self.weight_paths = set()
        self.is_valid_weight = False
        self.is_aggregate_weight = False

    def __str__(self):
        s = "===============================================\n"
        # s += "   Instance id : " + str(self.instance_id) + "\n"
        s += "   Dynamic Node id: " + str(self.id) + "\n"
        s += "   Instruction id : " + str(self.insn_id) + "\n"
        s += "    -------------------------------------\n"
        s += "    ------------Static Node--------------\n"
        s += "      " + self.static_node.hex_insn + "\n"
        s += "      " + self.static_node.function + "\n"
        #s += str(self.static_node) + "\n"
        #s += "    -------------------------------------\n"
        #s += "    -------------------------------------\n"
        s += "    dynamic control flow predecessors: ["
        for prede in self.cf_predes:
            s += '[' + str(prede.id) + "," + str(prede.static_node.hex_insn) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic control flow successors: ["
        for succe in self.cf_succes:
            s += '[' + str(succe.id) + "," + str(succe.static_node.hex_insn) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic data flow predecessors: ["
        for prede in self.df_predes:
            s += '[' + str(prede.id) + "," + str(prede.static_node.hex_insn) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    dynamic data flow successors: ["
        for succe in self.df_succes:
            s += '[' + str(succe.id) + "," + str(succe.static_node.hex_insn) + ']'
        s = s.strip(",")
        s += "] \n"
        s += "    mem_load_addr: " + (hex(self.mem_load_addr) if self.mem_load_addr is not None else str(None)) + "\n"
        s += "    mem_store_addr: " + (hex(self.mem_store_addr) if self.mem_store_addr is not None else str(None)) + "\n"
        s += "    load_bit_mask: " + ("{:64b}".format(self.load_bit_mask) if self.load_bit_mask is not None else str(None)) + "\n"
        s += "    remaining_load_bit_mask: " + ("{:64b}".format(self.remaining_load_bit_mask) if self.remaining_load_bit_mask is not None else str(None)) + "\n"
        s += "    store_bit_mask: " + ("{:64b}".format(self.store_bit_mask) if self.store_bit_mask is not None else str(None)) + "\n"
        s += "    weight: " + str(self.weight) + "\n"
        s += "    is valid weight: " + str(self.is_valid_weight) + "\n"
        s += "    is aggregate weight: " + str(self.is_aggregate_weight) + "\n"
        return s

    def toJSON(self):
        data = {}
        data["id"] = self.id
        data["insn_id"] = self.insn_id
        data["hex_insn"] = self.static_node.hex_insn #for debugging
        data["func"] = self.static_node.function #for debugging
        data["static_node"] = self.static_node.id
        data["weight"] = self.weight
        data["is_valid_weight"] = self.is_valid_weight
        data["is_aggregate_weight"] = self.is_aggregate_weight

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
        data["mem_load_addr"] = self.mem_load_addr
        data["mem_load_addr_hex"] = None if self.mem_load_addr is None else hex(self.mem_load_addr) #for debugging
        data["mem_store_addr"] = self.mem_store_addr
        data["mem_store_addr_hex"] = None if self.mem_store_addr is None else hex(self.mem_store_addr) #for debugging
        if self.bit_ops is not None:
            data["bit_ops"] = self.bit_ops
            bit_ops_binary = {}
            for insn in self.bit_ops:
                bit_ops_binary[hex(insn)] = "{:64b}".format(self.bit_ops[insn])
            data["bit_ops_binary"] = bit_ops_binary
        if self.load_bit_mask is not None:
            data["load_bit_mask"] = self.load_bit_mask
            data["load_bit_mask_binary"] = "{:64b}".format(self.load_bit_mask)
            data["remaining_load_bit_mask"] = self.remaining_load_bit_mask
            data["remaining_load_bit_mask_binary"] = "{:64b}".format(self.remaining_load_bit_mask)
        if self.store_bit_mask is not None:
            data["store_bit_mask"] = self.store_bit_mask
            data["store_bit_mask_binary"] = "{:64b}".format(self.store_bit_mask)
        data["weight_origins"] = list(self.weight_origins)
        data["weight_paths"] = list(self.weight_paths)
        return data

    @staticmethod
    def fromJSON(data):
        id = data["id"]
        insn_id = data["insn_id"]
        static_node = data["static_node"]
        dn = DynamicNode(insn_id, static_node, id)

        dn.mem_load_addr = data["mem_load_addr"]
        dn.mem_store_addr = data["mem_store_addr"]

        dn.cf_predes = data['cf_predes']
        dn.cf_succes = data['cf_succes']
        dn.df_predes = data['df_predes']
        dn.df_succes = data['df_succes']
        dn.cf_predes_insn_id = data["cf_predes_insn_id"]
        if "bit_ops" in data:
            dn.bit_ops = {}
            for key in data["bit_ops"]:
                dn.bit_ops[int(key)] = data["bit_ops"][key]
        if "load_bit_mask" in data:
            dn.load_bit_mask = data["load_bit_mask"]
        if "remaining_load_bit_mask" in data:
            dn.remaining_load_bit_mask = data["remaining_load_bit_mask"]
        if "store_bit_mask" in data:
            dn.store_bit_mask = data["store_bit_mask"]
        dn.weight = data["weight"]
        dn.weight_origins = set(data["weight_origins"])
        dn.weight_paths = set(data["weight_paths"])
        dn.is_valid_weight = data["is_valid_weight"]
        dn.is_aggregate_weight = data["is_aggregate_weight"]
        return dn


    # Just trying to figure out which bits are being read
    def calculate_load_bit_mask(self):
        #TODO, technically even if an instruction does not use a register and uses only a constant
        # still wanna print the instruction so that we know it executed...
        # this is not currently implemented
        assert self.static_node.mem_load is not None
        if self.static_node.mem_load.read_same_as_write is True:
            self.load_bit_mask = 0
        else:
            bit_opses = self.static_node.mem_load.bit_operations
            for bit_ops in bit_opses:
                all_ops_encountered = True
                # Sometimes, not all sets of bit operations are guaranteed to be executed
                # but at least one set should have been encountered
                for bit_op in bit_ops:
                    if bit_op.operand not in reg_map:
                        self.bit_ops[bit_op.insn] = int(bit_op.operand, 16)
                    if bit_op.insn not in self.bit_ops:
                        all_ops_encountered = False
                        break
                if all_ops_encountered is False:
                    continue

                load_bit_mask = None
                for bit_op in bit_ops:
                    if bit_op.operation == "and":
                        if load_bit_mask is None:
                            load_bit_mask = self.bit_ops[bit_op.insn]
                            continue
                    elif bit_op.operation == "shr":
                        assert load_bit_mask is not None
                        # do the reverse shift
                        load_bit_mask = load_bit_mask << self.bit_ops[bit_op.insn]
                        continue
                    elif bit_op.operation == "shl":
                        assert load_bit_mask is not None
                        # do the reverse shift
                        load_bit_mask = load_bit_mask >> self.bit_ops[bit_op.insn]
                        continue
                    print("Unhandled bit op: " + str(bit_op.operation))
                    print(self.static_node)
                    raise Exception
                if self.load_bit_mask is None:
                    self.load_bit_mask = load_bit_mask
                else:
                    self.load_bit_mask = self.load_bit_mask | load_bit_mask
        self.remaining_load_bit_mask = self.load_bit_mask
        print("load mask calculated for " + self.static_node.hex_insn + " to be " + "{:64b}".format(self.load_bit_mask))

    # calculates the bits that are being modified
    # for an AND, a bit could  be modified when we and it with a 0,
    # so we not the AND operand to obtain possible modification bits
    # for an OR, a bit could  be modified when we and it with a 1
    def calculate_store_bit_mask(self):
        assert self.static_node.mem_store is not None
        bit_opses = self.static_node.mem_store.bit_operations
        for bit_ops in bit_opses:
            for bit_op in bit_ops:
                if bit_op.operand not in reg_map:
                    self.bit_ops[bit_op.insn] = int(bit_op.operand, 16)
                if bit_op.insn not in self.bit_ops:
                    print("[warn] not all bit ops are encountered yet for " + self.static_node.hex_insn)
                    return
                if bit_op.operation == "and":
                    if self.store_bit_mask is None:
                        self.store_bit_mask = (~self.bit_ops[bit_op.insn])&0xffffffffffffffff
                    else:
                        self.store_bit_mask = self.store_bit_mask | ((~self.bit_ops[bit_op.insn])&0xffffffffffffffff)
                    continue
                elif bit_op.operation == "or":
                    if self.store_bit_mask is None:
                        self.store_bit_mask = self.bit_ops[bit_op.insn]
                    else:
                        self.store_bit_mask = self.store_bit_mask | (self.bit_ops[bit_op.insn])
                    continue
                print("Unhandled bit op: " + str(bit_op.operation))
                raise Exception
        print("store mask calculated for " + self.static_node.hex_insn + " to be " + "{:64b}".format(self.store_bit_mask))


class DynamicDependence:
    def __init__(self, starting_events, prog, arg, path):
        self.prog = prog
        self.arg = arg
        self.path = path
        self.key = None
        self.all_static_cf_nodes = []
        self.all_static_df_nodes = []
        self.insn_of_cf_nodes = []
        self.insn_of_df_nodes = []
        self.dynamic_nodes = OrderedDict()
        self.insn_to_static_node = {}
        self.insn_of_local_df_nodes = []
        self.insn_of_remote_df_nodes = []
        self.insn_to_reg_count = {}
        self.insn_to_reg_count2 = {}
        self.code_to_insn = {}
        self.insns_with_regs = set()
        self.max_code_with_static_node = -1
        self.load_insn_to_bit_ops = {} #bit op follows the load
        self.bit_op_to_store_insns = {} #bit op precedes store
        self.store_insn_to_bit_ops = {}
        self.trace_path = None

        # phase out this eventually and just use one unified list to represent every starting event
        self.starting_insns = set()
        for p in starting_events:
            self.starting_insns.add(p[1]) #FIXME: change start to starting?
        self.starting_events = list(starting_events)
        print(self.starting_events)
        self.init_graph = None

    def get_dynamic_trace(self, prog, arg, path, trace_name=""):
        trace_name = trace_name + 'instruction_trace.out'
        trace_path = os.path.join(curr_dir, 'pin', trace_name)
        
        instructions = []
        unique_insns = set()
        i = 0

        insn_to_bit_operand = {}
        for node in self.all_static_df_nodes:
            if node.mem_store != None:
                if node.mem_store.bit_operations is not None:
                    if node.mem_store.is_bit_var is not True:
                        print(node.print_node("[WARN] Should be a bit var! "))
                    for bos in node.mem_store.bit_operations:
                        for bo in bos:
                            if bo.operand.lower() not in reg_map:
                                continue

                            if bo.insn in insn_to_bit_operand:
                                assert(insn_to_bit_operand[bo.insn] == bo.operand)
                            else:
                                insn_to_bit_operand[bo.insn] = bo.operand.lower()

                            if bo.insn not in self.bit_op_to_store_insns:
                                self.bit_op_to_store_insns[bo.insn] = []
                            if node.insn not in self.bit_op_to_store_insns[bo.insn]:
                                self.bit_op_to_store_insns[bo.insn].append(node.insn)

                            if node.insn not in self.store_insn_to_bit_ops:
                                self.store_insn_to_bit_ops[node.insn] = []
                            if bo.insn not in self.store_insn_to_bit_ops[node.insn]:
                                self.store_insn_to_bit_ops[node.insn].append(bo.insn)

            if node.mem_load != None:
                if node.mem_load.bit_operations is not None:
                    if node.mem_load.is_bit_var is not True:
                        print(node.print_node("[WARN] Should be a bit var! "))
                    for bos in node.mem_load.bit_operations:
                        for bo in bos:
                            if bo.operand.lower() not in reg_map:
                                continue

                            if bo.insn in insn_to_bit_operand:
                                #if already included by load, do not include in store
                                # because this is likely the case where
                                # we load and store from the same instruction while doing a bit op
                                assert(insn_to_bit_operand[bo.insn] == bo.operand)
                                continue
                            insn_to_bit_operand[bo.insn] = bo.operand.lower()

                            if node.insn not in self.load_insn_to_bit_ops:
                                self.load_insn_to_bit_ops[node.insn] = []
                            if bo.insn not in self.load_insn_to_bit_ops[node.insn]:
                                self.load_insn_to_bit_ops[node.insn].append(bo.insn)

        for start_event in self.starting_events:
            reg = start_event[0]
            insn = start_event[1]
            assert insn not in unique_insns
            unique_insns.add(insn)

            i += 1
            self.code_to_insn[i] = insn
            instructions.append([hex(insn), reg, i])
            self.insns_with_regs.add(insn)
            self.insn_to_reg_count[insn] = 1

        #go through every dataflow node to find the bit vars first

        for node in self.all_static_df_nodes:
            #print("DF" + node.hex_insn)
            if node.insn in unique_insns: #TODO should not have overlaps ..
                continue
            unique_insns.add(node.insn)

            i += 1
            self.code_to_insn[i] = node.insn

            # trace local
            has_reg = False
            load_reg_count = 0
            store_reg_count = 0

            #order matters here,
            # 1. mem_load needs to be logged before mem_store regs
            # 2. the bit operand must be logged first and read last,
            # in case the same instruction has both store/read and bit_operation
            if node.insn in insn_to_bit_operand:
                instructions.append([node.hex_insn, insn_to_bit_operand[node.insn], i])
                #has_reg = True
                del insn_to_bit_operand[node.insn]

            if node.mem_load != None:
                if node.mem_load.reg != None and node.mem_load.reg != '':
                    instructions.append([node.hex_insn, node.mem_load.reg.lower(), i])
                    load_reg_count += 1
                    has_reg = True
                if node.mem_load.off_reg != None and node.mem_load.off_reg != '':
                    instructions.append([node.hex_insn, node.mem_load.off_reg.lower(), i])
                    load_reg_count += 1
                    has_reg = True
                # bit var ops treated as load
            # trace remote
            #TODO handle this!!
            if node.mem_store != None:
                if node.mem_store.reg != None and node.mem_store.reg != '':
                    instructions.append([node.hex_insn, node.mem_store.reg.lower(), i])
                    store_reg_count += 1
                    has_reg = True
                if node.mem_store.off_reg != None and node.mem_store.off_reg != '':
                    instructions.append([node.hex_insn, node.mem_store.off_reg.lower(), i])
                    store_reg_count += 1
                    has_reg = True
            if not has_reg:
                instructions.append([node.hex_insn, 'pc', i])
            reg_count = load_reg_count + store_reg_count
            if reg_count >= 1: #TODO, sort out the logic better next time
                assert has_reg
                if store_reg_count == 0 or load_reg_count == 0:
                    self.insn_to_reg_count[node.insn] = reg_count
                else:
                    self.insn_to_reg_count[node.insn] = load_reg_count
                    self.insn_to_reg_count2[node.insn] = store_reg_count
            if reg_count >= 1:
                self.insns_with_regs.add(node.insn)

        for insn in insn_to_bit_operand:
            assert insn not in unique_insns
            unique_insns.add(insn)

        for node in self.all_static_cf_nodes:
            if node.insn in unique_insns:
                continue
            unique_insns.add(node.insn)

            i += 1
            self.code_to_insn[i] = node.insn
            instructions.append([node.hex_insn, 'pc', i])

        self.max_code_with_static_node = i

        for insn in insn_to_bit_operand:
            i += 1
            self.code_to_insn[i] = insn
            reg = insn_to_bit_operand[insn]
            instructions.append([hex(insn), reg, i])
            #self.insns_with_regs.add(insn)
            #self.insn_to_reg_count[insn] = 1

        if os.path.isfile(trace_path):
            return trace_path

        # invoke PIN. get output of a sequence of insn
        trace = InsRegTrace(path + prog + ' ' + path + arg,
                            pin='~/pin-3.11/pin', out=trace_name)
        print("[dyn_dep] Total number of instructions watched: " + str(len(instructions)))
        print(instructions)
        trace.run_function_trace(instructions)
        return trace_path

    def build_static_dependencies(self, starting_events, prog, sa_steps=10000):

        # Get slice #TODO, add a cache here
        used_cached_result = StaticDepGraph.build_dependencies(starting_events, prog, limit=sa_steps)

        for graph in StaticDepGraph.func_to_graph.values():

            for node in graph.none_df_starting_nodes:
                self.insn_to_static_node[node.insn] = node

            for node in graph.nodes_in_cf_slice:
                self.all_static_cf_nodes.append(node)
                self.insn_to_static_node[node.insn] = node
                self.insn_of_cf_nodes.append(node.insn)
                #print(node)

            for node in graph.nodes_in_df_slice:
                # trace local
                #if node.mem_load != None or node.mem_store != None:
                #TODO could just be loading a reg
                self.all_static_df_nodes.append(node)
                self.insn_to_static_node[node.insn] = node
                self.insn_of_df_nodes.append(node.insn)
                if node.mem_load != None:
                    self.insn_of_local_df_nodes.append(node.insn)
                elif node.mem_store != None:
                    self.insn_of_remote_df_nodes.append(node.insn)

                #print(node)
        return used_cached_result

    # TODO, refactor into a more user friendly interface?
    def build_dyanmic_dependencies(self, insn=None):
        file_name = 'dynamic_graph_result_' + self.key + "_" + (hex(insn) if insn is not None else str(insn))
        result_file = os.path.join(curr_dir, 'cache', self.prog, file_name)
        time_record["start"] = time.time()
        if os.path.isfile(result_file):
            print("Reading from file:" + result_file)
            with open(result_file, 'r') as f:
                in_result = json.load(f)
                static_id_to_node = {}
                for func in StaticDepGraph.func_to_graph:
                    for sn in StaticDepGraph.func_to_graph[func].id_to_node.values():
                        static_id_to_node[sn.id] = sn
                dynamic_graph = DynamicGraph.fromJSON(in_result, static_id_to_node)
                time_record["load_json"] = time.time()
                print("[TIME] Loading graph from json: ", str(time_record["load_json"] - time_record["start"]), flush=True)
        else:
            preprocess_data = {
                "trace_file": self.trace_path,
                "static_graph_file": StaticDepGraph.result_file,
                "starting_insns" : list(self.starting_insns) if insn is None else [insn],
                "code_to_insn" : self.code_to_insn,
                "insns_with_regs" : list(self.insns_with_regs),
                "insn_of_cf_nodes" : self.insn_of_cf_nodes,
                "insn_of_df_nodes" : self.insn_of_df_nodes,
                "insn_of_local_df_nodes" : self.insn_of_local_df_nodes,
                "insn_of_remote_df_nodes" : self.insn_of_remote_df_nodes,
                "insn_to_reg_count" : self.insn_to_reg_count,
                "insn_to_reg_count2": self.insn_to_reg_count2,
                "load_insn_to_bit_ops": self.load_insn_to_bit_ops,
                "bit_op_to_store_insns": self.bit_op_to_store_insns,
                "max_code_with_static_node": self.max_code_with_static_node
            }

            preprocess_data_file = os.path.join(curr_dir, 'preprocess_data')
            with open(preprocess_data_file, 'w') as f:
                json.dump(preprocess_data, f, indent=4, ensure_ascii=False)
            preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'preprocess')
            pp_process = subprocess.Popen([preprocessor_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = pp_process.communicate()
            print(stdout)
            print(stderr)

            time_record["preparse"] = time.time()
            print("[TIME] Preparsing trace took: ", str(time_record["preparse"] - time_record["start"]), flush=True)

            with open(self.trace_path + ".parsed", 'rb') as f:
                byte_seq = f.read() #more than twice faster than readlines!

            time_record["read_preparse"] = time.time()
            print("[TIME] Loading preparsed trace took: ", str(time_record["read_preparse"] - time_record["preparse"]), flush=True)

            dynamic_graph = DynamicGraph(self.starting_events)
            dynamic_graph.build_dynamic_graph(byte_seq, self.starting_insns if insn is None else set([insn]),
                                              self.code_to_insn, self.insns_with_regs, self.insn_to_static_node,
                                              set(self.insn_of_cf_nodes), set(self.insn_of_df_nodes),
                                              set(self.insn_of_local_df_nodes), set(self.insn_of_remote_df_nodes),
                                              self.insn_to_reg_count, self.insn_to_reg_count2,
                                              self.load_insn_to_bit_ops, self.store_insn_to_bit_ops)
            time_record["build_finish"] = time.time()
            print("[TIME] Building dynamic graph took: ", str(time_record["build_finish"] - time_record["read_preparse"]), flush=True)

            dynamic_graph.trim_dynamic_graph(self.starting_insns if insn is None else set([insn]))
            time_record["trim_finish"] = time.time()
            print("[TIME] Trimming dynamic graph took: ", str(time_record["trim_finish"] - time_record["build_finish"]), flush=True)

            dynamic_graph.report_result()
            time_record["report_result"] = time.time()
            print("[TIME] Reporting result took: ", str(time_record["report_result"] - time_record["trim_finish"]), flush=True)

            dynamic_graph.sanity_check()
            time_record["sanity_check"] = time.time()
            print("[TIME] Sanity check took: ", str(time_record["sanity_check"] - time_record["report_result"]), flush=True)

            dynamic_graph.find_entry_and_exit_nodes()
            dynamic_graph.find_target_nodes(self.starting_insns if insn is None else set([insn]))
            time_record["find_target_nodes"] = time.time()
            print("[TIME] Locating entry&exit&target nodes took: ",
                  str(time_record["find_target_nodes"] - time_record["sanity_check"]), flush=True)

            dynamic_graph.build_postorder_list()
            time_record["postorder"] = time.time()
            print("[TIME] Postorder traversal took: ",
                  str(time_record["postorder"] - time_record["find_target_nodes"]), flush=True)

            dynamic_graph.build_reverse_postorder_list()
            time_record["reverse_postorder"] = time.time()
            print("[TIME] Reverse postorder traversal took: ",
                  str(time_record["reverse_postorder"] - time_record["postorder"]), flush=True)

            if self.init_graph is None:
                dynamic_graph.propogate_initial_graph_weight()
            else:
                dynamic_graph.propogate_weight(self.init_graph)

            time_record["propogate_weight"] = time.time()
            print("[TIME] Propogating weight took: ",
                  str(time_record["propogate_weight"] - time_record["reverse_postorder"]), flush=True)

            with open(result_file, 'w') as f:
                json.dump(dynamic_graph.toJSON(), f, indent=4, ensure_ascii=False)

            time_record["save_dynamic_graph_as_json"] = time.time()
            print("[TIME] Saving graph in json took: ",
                  str(time_record["save_dynamic_graph_as_json"] - time_record["propogate_weight"]), flush=True)


        if self.init_graph is None:
            #pass
            dynamic_graph.verify_initail_graph_weight()
            #dynamic_graph.propogate_initial_graph_weight()
        else:
            dynamic_graph.propogate_weight(self.init_graph)
            dynamic_graph.verify_weight(self.init_graph)
            with open(result_file, 'w') as f:
                json.dump(dynamic_graph.toJSON(), f, indent=4, ensure_ascii=False)

        print("[dyn_dep] total number of dynamic nodes: " + str(len(dynamic_graph.dynamic_nodes)))
        return dynamic_graph

    def prepare_to_build_dynamic_dependencies(self, sa_steps=10000):
        # Get static dep, then invoke pin to get execution results, and build CFG
        #FIXME: convert start instruction to hex
        key = ""
        for i in range(len(self.starting_events)):
            event = self.starting_events[i]
            reg = event[0]
            insn = event[1]
            key += reg + "_" + hex(insn)
            if i + 1 < len(self.starting_events):
                key += "_"
        self.key = key

        time_record["before_static_slice"] = time.time()
        used_cached_result = \
            self.build_static_dependencies(self.starting_events, self.prog, sa_steps)
        time_record["static_slice"] = time.time()
        print("[TIME] Getting static slice: ",
              str(time_record["static_slice"] - time_record["before_static_slice"]), flush=True)

        self.trace_path = self.get_dynamic_trace(self.prog, self.arg, self.path, self.key + "_")
        time_record["invoke_pin"] = time.time()
        print("[TIME] Invoking PIN took: ",
              str(time_record["invoke_pin"] - time_record["static_slice"]), flush=True)
        self.init_graph = self.build_dyanmic_dependencies()

class DynamicGraph:
    # TODO: restructure DynamicGraph
    def __init__(self, starting_events):
        self.starting_events = starting_events
        self.starting_insns = set()
        self.starting_insn_to_reg = {}
        for event in starting_events:
            curr_insn = event[1]
            self.starting_insns.add(curr_insn)
            curr_reg = event[0]
            if curr_reg is None:
                continue
            curr_insn = event[1]
            assert(curr_insn not in self.starting_insn_to_reg)
            self.starting_insn_to_reg[curr_insn] = curr_reg

        self.insn_to_id = {}
        self.dynamic_nodes = OrderedDict()
        self.target_dir = os.path.join(curr_dir, 'dynamicGraph')
        self.node_frequencies = {}
        self.insn_to_static_node = None
        self.postorder_list = []
        self.reverse_postorder_list = []
        self.entry_nodes = set()
        self.exit_nodes = set()
        self.target_nodes = set()
        self.insn_to_dyn_nodes = {}
        self.id_to_node = {} #TODO, obselete now
        
    def toJSON(self):
        data = {}
        data["starting_events"] = self.starting_events
        data["insn_to_id"] = self.insn_to_id

        data["dynamic_nodes"] = []
        for n in self.dynamic_nodes.values():
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
        dg = DynamicGraph(data["starting_events"])
        dg.insn_to_id = data["insn_to_id"]

        id_to_node = {}
        for n in data["dynamic_nodes"]:
            dn = DynamicNode.fromJSON(n)
            dg.dynamic_nodes[dn.id] = dn
            id_to_node[dn.id] = dn
            dn.static_node = static_id_to_node[dn.static_node]

        for dn in dg.dynamic_nodes.values():
            insn = dn.static_node.insn
            if insn not in dg.insn_to_dyn_nodes:
                dg.insn_to_dyn_nodes[insn] = set()
            dg.insn_to_dyn_nodes[insn].add(dn)
            dg.id_to_node[dn.id] = dn

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
        for node in self.dynamic_nodes.values():
            insn = node.static_node.insn
            if insn not in self.insn_to_dyn_nodes:
                self.insn_to_dyn_nodes[insn] = set()
            self.insn_to_dyn_nodes[insn].add(node)
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
        worklist_set = set()
        for n in self.entry_nodes:
            worklist.append(n)
            worklist_set.add(n)
            if DEBUG_POST_ORDER: self.print_node("Initial  ", n)

        while len(worklist) > 0:
            curr = worklist.popleft()
            worklist_set.remove(curr)
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
                        if s in worklist_set:
                            continue
                        assert s not in all_completed
                        worklist.append(s)
                        worklist_set.add(s)
                        if DEBUG_POST_ORDER: self.print_node("Queuing  ", s)
                    for s in completed.df_succes:
                        if s in node_to_pending_prede_count:
                            continue
                        if s in worklist_set:
                            continue
                        assert s not in all_completed
                        worklist.append(s)
                        worklist_set.add(s)
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
        assert len(node_to_pending_prede_count) == 0, str(len(node_to_pending_prede_count))
        assert len(prede_to_node) == 0, str(len(prede_to_node))
        print("[dyn_dep] total number of nodes in reverse postorder_list: " + str(len(self.reverse_postorder_list)))

    # a node can be visited if all its successors are visited
    def build_postorder_list(self):
        self.postorder_list = []

        succe_to_node = {}
        node_to_pending_succe_count = {}
        all_completed = set()
        visited = set()
        worklist = deque()
        worklist_set = set()
        for n in self.exit_nodes:
            worklist.append(n)
            worklist_set.add(n)
            if DEBUG_POST_ORDER: self.print_node("Initial  ", n)

        while len(worklist) > 0:
            curr = worklist.popleft()
            worklist_set.remove(curr)
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
                        if p in worklist_set:
                            continue
                        assert p not in all_completed
                        worklist.append(p)
                        worklist_set.add(p)
                        if DEBUG_POST_ORDER: self.print_node("Queuing    ", p)
                    for p in completed.df_predes:
                        if p in node_to_pending_succe_count:
                            continue
                        if p in worklist_set:
                            continue
                        assert p not in all_completed
                        worklist.append(p)
                        worklist_set.add(p)
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
        assert len(node_to_pending_succe_count) == 0, str(len(node_to_pending_succe_count))
        assert len(succe_to_node) == 0, str(len(succe_to_node))
        print("[dyn_dep] total number of nodes in postorder_list: " + str(len(self.postorder_list)))

    def find_entry_and_exit_nodes(self):
        #self.entry_nodes = set()
        #self.exit_nodes = set()
        assert len(self.entry_nodes) == 0
        assert len(self.exit_nodes) == 0

        for node in self.dynamic_nodes.values():
            if len(node.cf_predes) == 0 and len(node.df_predes) == 0:
                assert node not in self.entry_nodes
                self.entry_nodes.add(node)
            if len(node.cf_succes) == 0 and len(node.df_succes) == 0:
                assert node not in self.exit_nodes
                self.exit_nodes.add(node)
        print("[dyn_dep] total number of entry nodes: " + str(len(self.entry_nodes)))
        print("[dyn_dep] total number of exit nodes: " + str(len(self.exit_nodes)))

    def find_target_nodes(self, target_insns):
        self.target_nodes = []
        #if len(self.target_nodes) > 0:
        #    return
        for node in self.dynamic_nodes.values(): #Dont use exit node, not every target node is an exit node
            if node.static_node.insn in target_insns:
                self.target_nodes.append(node)
        print("[dyn_dep] total number of target nodes: " + str(len(self.target_nodes)))

    def sanity_check(self):
        for n in self.dynamic_nodes.values():
            if n.bit_ops is not None:
                has_bit_op = False
                if n.static_node.mem_store is not None:
                    if n.static_node.mem_store.bit_operations is not None:
                        has_bit_op = True
                if n.static_node.mem_load is not None:
                    if n.static_node.mem_load.bit_operations is not None:
                        has_bit_op = True
                assert has_bit_op is True, str(n)

        """
        for n in self.dynamic_nodes.values():
            for p in n.cf_predes:
                assert p.static_node.id != n.static_node.id
            for s in n.cf_succes:
                assert s.static_node.id != n.static_node.id

        bad_count = 0
        for node in self.dynamic_nodes.values():
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
        """

    def build_dynamic_graph(self, byte_seq, starting_insns, code_to_insn, insns_with_regs, insn_to_static_node,
                            insn_of_cf_nodes, insn_of_df_nodes, insn_of_local_df_nodes, insn_of_remote_df_nodes,
                            insn_to_reg_count, insn_to_reg_count2, load_insn_to_bit_ops, store_insn_to_bit_ops):
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

        bit_insn_to_operand = {}
        load_bit_insns = set()
        for bit_insns in load_insn_to_bit_ops.values():
            for bit_insn in bit_insns:
                load_bit_insns.add(bit_insn)

        bit_insn_to_node = {}
        store_bit_insns = set()
        for bit_insns in store_insn_to_bit_ops.values():
            for bit_insn in bit_insns:
                store_bit_insns.add(bit_insn)

        # traverse
        prev_insn = None
        pending_reg_count = 0
        pending_regs = None #TODO, actually can have at most one pending reg????

        hasPrevValues = False
        prev_pending_regs = None
        prev_reg_value = None

        index = 0
        length = len(byte_seq)
        ii = 0

        other_regs_parsed = False
        print("START: " + str(starting_insns))
        while index < length:
            code = int.from_bytes(byte_seq[index:index + 2], byteorder='little')
            #print("Code: " + str(code))
            insn = code_to_insn[code]
            #print("Addr " + str(insn) + " " + hex(insn))
            index += 2

            ok = False
            if insn in starting_insns:
                ok = True
            elif insn in cf_prede_insn_to_succe_node \
                    or insn in local_df_prede_insn_to_succe_node \
                    or insn in remote_df_prede_insn_to_succe_node: #TODO, could optiimze
                ok = True

            contains_bit_op = insn in load_bit_insns or insn in store_bit_insns

            if ok is False and contains_bit_op is False:
                index += 8 #for uid
                if insn in insns_with_regs:
                    index += 8
                if insn in bit_insn_to_node:
                    del bit_insn_to_node[bit_insn]

                if insn in load_insn_to_bit_ops:
                    for bit_insn in load_insn_to_bit_ops[insn]:
                        if bit_insn in bit_insn_to_operand:
                            del bit_insn_to_operand[bit_insn]
                continue

            uid = int.from_bytes(byte_seq[index:index + 8], byteorder='little')
            index += 8

            if insn in insns_with_regs or contains_bit_op is True:
                reg_value = int.from_bytes(byte_seq[index:index+8], byteorder='little')
                #print("Reg " + hex(reg_value))
                index += 8
            else:
                reg_value = None

            if contains_bit_op is True:
                if other_regs_parsed is True or insn not in insns_with_regs:
                    other_regs_parsed = False
                    if insn in load_bit_insns:
                        bit_insn_to_operand[insn] = reg_value
                    if insn in store_bit_insns:
                        if insn in bit_insn_to_node:
                            parent_node = bit_insn_to_node[insn]
                            if parent_node.bit_ops is None:
                                parent_node.bit_ops = {}
                            # Only save to the closest store
                            if insn not in parent_node.bit_ops:
                                parent_node.bit_ops[insn] = reg_value
                                #Re-calculate the store bit mask every time
                                parent_node.store_bit_mask = None
                                parent_node.calculate_store_bit_mask()
                                # if an instruction has both a load and a store, and a bit op,
                                # the load is considered to not really have a bitmask
                                if parent_node.static_node.mem_load is not None and \
                                        parent_node.static_node.mem_load.bit_operations is not None:
                                    assert parent_node.static_node.mem_load.read_same_as_write is True
                                    parent_node.load_bit_mask = 0
                                    parent_node.remaining_load_bit_mask = 0
                                # if we found a match for the a successor node,
                                # remove it from "addr_to_df_succe_node" which stores nodes with loads pending nodes with stores
                                # this does not guarantee that nodes with non-matching bit mask has already been added to the dataflow predecessor of a node
                                # so further trimming is needed
                                if parent_node.store_bit_mask is not None:
                                    for succe in parent_node.df_succes:
                                        if succe.load_bit_mask is None:
                                            continue
                                        if succe.mem_load_addr is None:
                                            continue
                                        assert succe.mem_load_addr == parent_node.mem_store_addr
                                        overlap = parent_node.store_bit_mask & succe.remaining_load_bit_mask
                                        if overlap != 0x0:
                                            print("[bit_var] store bit mask " + "{:64b}".format(parent_node.store_bit_mask))
                                            print("[bit_var] load bit mask before " + "{:64b}".format(succe.remaining_load_bit_mask))
                                            succe.remaining_load_bit_mask = succe.remaining_load_bit_mask&((~overlap)&0xffffffffffffffff)
                                            print("[bit_var] load bit mask after " + "{:64b}".format(succe.remaining_load_bit_mask))
                                            if succe.remaining_load_bit_mask == 0x0:
                                                if succe in addr_to_df_succe_node[succe.mem_load_addr]:
                                                    addr_to_df_succe_node[succe.mem_load_addr].remove(succe)
                                                    if len(addr_to_df_succe_node[succe.mem_load_addr]) == 0:
                                                        del addr_to_df_succe_node[succe.mem_load_addr]
                            #del bit_insn_to_node[insn]
                    continue

            if insn in bit_insn_to_node:
                del bit_insn_to_node[insn]

            #assert (byte_seq[index] == 58)
            #index -= 1
            static_node = self.insn_to_static_node[insn]

            #print(" pending " + str(pending_reg_count))
            if hasPrevValues is False and insn in insn_to_reg_count2:
                #print(insn_line)
                #print("has a load and a store : " + hex(insn))
                if insn_to_reg_count2[insn] > 1:
                    #print("has more than one reg ")
                    if pending_reg_count == 0:
                        pending_reg_count = insn_to_reg_count2[insn]
                        pending_regs = []
                        #print(" first encountering the insn")
                    if len(pending_regs) + 1 < pending_reg_count:
                        pending_regs.append(reg_value)
                        #print(" not all regs of the insn are accounted for")
                        continue
                    pending_reg_count = 0
                else:
                    #print("has just one reg ")
                    pending_regs = None
                #print(" all regs of the insn are accounted for " + str(pending_regs))
                hasPrevValues = True
                prev_reg_value = reg_value
                prev_pending_regs = None if pending_regs is None else list(pending_regs)
                continue
            else:
                #print("just one load and a store : " + hex(insn))
                if insn in insn_to_reg_count and insn_to_reg_count[insn] > 1:
                    #print("has more than one reg ")
                    if pending_reg_count == 0:
                        pending_reg_count = insn_to_reg_count[insn]
                        pending_regs = []
                        # print(" first encountering the insn")
                    if len(pending_regs) + 1 < pending_reg_count:
                        pending_regs.append(reg_value)
                        # print(" not all regs of the insn are accounted for")
                        continue
                    # print(" all regs of the insn are accounted for " + str(pending_regs))
                    pending_reg_count = 0
                else:
                    #print("has just one reg ")
                    pending_regs = None

            if contains_bit_op: other_regs_parsed = True

            if insn in remote_df_prede_insn_to_succe_node:
                mem_store_addr = 0
                if static_node.mem_store is not None:
                    if hasPrevValues is True:
                        mem_store_addr = self.calculate_mem_addr(prev_reg_value, static_node.mem_store,
                                                                 None if prev_pending_regs is None else prev_pending_regs[0])
                    else:
                        mem_store_addr = self.calculate_mem_addr(reg_value, static_node.mem_store,
                                                         None if pending_regs is None else pending_regs[0])
                #print("[build] Store " + hex(insn) + " to " + hex(mem_store_addr))
                if (insn not in starting_insns) and (mem_store_addr not in addr_to_df_succe_node):
                    if insn not in local_df_prede_insn_to_succe_node:
                        hasPrevValues = False

                        if insn in load_insn_to_bit_ops:
                            for bit_insn in load_insn_to_bit_ops[insn]:
                                if bit_insn in bit_insn_to_operand:
                                    del bit_insn_to_operand[bit_insn]
                        continue
            hasPrevValues = False

            if insn not in self.insn_to_id:
                self.insn_to_id[insn] = insn_id
                insn_id += 1

            dynamic_node = DynamicNode(self.insn_to_id[insn], static_node, id=uid)
            assert dynamic_node.id not in self.dynamic_nodes
            self.dynamic_nodes[dynamic_node.id] = dynamic_node
            if insn not in self.insn_to_dyn_nodes:
                self.insn_to_dyn_nodes[insn] = set()
            self.insn_to_dyn_nodes[insn].add(dynamic_node)
            self.id_to_node[dynamic_node.id] = dynamic_node

            #if DEBUG:
            print("[dyn_dep] created Dynamic Node id: " + str(dynamic_node.id) \
                  + " Static Node id: " + str(dynamic_node.static_node.id) \
                  + " insn: " + str(dynamic_node.static_node.hex_insn) \
                  + " lines: " + ("" if dynamic_node.static_node.bb is None else str(dynamic_node.static_node.bb.lines)))

            #Note, if a variable has both a load and a store with bit ops
            # the bit mask will be associated to the store
            # and the dataflow will be broken at the load for now
            # as we will not look for further predecessors of the load
            if insn in load_insn_to_bit_ops:
                #assert dynamic_node.bit_ops is None
                dynamic_node.bit_ops = {}
                for bit_insn in load_insn_to_bit_ops[insn]:
                    if bit_insn in bit_insn_to_operand:
                        dynamic_node.bit_ops[bit_insn] = bit_insn_to_operand[bit_insn]
                        del bit_insn_to_operand[bit_insn] #TODO
                dynamic_node.calculate_load_bit_mask()
            if insn in store_insn_to_bit_ops:
                for bit_insn in store_insn_to_bit_ops[insn]:
                    bit_insn_to_node[bit_insn] = dynamic_node

            if insn in self.starting_insn_to_reg:
                dynamic_node.weight = reg_value
                dynamic_node.is_valid_weight = True
                dynamic_node.weight_origins.add(dynamic_node.id)
                dynamic_node.weight_paths.add(dynamic_node.static_node.hex_insn + "@" + dynamic_node.static_node.function)
                print("[dyn_dep] Appending weight " + str(reg_value) + " to node with id: " + str(dynamic_node.id))
            """
            if insn not in self.node_frequencies:
                self.node_frequencies[insn] = 0
            self.node_frequencies[insn] = self.node_frequencies[insn] + 1
            """
            if insn in cf_prede_insn_to_succe_node:
                to_remove = set()
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
                    to_remove = set()
                    for succe in addr_to_df_succe_node[mem_store_addr]:
                        succe.df_predes.append(dynamic_node)
                        dynamic_node.df_succes.append(succe)
                        if succe.load_bit_mask is not None:
                            continue

                        # HACK: if the src reg is smaller than the dst reg, keep looking for more writes
                        dst_reg = succe.static_node.reg_store
                        src_reg = dynamic_node.static_node.reg_load
                        if dst_reg is not None and dst_reg != '' \
                                and src_reg is not None and src_reg != '':
                            dst_reg_size = reg_size_map[dst_reg.lower()]
                            src_reg_size = reg_size_map[src_reg.lower()]
                            if src_reg_size < dst_reg_size:
                                continue
                        to_remove.add(succe)
                    for succe in to_remove:
                        addr_to_df_succe_node[mem_store_addr].remove(succe)
                    if len(addr_to_df_succe_node[mem_store_addr]) == 0:
                        del addr_to_df_succe_node[mem_store_addr]

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

    def trim_dynamic_graph(self, target_insns):
        # get all the nodes with dataflow connection, and where addrs match,
        for dnode in self.dynamic_nodes.values():
            if dnode.mem_store_addr is None:
                continue
            if dnode.bit_ops is None:
                continue
            if dnode.mem_load_addr is not None:
                continue
            if dnode.static_node.mem_store.read_same_as_write is not True:
                continue
            to_remove = set()
            for df_prede in dnode.df_predes:
                if df_prede.static_node.mem_load is None:
                    continue
                if df_prede.static_node.mem_load.read_same_as_write is True:
                    assert df_prede.mem_store_addr is None
                    to_remove.add(df_prede)
                    print("TRIM Do not consider the load for bit vars ")
            for df_prede in to_remove:
                dnode.df_predes.remove(df_prede)
        # check bit mask where they exist, then trim ones that do not match
        for dnode in self.dynamic_nodes.values():
            dnode.remaining_load_bit_mask = dnode.load_bit_mask
            if dnode.mem_load_addr is None:
                continue
            if dnode.bit_ops is None:
                continue
            assert dnode.load_bit_mask is not None, str(dnode) + str(dnode.static_node)
            to_remove = set()
            prede_map = {}
            for df_prede in dnode.df_predes:
                prede_map[df_prede.id] = df_prede
            od = OrderedDict(sorted(prede_map.items()))
            for df_prede in od.values():
                print("CHECKING PREDE " + str(df_prede.id))
                if df_prede.mem_store_addr != dnode.mem_load_addr:
                    continue
                if df_prede.store_bit_mask is None:
                    print("[WARN] store has no bit mask, excluding: " +
                          str(df_prede) + str(df_prede.static_node) + str(dnode) + str(dnode.static_node))
                if (df_prede.store_bit_mask is None) or (df_prede.store_bit_mask & dnode.remaining_load_bit_mask == 0x0):
                    df_prede.df_succes.remove(dnode)
                    to_remove.add(df_prede)
                    print("TRIM Addrs match but bit masks do not: ")# + str(dnode) + " " + str(df_prede))
                else:
                    print("KEEP Addrs match AND bit masks do: ")# + str(dnode) + " " + str(df_prede))
                    overlap = df_prede.store_bit_mask & dnode.remaining_load_bit_mask
                    dnode.remaining_load_bit_mask = dnode.remaining_load_bit_mask&((~overlap)&0xffffffffffffffff)
            for df_prede in to_remove:
                dnode.df_predes.remove(df_prede)

        worklist = deque()
        visited_ids = set()
        # do a one pass traversal to colour nodes
        for node in self.dynamic_nodes.values(): #Dont use exit node, not every target node is an exit node
            if node.static_node.insn in target_insns:
                worklist.append(node)

        while(len(worklist) > 0):
            node = worklist.popleft()
            if node.id in visited_ids:
                continue
            visited_ids.add(node.id)
            for cf_prede in node.cf_predes:
                worklist.append(cf_prede)
            for df_prede in node.df_predes:
                worklist.append(df_prede)

        to_remove = set()
        for node in self.dynamic_nodes.values():
            if node.id not in visited_ids:
                to_remove.add(node)
        print("Total number of nodes removed: " + str(len(to_remove)))
        for node in to_remove: #TODO, might be slow..
            for df_prede in node.df_predes:
                df_prede.df_succes.remove(node)
            for cf_prede in node.cf_predes:
                cf_prede.cf_succes.remove(node)
            del self.dynamic_nodes[node.id]
            del self.id_to_node[node.id]
            self.insn_to_dyn_nodes[node.static_node.insn].remove(node)

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

    def calculate_mem_addr(self, reg_value, expr, off_reg_value=None): #TODO, why not move this into the dynamic node object?
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

    def verify_initail_graph_weight(self):
        bad_count = 0
        good_count = 0
        for node in self.insn_to_dyn_nodes[0x407240]:
            target = node
            for prede in target.cf_predes:
                if prede.static_node.insn == 0x407226:
                    target = prede

            for prede in target.cf_predes:
                if prede.static_node.insn == 0x40720c:
                    target = prede

            for prede in target.cf_predes:
                if prede.static_node.insn == 0x4071c9:
                    target = prede
            assert target.static_node.insn == 0x4071c9
            if target.weight != node.weight:
                print("---------------------------------------------")
                print("---------------------------------------------")
                print(str(target) + "\n" + str(node))
                bad_count += 1
            else:
                good_count += 1
        print("GRAPH SUMMARY0 initial graph good: " + str(good_count) + " bad: " + str(bad_count))

    def propogate_initial_graph_weight(self):
        assert(len(self.postorder_list) > 0)
        """
        for node in self.id_to_node.values():
            if node in self.target_nodes:
                print("Skipping clearing target node: " + str(node.id) + " " + node.static_node.hex_insn)
                continue
            node.is_valid_weight = False
            node.is_aggregate_weight = False
            node.weight = -1
            node.weight_origins = set()
            node.weight_paths = set()
        """

        #backward pass
        for node in self.postorder_list:  # a node will be visited only if its successors have all been visited
            if node in self.target_nodes:
                #assert(node.weight != -1)
                continue
            #assert(node.weight == -1)
            weights = set()
            weight_origins = set()
            weight_paths = set()
            is_aggregate_weight = False

            #for succe in node.cf_succes:
            #    if succe.is_aggregate_weight is True:
            #        is_aggregate_weight = True
            #        break
            #    if succe.is_valid_weight is False:
            #        continue
            #    weights.add(succe.weight)
            for succe in itertools.chain(node.cf_succes, node.df_succes): #hack: break df links
                if succe.is_aggregate_weight is True:
                    continue
                if succe.is_valid_weight is False:
                    continue
                weights.add(succe.weight)
                weight_origins = weight_origins.union(succe.weight_origins)
                weight_paths = weight_paths.union(succe.weight_paths)

            assert -1 not in weights
            if len(weights) > 1:
                weights = set()
                weight_origins = set()
                weight_paths = set()
                for succe in itertools.chain(node.cf_succes, node.df_succes):  # hack: break df links
                    if succe.is_aggregate_weight is True:
                        continue
                    if succe.is_valid_weight is False:
                        continue
                    if (node.static_node.hex_insn + "@" + node.static_node.function) in succe.weight_paths:
                        print("[weight] At " + node.static_node.hex_insn + " " + str(node.id) +
                              " ignore weight from " + succe.static_node.hex_insn + " " + str(succe.id) + " for cycles1")
                        continue
                    weights.add(succe.weight)
                    weight_origins = weight_origins.union(succe.weight_origins)
                    weight_paths = weight_paths.union(succe.weight_paths)

            weight_paths.add(node.static_node.hex_insn + "@" + node.static_node.function)
            if len(weights) > 1:
                node.static_node.print_node("Do not aggregate weights: " + str(weights))
                is_aggregate_weight = True
            if is_aggregate_weight is True:
                node.is_aggregate_weight = True
                continue
            node.weight_origins = weight_origins
            node.weight_paths = weight_paths
            for w in weights:
                assert w != -1
                node.weight = w
                node.is_valid_weight = True
                break

    def verify_weight(self, reference):
        good_count = 0
        bad_count = 0
        for node in self.insn_to_dyn_nodes[0x4071c9]:
            ref_node = reference.id_to_node[node.id]
            if node.weight == ref_node.weight:
                good_count += 1
            else:
                bad_count += 1
        print("GRAPH SUMMARY1 subsequent graph good: " + str(good_count) + " bad: " + str(bad_count))

        good_count = 0
        bad_count = 0
        broken_count = 0
        connected_count = 0
        for node in self.insn_to_dyn_nodes[0x40a6aa]:
            target = node
            for prede in target.cf_predes:
                if prede.static_node.insn == 0x40a6a8:
                    target = prede
            for prede in target.cf_predes:
                if prede.static_node.insn == 0x40a68e:
                    target = prede
            for prede in target.df_predes:
                if prede.static_node.insn == 0x407296:
                    target = prede
            for prede in target.cf_predes:
                if prede.static_node.insn == 0x40728b:
                    target = prede
            for prede in target.cf_predes:
                if prede.static_node.insn == 0x407271:
                    target = prede
            for prede in target.cf_predes:
                if prede.static_node.insn == 0x4071c9:
                    target = prede
            if target.static_node.insn != 0x4071c9:
                print("Broken0 at " + target.static_node.hex_insn)
                broken_count += 1
            else:
                connected_count += 1
                if node.weight == target.weight:
                    good_count += 1
                else:
                    bad_count += 1
        print("GRAPH SUMMARY2 subsequent  connected: " + str(connected_count) + " bad: " + str(broken_count))
        print("GRAPH SUMMARY3 mrkallocated weightOK: " + str(good_count) + " bad: " + str(bad_count))

        good_count = 0
        bad_count = 0
        broken_count = 0
        connected_count = 0
        mark_allocated_weighted = 0
        mark_allocated_not_weighted = 0
        bit_weight_same_as_ptr = 0
        bit_weight_diff_than_ptr = 0
        bad_addrs = {}
        for node in self.insn_to_dyn_nodes[0x4093c6]:
            target = node
            for prede in target.df_predes:
                if prede.static_node.insn == 0x40a6aa:
                    target = prede

            cf_target = node
            for prede in cf_target.cf_predes:
                if prede.static_node.insn == 0x40938e:
                    cf_target = prede

            if target.static_node.insn != 0x40a6aa:
                print("Broken1 at " + target.static_node.hex_insn)
                broken_count += 1
            else:
                connected_count += 1
                if node.weight == target.weight:
                    good_count += 1
                else:
                    bad_count += 1
                if node.id == 3788971047:
                    print("SUMMARY " + str(node.id))
                    print("SUMMARY " + str(target.id))
                    print("SUMMARY " + target.static_node.hex_insn)
                    print("SUMMARY " + str(target.weight))
                    print("SUMMARY " + str(cf_target.id))
                    print("SUMMARY " + cf_target.static_node.hex_insn)
                    print("SUMMARY " + str(cf_target.weight))
                if target.weight == -1:
                    mark_allocated_not_weighted += 1
                else:
                    mark_allocated_weighted += 1
                    if target.weight == cf_target.weight:
                        bit_weight_same_as_ptr += 1
                    else:
                        bit_weight_diff_than_ptr += 1
                        pointer_def = node
                        for prede in pointer_def.cf_predes:
                            if prede.static_node.insn == 0x40938e:
                                pointer_def = prede
                        for prede in pointer_def.cf_predes:
                            if prede.static_node.insn == 0x409380:
                                pointer_def = prede
                        for prede in pointer_def.df_predes:
                            if prede.static_node.insn == 0x409379:
                                pointer_def = prede
                        if len(pointer_def.df_predes) != 1:
                            print("SUMMARY warn: " + str(pointer_def.id))
                        else:
                            pointer_def = pointer_def.df_predes[0]
                            key = pointer_def.static_node.hex_insn + "@" + pointer_def.static_node.function
                            if key not in bad_addrs:
                                bad_addrs[key] = 0
                            bad_addrs[key] = bad_addrs[key] + 1

        print("GRAPH SUMMARY4 subsequent  connected: " + str(connected_count) + " bad: " + str(broken_count))
        print("GRAPH SUMMARY5    get bits weight OK: " + str(good_count) + " bad: " + str(bad_count))
        print("GRAPH SUMMARY5.1  set bits  weighted: " + str(mark_allocated_weighted) + " bad: " + str(mark_allocated_not_weighted))
        print("GRAPH SUMMARY5.2 bits wt same as ptr: " + str(bit_weight_same_as_ptr) + " bad: " + str(bit_weight_diff_than_ptr))
        print("GRAPH SUMMARY5.2 " + str(len(bad_addrs)) + " " + str(bad_addrs))

        good_count = 0
        bad_count = 0
        for node in self.insn_to_dyn_nodes[0x4093c6]:
            if node.weight != -1:
                good_count += 1
            else:
                bad_count += 1
        print("GRAPH SUMMARY6   0x4093c6   weighted: " + str(good_count) + " bad: " + str(bad_count))

        good_count = 0
        bad_count = 0
        for node in self.insn_to_dyn_nodes[0x409418]:
            if node.weight != -1:
                good_count += 1
            else:
                bad_count += 1
        print("GRAPH SUMMARY7   0x409418   weighted: " + str(good_count) + " bad: " + str(bad_count))

        good_count = 0
        bad_count = 0
        for node in self.insn_to_dyn_nodes[0x40721b]:
            if node.weight != -1:
                good_count += 1
            else:
                bad_count += 1
        print("GRAPH SUMMARY8   0x40721b   weighted: " + str(good_count) + " bad: " + str(bad_count))

    def propogate_weight_at_node(self, node, succes, check_aggregation=False, aggregate_static_node_ids=[],
                                 ignore_cycle=False, ignore_cf=False):
        weights = set()
        weight_origins = set()
        weight_paths = set()
        nodes = set()
        if succes is True:
            nodes = nodes.union(node.df_succes)
            if ignore_cf is False or node.static_node.is_df is False:
                nodes = nodes.union(node.cf_succes)
        else:
            nodes = nodes.union(node.df_predes)
            if ignore_cf is False or node.static_node.is_df is False:
                nodes = nodes.union(node.cf_predes)
        for succe_or_prede in nodes:
            if succe_or_prede.is_valid_weight is False:
                continue
            if check_aggregation is True:
                if succe_or_prede.is_aggregate_weight is True:
                    continue
                if succe_or_prede.static_node.id in aggregate_static_node_ids:
                    succe_or_prede.is_aggregate_weight = True
                    continue
            if ignore_cycle is True:
                if (node.static_node.hex_insn + "@" + node.static_node.function) in succe_or_prede.weight_paths:
                    print("[weight] At " + node.static_node.hex_insn + " " + str(node.id) +
                      " ignore weight from " + succe_or_prede.static_node.hex_insn + " " + str(
                    succe_or_prede.id) + " for cycles")
                    continue
            weights.add(succe_or_prede.weight)
            weight_origins = weight_origins.union(succe_or_prede.weight_origins)
            weight_paths = weight_paths.union(succe_or_prede.weight_paths)
        return weights, weight_origins, weight_paths

    def propogate_weight(self, reference):
        assert(len(self.postorder_list) > 0)
        assert (len(self.reverse_postorder_list) > 0)

        for node in self.id_to_node.values():
            node.is_valid_weight = False
            node.is_aggregate_weight = False
            node.weight = -1
            node.weight_origins = set()
            node.weight_paths = set()
            if node.id in reference.id_to_node:
                assert node.is_valid_weight is False
                assert node.is_aggregate_weight is False
                print("in reference graph")
                if reference.id_to_node[node.id].is_valid_weight is False:
                    assert reference.id_to_node[node.id].weight == -1
                    continue
                print("has valid weight")
                ref_node = reference.id_to_node[node.id]
                node.weight = ref_node.weight
                node.weight_origins = set(ref_node.weight_origins)
                node.weight_paths = set(ref_node.weight_paths)
                node.is_valid_weight = True
                assert node.weight != -1

        aggregate_static_node_ids = set()
        for i in range(0,1):
            for node in self.postorder_list:  # a node will be visited only if its successors have all been visited
                weights, weight_origins, weight_paths = self.propogate_weight_at_node(node, True)
                if len(weights) > 1:
                    weights, weight_origins, weight_paths = self.propogate_weight_at_node(node, True, ignore_cycle=True)
                assert -1 not in weights
                is_aggregate_weight = False
                if len(weights) > 1:
                    is_aggregate_weight = True
                if is_aggregate_weight is True:
                    node.is_aggregate_weight = True
                    aggregate_static_node_ids.add(node.static_node.id)
                #else:
                #    node.weight_paths = weight_paths
                #else:
                #    for w in weights:
                #        assert w != -1
                #        node.weight = w
                #        node.is_valid_weight = True
                #        node.weight_origins = weight_origins
                #        break
            for node in self.insn_to_dyn_nodes[0x4071c9]:
                node.is_aggregate_weight = False
                if node.static_node.id in aggregate_static_node_ids:
                    aggregate_static_node_ids.remove(node.static_node.id)
            for node in self.reverse_postorder_list:  # a node will be visited only if its predecessors have all been visited
                weights, weight_origins, weight_paths = self.propogate_weight_at_node(node, False,
                                                                                      check_aggregation=True, aggregate_static_node_ids=aggregate_static_node_ids)
                if len(weights) > 1:
                    weights, weight_origins, weight_paths = self.propogate_weight_at_node(node, False,
                                                                                          check_aggregation=True, aggregate_static_node_ids=aggregate_static_node_ids,
                                                                                          ignore_cycle=True)
                if len(weights) > 1:
                    weights, weight_origins, weight_paths = self.propogate_weight_at_node(node, False,
                                                                                          check_aggregation=True, aggregate_static_node_ids=aggregate_static_node_ids,
                                                                                          ignore_cycle=True, ignore_cf=True)
                if len(weights) > 1:
                    node.weight = -1
                    node.is_valid_weight = False
                    node.is_aggregate_weight = True
                    node.static_node.print_node("Do not aggregate weights: " + str(node.id) + " " + str(weights))
                    continue
                if len(weights) > 0:
                    #weight_paths.add(node.static_node.hex_insn + "@" + node.static_node.function)
                    node.weight_origins = weight_origins
                    node.weight_paths = weight_paths
                for w in weights:
                    assert w != -1  # TODO remove
                    node.weight = w
                    node.is_valid_weight = True
                    break
            done = True
            for node in self.target_nodes:
                if node.is_valid_weight is False:
                    done = False
            if done:
                break

def print_path(curr_node, end_id):
    for p in curr_node.df_predes:#itertools.chain(curr_node.cf_predes, curr_node.df_predes):
        if p.id == end_id:
            print(p)
            return True
        found = print_path(p, end_id)
        if found:
            print(p)
            return found
    return False

if __name__ == '__main__':
    starting_events = []
    starting_events.append(["rdi", 0x409daa, "sweep"])
    starting_events.append(["rbx", 0x407240, "runtime.mallocgc"])
    starting_events.append(["rdx", 0x40742b, "runtime.mallocgc"])
    starting_events.append(["rcx", 0x40764c, "runtime.free"])

    dd = DynamicDependence(starting_events, "909_ziptest_exe9", "test.zip", "/home/anygroup/perf_debug_tool/")
    dd.prepare_to_build_dynamic_dependencies(10000)

    dg = dd.build_dyanmic_dependencies(0x409418)

    sizes = {}
    with open("weight", "r") as f:
        lines = f.readlines()
        for l in lines:
            segs = l.split()
            addr = int(segs[0], 16)
            if addr in sizes:
                if sizes[addr] != segs[1]:
                    print(segs[1])
                    print(sizes[addr])
            #print("HERE1 " + hex(addr))
            sizes[addr] = segs[1]

    total_weight = 0
    #for addr in sizes:
    #    total_weight+= int(sizes[addr])

    addr_not_explained = set()
    addr_explained = set()
    prede_found = 0
    prede_not_found = 0
    connected_predes = {}
    connected_predes_not_connected_to_malloc = {}
    connected_predes_not_connected_to_malloc1 = {}
    from_malloc = 0
    addr_from_malloc = set()
    node_to_weight = {}
    connected_count = 0
    for n in dg.insn_to_dyn_nodes[4232057]:
        sw = deque()
        sw.append(n)
        visited = set()
        while len(sw) > 0:
            sc = sw.popleft()
            if sc in visited:
                continue
            visited.add(sc)
            if sc.static_node.insn == 0x409418:
                node_to_weight[n] = n.weight
                """
                if sc.mem_load_addr in sizes:
                    node_to_weight[n] = sizes[sc.mem_load_addr]
                else:
                    node_to_weight[n] = 0
                """
                #print("FOUND SUCCE")
                break
            for scs in sc.df_succes:
                sw.append(scs)
            for scs in sc.cf_succes:
                sw.append(scs)
        
        total_weight += int(node_to_weight[n])
        if len(n.df_predes) == 0:
            prede_not_found += 1
            addr_not_explained.add(hex(n.mem_load_addr))
        else:
            malloc_nodes = set()
            connected_to_malloc = False
            prede_found += 1
            addr_explained.add(hex(n.mem_load_addr))
            for p in n.df_predes:
                if p.static_node not in connected_predes:
                    connected_predes[p.static_node] = 0
                connected_predes[p.static_node] += \
                        connected_predes[p.static_node] + int(node_to_weight[n])
            wl = deque()
            wl.append(n)
            visited = set()
            while len(wl) > 0:
                c = wl.popleft()
                if c in visited:
                    continue
                visited.add(c)
                #0x408038
                if c.static_node.insn == 0x4072e5:# or c.static_node.insn == 0x408447: # or c.static_node.insn ==  0x4072e5:
                    addr_from_malloc.add(hex(n.mem_load_addr))
                    if len(malloc_nodes) == 0:
                        from_malloc += 1
                    malloc_nodes.add(c.id)
                    connected_to_malloc = True
                    #break TODO
                for pp in c.df_predes:
                    wl.append(pp)
            """
            if len(malloc_nodes) > 1:
                print(str(n.id) + " is connected to more than one malloc " + str(len(malloc_nodes)))
                for malloc_node in malloc_nodes:
                    print("*************************************************")
                    print("ID " + str(malloc_node))
                    print_path(n, malloc_node)
                    print(n)
                    print("*************************************************")
            """
            if connected_to_malloc is False:
                if p.static_node not in connected_predes_not_connected_to_malloc:
                    connected_predes_not_connected_to_malloc[p.static_node] = 0
                    connected_predes_not_connected_to_malloc1[p.static_node] = []
                connected_predes_not_connected_to_malloc[p.static_node] =\
                connected_predes_not_connected_to_malloc[p.static_node] + int(node_to_weight[n])#+ 1
                connected_predes_not_connected_to_malloc1[p.static_node].append(hex(n.mem_load_addr))
            else:
                connected_count += int(node_to_weight[n])


    print("Total weight " + str(total_weight))
    print(" Total count " + str(len(dg.insn_to_dyn_nodes[4232057])))
    print(" Total count with prede " + str(prede_found) + " " + str(len(addr_explained)))
    print(" Total count with no prede " + str(prede_not_found) + " " + str(len(addr_not_explained)))
    print(" Total count connected to malloc " + str(from_malloc) + " " + str(len(addr_from_malloc)))
    for addr in addr_explained:
        print("FOUND: " + addr)
    for addr in addr_not_explained:
        print("MISSING: " + addr)


    print("==============================")
    sn = StaticDepGraph.func_to_graph['scanblock'].insn_to_node[4232057]
    """
    predes = []
    for p in sn.df_predes:
        assert p.explained
        assert p.mem_store is not None
        print(p.mem_store)
        predes.append(p.toJSON())
        p.print_node(" all predes: ")
    print("==============================")
    """
    #total_not_connected = 0
    for p in connected_predes:
        print(p.mem_store)
        p.print_node(" connected:  ")
        #print(" count: " + str(connected_predes[p]))
        #total_not_connected += connected_predes[p]
    #print( " TOTAL COUNT: " + str(total_not_connected))
    #print( " % " + str(total_not_connected/total_weight))
    print("==============================")
    total_not_connected = 0
    for p in connected_predes_not_connected_to_malloc:
        print(p.mem_store)
        p.print_node(" connected but not to malloc:  ")
        print(" count: " + str(connected_predes_not_connected_to_malloc[p]))
        print(" % : " + str(connected_predes_not_connected_to_malloc[p]/total_weight*100))
        print(" addrs : " + str(connected_predes_not_connected_to_malloc1[p]))
        total_not_connected += connected_predes_not_connected_to_malloc[p]
    print( " TOTAL COUNT: " + str(total_not_connected))
    print( " TOTAL WEIGHT: " + str(total_not_connected))
    print( " % " + str(total_not_connected/total_weight*100))
    print( " TOTAL COUNT: " + str(connected_count))
    print( " % " + str(connected_count/total_weight*100))
    print("==============================")
    for p in sn.df_predes:
        if p in connected_predes:
            continue
        print(p.mem_store)
        p.print_node(" not found:  ")
    #with open(os.path.join(curr_dir, 'predes'), 'w') as f:
    #    json.dump(predes, f, indent=4, ensure_ascii=False)
