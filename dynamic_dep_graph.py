import json
import os
import select
import time
from util import *
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
import traceback
import socketserver
import socket
import select
import copy

curr_dir = os.path.dirname(os.path.realpath(__file__))
target_dir = os.path.join(curr_dir, 'dynamicGraph')

time_record = {}
DEBUG_POST_ORDER = False
DEBUG = False
PARALLEL_PREPARSE = True
PROP_WEIGHT = False
DEBUG_MULTIPLE = False

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
        self.output_set_uid = None
        self.output_exclude_set = set()
        self.output_set_count = None
        self.output_weight = None
        #self.output_set1 = set()
        self.input_sets = {}
        self.weight = -1
        self.weight_origins = set()
        self.weight_paths = set()
        self.forward_weight_paths = []
        self.is_valid_weight = False
        self.is_aggregate_weight = False
        self.thread_id = None
        self.is_starting = False #flag used when building multiple dynamic graphs tgt

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
        if self.thread_id != None:
            s += "    thread id: " + str(self.thread_id)
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
        #data["weight_origins"] = list(self.weight_origins)
        #data["weight_paths"] = list(self.weight_paths)
        #data["forward_weight_paths"] = list(self.forward_weight_paths)
        if len(self.input_sets) > 0:
            data["input_sets"] = self.input_sets
        data["output_set_count"] = self.output_set_count
        data["output_weight"] = self.output_weight
        if self.thread_id != None:
            data["thread_id"] = self.thread_id
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
        #dn.weight_origins = set(data["weight_origins"])
        #dn.weight_paths = set(data["weight_paths"])
        #if "forward_weight_paths" in data:
        #    dn.forward_weight_paths = set(data["forward_weight_paths"])
        dn.is_valid_weight = data["is_valid_weight"]
        dn.is_aggregate_weight = data["is_aggregate_weight"]

        if "output_set_count" in data:
            dn.output_set_count = data["output_set_count"]
        if "output_weight" in data:
            dn.output_weight =  data["output_weight"]
        if "input_sets" in data:
            json_input_sets = data["input_sets"]
            for k in json_input_sets:
                dn.input_sets[int(k)] = json_input_sets[k]

        if "thread_id" in data:
            dn.thread_id = data["thread_id"]
        return dn


    @staticmethod
    def semi_deepcopy(node):
        #FIXME: This should suffice for now...
        c = copy.copy(node)
        for k in c.__dict__.keys():
            if isinstance(c.__dict__[k], StaticNode):
                continue
            if isinstance(c.__dict__[k], DynamicNode):
                continue
            c.__dict__[k] = copy.copy(c.__dict__[k])
        return c

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
                        else:
                            load_bit_mask = load_bit_mask & self.bit_ops[bit_op.insn]
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
                    #raise Exception
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
                print("[warn] Unhandled bit op: " + str(bit_op.operation))
                self.store_bit_mask = None
                return
        print("store mask calculated for " + self.static_node.hex_insn + " to be " + "{:64b}".format(self.store_bit_mask))


class DynamicDependence:
    def __init__(self, starting_events, prog, arg, path, starting_insn_to_weight={}):
        self.prog = prog
        self.arg = arg
        self.path = path
        self.key = None
        self.all_static_cf_nodes = []
        self.all_static_df_nodes = []
        self.insn_of_cf_nodes = []
        self.insn_of_cf_nodes_set = None
        self.insn_of_df_nodes = []
        self.insn_of_df_nodes_set = None
        self.dynamic_nodes = OrderedDict()
        self.insn_to_static_node = {}
        self.insn_of_local_df_nodes = []
        self.insn_of_local_df_nodes_set = None
        self.insn_of_remote_df_nodes = []
        self.insn_of_remote_df_nodes_set = None
        self.insn_to_reg_count = {}
        self.insn_to_reg_count2 = {}
        self.code_to_insn = {}
        self.insns_with_regs = []
        self.insns_with_regs_set = None
        self.max_code_with_static_node = -1
        self.load_insn_to_bit_ops = {} #bit op follows the load
        self.bit_op_to_store_insns = {} #bit op precedes store
        self.store_insn_to_bit_ops = {}

        # phase out this eventually and just use one unified list to represent every starting event
        self.starting_insns = set()
        self.starting_insn_to_reg = {}
        for event in starting_events:
            curr_insn = event[1]
            self.starting_insns.add(curr_insn) #FIXME: change start to starting?
            curr_reg = event[0]
            if curr_reg is None:
                continue
            curr_insn = event[1]
            assert(curr_insn not in self.starting_insn_to_reg)
            self.starting_insn_to_reg[curr_insn] = curr_reg

        self.starting_events = list(starting_events)
        print("[dg] Starting events are: " + str(self.starting_events))
        self.starting_insn_to_weight = starting_insn_to_weight

        self.key = build_key(self.starting_events)

        self.trace_name = self.key + "_" + 'instruction_trace.out'
        self.trace_path = os.path.join(curr_dir, 'pin', self.trace_name)

        self.init_graph = None

    def get_dynamic_trace(self, prog, arg, path, trace_name, trace_path):
        #FIXME: not necessary to pass prog, arg, path, they are fields
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

        instructions = []
        unique_insns = set()
        i = 0

        print("[dyn_dep] number of instructions to ignore: " + str(len(StaticDepGraph.insns_that_never_executed)))

        for start_event in self.starting_events:
            reg = start_event[0]
            insn = start_event[1]
            func = start_event[2]
            graph = StaticDepGraph.get_graph(func, insn)
            node = graph.insn_to_node[insn] if graph is not None else None
            if node is None:
                print("[dg/warn] starting event not found: " + hex(insn))
                continue
            assert insn not in unique_insns
            unique_insns.add(insn)
            if insn in StaticDepGraph.insns_that_never_executed:
                continue

            i += 1
            self.code_to_insn[i] = insn
            
            if self.insn_to_static_node[insn].mem_load is not None:
                self.insn_to_static_node[insn].mem_load = None
                print("[warn] Ignoring the mem load of a starting node")
            if self.insn_to_static_node[insn].mem_store is not None:
                self.insn_to_static_node[insn].mem_store = None
                print("[warn] Ignoring the mem store of a starting node")
 
            if reg != "":
                instructions.append([hex(insn), reg, i])
                self.insns_with_regs.append(insn)
                self.insn_to_reg_count[insn] = 1
            else:
                instructions.append([hex(insn), "pc", i])


        #go through every dataflow node to find the bit vars first

        for node in self.all_static_df_nodes:
            #print("DF" + node.hex_insn)
            if node.insn in unique_insns: #TODO should not have overlaps ..
                continue
            unique_insns.add(node.insn)
            if node.insn in StaticDepGraph.insns_that_never_executed:
                continue

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
                self.insns_with_regs.append(node.insn)

        for insn in insn_to_bit_operand:
            assert insn not in unique_insns
            unique_insns.add(insn)

        for node in self.all_static_cf_nodes:
            if node.insn in unique_insns:
                continue
            unique_insns.add(node.insn)
            if node.insn in StaticDepGraph.insns_that_never_executed:
                continue

            i += 1
            self.code_to_insn[i] = node.insn
            instructions.append([node.hex_insn, 'pc', i])

            if self.insn_to_static_node[node.insn].mem_load is not None:
                self.insn_to_static_node[node.insn].mem_load = None
                print("[warn] Ignoring the mem load of a CF node")
            if self.insn_to_static_node[node.insn].mem_store is not None:
                self.insn_to_static_node[node.insn].mem_store = None
                print("[warn] Ignoring the mem store of a CF node")
 
        self.max_code_with_static_node = i

        for insn in insn_to_bit_operand:
            if insn in StaticDepGraph.insns_that_never_executed:
                continue
            i += 1
            self.code_to_insn[i] = insn
            reg = insn_to_bit_operand[insn]
            instructions.append([hex(insn), reg, i])
            #self.insns_with_regs.add(insn)
            #self.insn_to_reg_count[insn] = 1
            
        assert i < 65536, i
        self.insns_with_regs_set = set(self.insns_with_regs)

        if os.path.isfile(trace_path):
            return

        # invoke PIN. get output of a sequence of insn
        trace = InsRegTrace(path + prog + ' ' + arg,
                            pin='~/pin-3.11/pin', out=trace_name)
        print("[dyn_dep] Total number of instructions watched: " + str(len(instructions)))
        print(instructions)
        trace.run_function_trace(instructions)
        return

    def build_static_dependencies(self, starting_events, prog, sa_steps=10000):

        # Get slice #TODO, add a cache here
        used_cached_result = StaticDepGraph.build_dependencies(starting_events, prog, limit=sa_steps)

        for graph in StaticDepGraph.func_to_graph.values():

            for node in graph.none_df_starting_nodes:
                self.all_static_cf_nodes.append(node)
                self.insn_to_static_node[node.insn] = node

            for node in graph.nodes_in_cf_slice.keys():
                self.all_static_cf_nodes.append(node)
                self.insn_to_static_node[node.insn] = node
                self.insn_of_cf_nodes.append(node.insn)
                #print(node)

            for node in graph.nodes_in_df_slice.keys():
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
        self.insn_of_cf_nodes_set = set(self.insn_of_cf_nodes)
        self.insn_of_df_nodes_set = set(self.insn_of_df_nodes)
        self.insn_of_local_df_nodes_set = set(self.insn_of_local_df_nodes)
        self.insn_of_remote_df_nodes_set = set(self.insn_of_remote_df_nodes)
        return used_cached_result

    # TODO, refactor into a more user friendly interface?
    def build_dynamic_dependencies(self, insn=None, pa_id=None):
        print("Building dynamic graph, starting insn is: " + (hex(insn) if insn is not None else str(insn)) + " pa_id " + str(pa_id))
        file_name = 'dynamic_graph_result_' + self.key + "_" + (hex(insn) if insn is not None else str(insn))
        result_file = os.path.join(curr_dir, 'cache', self.prog, file_name)
        time_record["start"] = time.time()
        if os.path.isfile(result_file):
            print("Reading from file:" + result_file)
            with open(result_file, 'r') as f:
                dynamic_graph = DynamicGraph.load_graph_from_json(result_file)
                time_record["load_json"] = time.time()
                print("[TIME] Loading graph from json: ", str(time_record["load_json"] - time_record["start"]), flush=True)
        else:
            byte_seq, codes_to_ignore, thread_id_byte_seq, _ = self.invoke_preparser(list(self.starting_insns) if insn is None else [insn],
                                                                                     curr_dir, pa_id=pa_id)

            #time_record["read_preparse"] = time.time()
            #print("[TIME] Loading preparsed trace took: ", str(time_record["read_preparse"] - time_record["preparse"]), flush=True)

            time_record["preparse"] = time.time()
            print("[TIME] Preparsing trace took: ", str(time_record["preparse"] - time_record["start"]), flush=True)

            dynamic_graph = self.build_dynamic_graph(self.starting_insns if insn is None else set([insn]),
                                      byte_seq, codes_to_ignore, thread_id_byte_seq)
            time_record["build_finish"] = time.time()
            print("[TIME] Building dynamic graph took: ", str(time_record["build_finish"] - time_record["preparse"]), flush=True)

            dynamic_graph.trim_dynamic_graph(self.starting_insns if insn is None else set([insn]))
            time_record["trim_finish"] = time.time()
            print("[TIME] Trimming dynamic graph took: ", str(time_record["trim_finish"] - time_record["build_finish"]), flush=True)

            dynamic_graph.report_result()
            dynamic_graph.result_file = result_file
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
            
            if PROP_WEIGHT is True:
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

        if PROP_WEIGHT is True:
            if self.init_graph is None:
                #pass
                #dynamic_graph.verify_initial_graph_weight()
                dynamic_graph.propogate_initial_graph_weight()
            else:
                dynamic_graph.propogate_weight(self.init_graph)
                #dynamic_graph.verify_weight(self.init_graph)
                #with open(result_file, 'w') as f:
                #    json.dump(dynamic_graph.toJSON(), f, indent=4, ensure_ascii=False)

        print("[dyn_dep] total number of dynamic nodes: " + str(len(dynamic_graph.dynamic_nodes)))
        print("[dyn_dep] total number of target nodes: " + str(len(dynamic_graph.target_nodes)))
        return dynamic_graph

    def prepare_to_build_dynamic_dependencies(self, sa_steps=10000):
        # Get static dep, then invoke pin to get execution results, and build CFG
        #FIXME: convert start instruction to hex
        time_record["before_static_slice"] = time.time()
        used_cached_result = \
            self.build_static_dependencies(self.starting_events, self.prog, sa_steps)
        time_record["static_slice"] = time.time()
        print("[TIME] Getting static slice: ",
              str(time_record["static_slice"] - time_record["before_static_slice"]), flush=True)

        self.get_dynamic_trace(self.prog, self.arg, self.path, self.trace_name, self.trace_path)
        time_record["invoke_pin"] = time.time()
        print("[TIME] Invoking PIN took: ",
              str(time_record["invoke_pin"] - time_record["static_slice"]), flush=True)
        if PROP_WEIGHT is True:
            self.init_graph = self.build_dynamic_dependencies()

    def detect_dynamic_callees_run_trace(self):
        StaticDepGraph.binary_ptr = setup(self.prog)
        callsites = get_dynamic_callsites(StaticDepGraph.binary_ptr)
        visited = set()
        instructions = []
        mem_accesses = []
        insn_to_func_map = {}
        i = 0
        for load in callsites:
            insn = load[0]
            assert insn not in visited
            visited.add(insn)
            hex_insn = hex(insn)
            reg = load[1]
            shift = load[2]
            off = load[3]
            off_reg = load[4]
            mem_load = MemoryAccess(reg, shift, off, off_reg, False)
            func = load[8]
            insn_to_func_map[insn] = func

            reg_count = 0
            if mem_load.reg != None and mem_load.reg != '':
                reg_count += 1
            if mem_load.off_reg != None and mem_load.off_reg != '':
                reg_count += 1
            if reg_count == 0:
                continue
            if reg_count > 1:
                print("[warn] dynamic callsite involving multiple regs are not handled right now: " + hex_insn)
                continue
            i += 1
            mem_accesses.append(mem_load.toJSON())
            if mem_load.reg != None and mem_load.reg != '':
                instructions.append([hex_insn, mem_load.reg.lower(), i])
            if mem_load.off_reg != None and mem_load.off_reg != '':
                instructions.append([hex_insn, mem_load.off_reg.lower(), i])

            self.code_to_insn[i] = insn
            self.insn_to_reg_count[insn] = reg_count
        assert i < 65536
        with open("getDynamicCallsites1_result", 'w') as f:
            json.dump(insn_to_func_map, f, indent=4, ensure_ascii=False)

        preprocess_data = {
            "trace_file": self.trace_path,
            "code_to_insn": self.code_to_insn,
            "insn_to_reg_count": self.insn_to_reg_count,
            "mem_accesses": mem_accesses
        }
        preprocess_data_file = os.path.join(curr_dir, 'preprocess_data')
        with open(preprocess_data_file, 'w') as f:
            json.dump(preprocess_data, f, indent=4, ensure_ascii=False)

        # invoke PIN. get output of a sequence of insn
        trace = InsRegTrace(self.path + self.prog + ' ' + self.arg,
                            pin='~/pin-3.11/pin', out=self.trace_name)
        print("[dyn_dep] Total number of instructions watched: " + str(len(instructions)))
        print(instructions)
        trace.run_function_trace(instructions, False)

    def detect_dynamic_callees_parse_trace(self):
        preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'call_site_parser')
        cmd = [preprocessor_file]
        try:
            pp_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = pp_process.communicate()
        except Exception as e:
            print("Caught exception: " + str(e))
            print(str(e))
            print("-" * 60)
            traceback.print_exc(file=sys.stdout)
            print("-" * 60)
        print(stdout)
        print(stderr)

        insn_to_func_map = {}
        with open("getDynamicCallsites1_result", 'r') as f:
            str_insn_to_func_map = json.load(f)
            for insn in str_insn_to_func_map:
                insn_to_func_map[int(insn)] = str_insn_to_func_map[insn]

        callee_to_callsite = {}
        with open(self.trace_path + ".parsed", 'r') as f:
            lines = f.readlines()  # more than twice faster than readlines!
            for l in lines:
                segs = l.split("|")
                callsite = int(segs[0], 16)
                callees = segs[1].split()
                print(hex(callsite))
                print(str(callees))
                func = insn_to_func_map[callsite]
                print(func)
                for c in callees:
                    callee = int(c, 16)
                    callsites = callee_to_callsite.get(callee, None)
                    if callsites is None:
                        callsites = []
                        callee_to_callsite[callee] = callsites
                    callsites.append([callsite, func])
        result_file = os.path.join(curr_dir, 'cache', self.prog, "dyn_callsites.json")
        with open(result_file, 'w') as f:
            json.dump(callee_to_callsite, f, indent=4, ensure_ascii=False)
        os.remove(self.trace_path)

    def build_multiple_dynamic_dependencies(self, insns):
        print("Building dynamic graph with multiple starting events and each only sliced one step"
                ", total number are: " + str(len(insns)) + " starting insns are: " + str(insns))
        #FIXME may want to version the file.
        file_name = 'dynamic_graph_result_' + self.key + "_multiple_" + str(len(insns))
        insns = set(insns)
        result_file = os.path.join(curr_dir, 'cache', self.prog, file_name)
        time_record["start"] = time.time()
        starting_insn_to_dynamic_graph = {}

        left_over = []
        for insn in insns:
            curr_result_file = result_file + "_" + hex(insn)
            print("Looking for file: " + str(curr_result_file))
            if os.path.isfile(curr_result_file):
                starting_insn_to_dynamic_graph[insn] = DynamicGraph.load_graph_from_json(curr_result_file)
            else:
                left_over.append(insn)
        insns = left_over
        time_record["load_json"] = time.time()
        print("[TIME] Loading graph from json: ", str(time_record["load_json"] - time_record["start"]), flush=True)
        if len(insns) > 0:
            byte_seq, codes_to_ignore, thread_id_byte_seq, starting_uid_byte_seq = self.invoke_preparser(insns, curr_dir, pa_id=None, parse_multiple=True)
            codes_to_ignore = set()
            #time_record["read_preparse"] = time.time()
            #print("[TIME] Loading preparsed trace took: ", str(time_record["read_preparse"] - time_record["preparse"]), flush=True)

            time_record["preparse"] = time.time()
            print("[TIME] Preparsing trace took: ", str(time_record["preparse"] - time_record["start"]), flush=True)

            # pass the starting file and flag to parse multiple
            dynamic_graph = self.build_dynamic_graph(insns, byte_seq, codes_to_ignore, thread_id_byte_seq, 
                                              starting_uid_byte_seq=starting_uid_byte_seq)
            time_record["build_finish"] = time.time()
            print("[TIME] Building dynamic graph took: ", str(time_record["build_finish"] - time_record["preparse"]), flush=True)

            dynamic_graph.trim_dynamic_graph(insns)
            time_record["trim_finish"] = time.time()
            print("[TIME] Trimming dynamic graph took: ", str(time_record["trim_finish"] - time_record["build_finish"]), flush=True)

            for insn in insns:
                starting_insn_to_dynamic_graph[insn] = DynamicGraph(self.starting_events)

            print("[dg] Total number of dynamic graphs to build: " + str(len(starting_insn_to_dynamic_graph)))

            for node in dynamic_graph.dynamic_nodes.values():
                if node.is_starting is True:
                    insn = node.static_node.insn
                    curr_dynamic_graph = starting_insn_to_dynamic_graph[insn]
                    copied_node = curr_dynamic_graph.dynamic_nodes.get(node.id, DynamicNode.semi_deepcopy(node))
                    curr_dynamic_graph.insert_node(insn, copied_node)
                    for prede in itertools.chain(node.cf_predes, node.df_predes):
                        copied_prede = curr_dynamic_graph.dynamic_nodes.get(prede.id, DynamicNode.semi_deepcopy(prede))
                        curr_dynamic_graph.insert_node(prede.static_node.insn, copied_prede)

            for insn in starting_insn_to_dynamic_graph.keys():
                print("[dg] Building multiple dynamic graphs, currently building: " + str(hex(insn)))
                curr_dynamic_graph = starting_insn_to_dynamic_graph[insn]
                for node in curr_dynamic_graph.dynamic_nodes.values():
                    new_cf_succes = []
                    for cf_succe in node.cf_succes:
                        if cf_succe.id in curr_dynamic_graph.id_to_node:
                            new_cf_succes.append(curr_dynamic_graph.id_to_node[cf_succe.id])
                    node.cf_succes = new_cf_succes

                    new_df_succes = []
                    for df_succe in node.df_succes:
                        if df_succe.id in curr_dynamic_graph.id_to_node:
                            new_df_succes.append(curr_dynamic_graph.id_to_node[df_succe.id])
                    node.df_succes = new_df_succes

                    if node.is_starting is False:
                        continue

                    new_cf_predes = []
                    for cf_prede in node.cf_predes:
                        if cf_prede.id in curr_dynamic_graph.id_to_node:
                            new_cf_predes.append(curr_dynamic_graph.id_to_node[cf_prede.id])
                    node.cf_predes = new_cf_predes

                    new_df_predes = []
                    for df_prede in node.df_predes:
                        if df_prede.id in curr_dynamic_graph.id_to_node:
                            new_df_predes.append(curr_dynamic_graph.id_to_node[df_prede.id])
                    node.df_predes = new_df_predes

                #curr_dynamic_graph.report_result()
                curr_result_file = result_file + "_" + hex(insn)
                curr_dynamic_graph.result_file = curr_result_file
                #time_record["report_result"] = time.time()
                #print("[TIME] Reporting result took: ", str(time_record["report_result"] - time_record["trim_finish"]), flush=True)

                curr_dynamic_graph.sanity_check()
                curr_dynamic_graph.sanity_check1()
                print("[TIME] finished Sanity check.")
                #time_record["sanity_check"] = time.time()
                #print("[TIME] Sanity check took: ", str(time_record["sanity_check"] - time_record["report_result"]), flush=True)

                curr_dynamic_graph.find_entry_and_exit_nodes()
                curr_dynamic_graph.find_target_nodes(self.starting_insns if insn is None else set([insn]))
                print("[TIME] finished Locating entry&exit&target nodes.")
                #time_record["find_target_nodes"] = time.time()
                #print("[TIME] Locating entry&exit&target nodes took: ",
                #      str(time_record["find_target_nodes"] - time_record["sanity_check"]), flush=True)

                curr_dynamic_graph.build_postorder_list()
                #time_record["postorder"] = time.time()
                #print("[TIME] Postorder traversal took: ",
                #      str(time_record["postorder"] - time_record["find_target_nodes"]), flush=True)

                curr_dynamic_graph.build_reverse_postorder_list()
                #time_record["reverse_postorder"] = time.time()
                #print("[TIME] Reverse postorder traversal took: ",
                #      str(time_record["reverse_postorder"] - time_record["postorder"]), flush=True)
                #if self.init_graph is None:
                #    curr_dynamic_graph.propogate_initial_graph_weight()
                #else:
                #    curr_dynamic_graph.propogate_weight(self.init_graph)

                #time_record["propogate_weight"] = time.time()
                #print("[TIME] Propogating weight took: ",
                #      str(time_record["propogate_weight"] - time_record["reverse_postorder"]), flush=True)
                with open(result_file + "_" + hex(insn), 'w') as f:
                    json.dump(curr_dynamic_graph.toJSON(), f, indent=4, ensure_ascii=False)
                print("[TIME] finished Saving graph in json.")
                #time_record["save_curr_dynamic_graph_as_json"] = time.time()
                #print("[TIME] Saving graph in json took: ",
                #      str(time_record["save_curr_dynamic_graph_as_json"] - time_record["trim_finish"]), flush=True)

                #if self.init_graph is None:
                #    #pass
                #    #dynamic_graph.verify_initial_graph_weight()
                #    dynamic_graph.propogate_initial_graph_weight()
                #else:
                #    dynamic_graph.propogate_weight(self.init_graph)
                #    #dynamic_graph.verify_weight(self.init_graph)
                #    #with open(result_file, 'w') as f:
                #    #    json.dump(dynamic_graph.toJSON(), f, indent=4, ensure_ascii=False)

                print("[dyn_dep] total number of dynamic nodes: " + str(len(curr_dynamic_graph.dynamic_nodes)))
                print("[dyn_dep] total number of target nodes: " + str(len(curr_dynamic_graph.target_nodes)))
        return starting_insn_to_dynamic_graph

    def build_multiple_dynamic_dependencies_in_context(self, parent_insn, insns):
        print("Building dynamic graph with multiple starting events and each only sliced one step"
                + " from existing graph: " + hex(parent_insn) +
                ", total number are: " + str(len(insns)) + " starting insns are: " + str(insns))
        #FIXME may want to version the file.
        parent_file_name = 'dynamic_graph_result_' + self.key + "_" + hex(parent_insn)
        file_name = parent_file_name + "_multiple_" + str(len(insns))
        insns = set(insns)
        result_file = os.path.join(curr_dir, 'cache', self.prog, file_name)
        time_record["start"] = time.time()
        starting_insn_to_dynamic_graph = {}

        left_over = []
        for insn in insns:
            curr_result_file = result_file + "_" + hex(insn)
            print("Looking for file: " + str(curr_result_file))
            if os.path.isfile(curr_result_file):
                starting_insn_to_dynamic_graph[insn] = DynamicGraph.load_graph_from_json(curr_result_file)
            else:
                left_over.append(insn)
        insns = left_over
        time_record["load_json"] = time.time()
        print("[TIME] Loading graph from json: ", str(time_record["load_json"] - time_record["start"]), flush=True)
        if len(insns) > 0:
            dynamic_graph = self.build_dynamic_dependencies(parent_insn)

            for insn in insns:
                starting_insn_to_dynamic_graph[insn] = DynamicGraph(self.starting_events)

            print("[dg] Total number of dynamic graphs to build: " + str(len(starting_insn_to_dynamic_graph)))
            for node in dynamic_graph.dynamic_nodes.values():
                if node.static_node.insn in insns:
                    insn = node.static_node.insn
                    curr_dynamic_graph = starting_insn_to_dynamic_graph[insn]
                    copied_node = curr_dynamic_graph.dynamic_nodes.get(node.id, DynamicNode.semi_deepcopy(node))
                    curr_dynamic_graph.insert_node(insn, copied_node)
                    for prede in itertools.chain(node.cf_predes, node.df_predes):
                        copied_prede = curr_dynamic_graph.dynamic_nodes.get(prede.id, DynamicNode.semi_deepcopy(prede))
                        curr_dynamic_graph.insert_node(prede.static_node.insn, copied_prede)

            for insn in starting_insn_to_dynamic_graph.keys():
                print("[dg] Building multiple dynamic graphs, currently building: " + str(hex(insn)))
                curr_dynamic_graph = starting_insn_to_dynamic_graph[insn]
                for node in curr_dynamic_graph.dynamic_nodes.values():
                    new_cf_succes = []
                    for cf_succe in node.cf_succes:
                        if cf_succe.id in curr_dynamic_graph.id_to_node:
                            new_cf_succes.append(curr_dynamic_graph.id_to_node[cf_succe.id])
                    node.cf_succes = new_cf_succes

                    new_df_succes = []
                    for df_succe in node.df_succes:
                        if df_succe.id in curr_dynamic_graph.id_to_node:
                            new_df_succes.append(curr_dynamic_graph.id_to_node[df_succe.id])
                    node.df_succes = new_df_succes

                    #if node.is_starting is False:
                    #    continue

                    new_cf_predes = []
                    for cf_prede in node.cf_predes:
                        if cf_prede.id in curr_dynamic_graph.id_to_node:
                            new_cf_predes.append(curr_dynamic_graph.id_to_node[cf_prede.id])
                    node.cf_predes = new_cf_predes

                    new_df_predes = []
                    for df_prede in node.df_predes:
                        if df_prede.id in curr_dynamic_graph.id_to_node:
                            new_df_predes.append(curr_dynamic_graph.id_to_node[df_prede.id])
                    node.df_predes = new_df_predes

                #curr_dynamic_graph.report_result()
                curr_result_file = result_file + "_" + hex(insn)
                curr_dynamic_graph.result_file = curr_result_file
                #time_record["report_result"] = time.time()
                #print("[TIME] Reporting result took: ", str(time_record["report_result"] - time_record["trim_finish"]), flush=True)

                curr_dynamic_graph.sanity_check()
                curr_dynamic_graph.sanity_check1()
                print("[TIME] finished Sanity check.")
                #time_record["sanity_check"] = time.time()
                #print("[TIME] Sanity check took: ", str(time_record["sanity_check"] - time_record["report_result"]), flush=True)

                curr_dynamic_graph.find_entry_and_exit_nodes()
                curr_dynamic_graph.find_target_nodes(self.starting_insns if insn is None else set([insn]))
                print("[TIME] finished Locating entry&exit&target nodes.")
                #time_record["find_target_nodes"] = time.time()
                #print("[TIME] Locating entry&exit&target nodes took: ",
                #      str(time_record["find_target_nodes"] - time_record["sanity_check"]), flush=True)

                curr_dynamic_graph.build_postorder_list()
                #time_record["postorder"] = time.time()
                #print("[TIME] Postorder traversal took: ",
                #      str(time_record["postorder"] - time_record["find_target_nodes"]), flush=True)

                curr_dynamic_graph.build_reverse_postorder_list()
                #time_record["reverse_postorder"] = time.time()
                #print("[TIME] Reverse postorder traversal took: ",
                #      str(time_record["reverse_postorder"] - time_record["postorder"]), flush=True)
                #if self.init_graph is None:
                #    curr_dynamic_graph.propogate_initial_graph_weight()
                #else:
                #    curr_dynamic_graph.propogate_weight(self.init_graph)

                #time_record["propogate_weight"] = time.time()
                #print("[TIME] Propogating weight took: ",
                #      str(time_record["propogate_weight"] - time_record["reverse_postorder"]), flush=True)
                with open(result_file + "_" + hex(insn), 'w') as f:
                    json.dump(curr_dynamic_graph.toJSON(), f, indent=4, ensure_ascii=False)
                print("[TIME] finished Saving graph in json.")
                #time_record["save_curr_dynamic_graph_as_json"] = time.time()
                #print("[TIME] Saving graph in json took: ",
                #      str(time_record["save_curr_dynamic_graph_as_json"] - time_record["trim_finish"]), flush=True)

                #if self.init_graph is None:
                #    #pass
                #    #dynamic_graph.verify_initial_graph_weight()
                #    dynamic_graph.propogate_initial_graph_weight()
                #else:
                #    dynamic_graph.propogate_weight(self.init_graph)
                #    #dynamic_graph.verify_weight(self.init_graph)
                #    #with open(result_file, 'w') as f:
                #    #    json.dump(dynamic_graph.toJSON(), f, indent=4, ensure_ascii=False)

                print("[dyn_dep] total number of dynamic nodes: " + str(len(curr_dynamic_graph.dynamic_nodes)))
                print("[dyn_dep] total number of target nodes: " + str(len(curr_dynamic_graph.target_nodes)))
        return starting_insn_to_dynamic_graph

    def invoke_preparser(self, insns, curr_dir, pa_id=None, parse_multiple=False):
        preprocess_data = {
            "trace_file": self.trace_path,
            "static_graph_file": StaticDepGraph.result_file,
            "starting_insns": insns,
            "code_to_insn": self.code_to_insn,
            "insns_with_regs": self.insns_with_regs,
            "insn_of_cf_nodes": self.insn_of_cf_nodes,
            "insn_of_df_nodes": self.insn_of_df_nodes,
            "insn_of_local_df_nodes": self.insn_of_local_df_nodes,
            "insn_of_remote_df_nodes": self.insn_of_remote_df_nodes,
            "insn_to_reg_count": self.insn_to_reg_count,
            "insn_to_reg_count2": self.insn_to_reg_count2,
            "load_insn_to_bit_ops": self.load_insn_to_bit_ops,
            "bit_op_to_store_insns": self.bit_op_to_store_insns,
            "max_code_with_static_node": self.max_code_with_static_node
        }
        preprocess_data_file = os.path.join(curr_dir, 'preprocess_data' + ('' if pa_id is None else ('_' + str(pa_id))))
        with open(preprocess_data_file, 'w') as f:
            json.dump(preprocess_data, f, indent=4, ensure_ascii=False)
        # TODO1 invoke the multple if multiple flag is set
        if pa_id is not None and PARALLEL_PREPARSE is True:
            print("Sending request to preparser")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("localhost", 8999))
            s.send(pa_id.to_bytes(1, 'big'))
            s.send("F".encode())
            print("Waiting for reply from preparser")
            read_sockets, _, _ = select.select([s], [], [])
            s = read_sockets[0]
            ret = s.recv(4096).decode().strip()
            print("Getting result from preparser")
            assert (ret == "OK")
            s.close()
        else:
            if parse_multiple is False:
                print("Invoking preprocessor/preprocess")
                preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'preprocess')
            else:
                print("Invoking preprocessor/preprocess_multiple")
                preprocessor_file = os.path.join(curr_dir, 'preprocessor', 'preprocess_multiple')
            cmd = [preprocessor_file]
            if pa_id is not None:
                cmd.append(str(pa_id))
            try:
                pp_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = pp_process.communicate()
            except Exception as e:
                print("Caught exception: " + str(e))
                print(str(e))
                print("-" * 60)
                traceback.print_exc(file=sys.stdout)
                print("-" * 60)
            print(stdout)
            print(stderr)

        with open(self.trace_path + ".parsed" + ('' if pa_id is None else ('_' + str(pa_id))), 'rb') as f:
            byte_seq = f.read()  # more than twice faster than readlines!

        with open(self.trace_path + ".large" + ('' if pa_id is None else ('_' + str(pa_id))), 'rb') as f:
            large = f.readlines()
            codes_to_ignore = set()
            for l in large:
                codes_to_ignore.add(int(l.split()[1]))
        print("[dyn_graph] Codes to ignore are: " + str(codes_to_ignore))

        thread_id_byte_seq = None
        if os.path.exists(self.trace_path + ".parsed_thread_ids" + ('' if pa_id is None else ('_' + str(pa_id)))):
            with open(self.trace_path + ".parsed_thread_ids" + ('' if pa_id is None else ('_' + str(pa_id))), 'rb') as f:
                thread_id_byte_seq = f.read()

        starting_uid_byte_seq = None
        if os.path.exists(self.trace_path + ".starting_uids"):
            with open(self.trace_path + ".starting_uids", 'rb') as f:
                starting_uid_byte_seq = f.read()

        return byte_seq, codes_to_ignore, thread_id_byte_seq, starting_uid_byte_seq

    def build_dynamic_graph(self, starting_insns, byte_seq, codes_to_ignore, thread_id_byte_seq,
                            starting_uid_byte_seq=None):
        # reverse the executetable, and remove insns beyond the start insn
        """
        target_str = str(hex(self.start_insn)) + ": " + str(hex(self.start_insn)) + '\n'
        if target_str in executable:
            index = executable.index(target_str)
            executable = executable[index:]
        else:
            print("There is no target instruction detected during Execution " + str(self.number))
            return
        """
        print(self.insn_to_reg_count)
        print(self.insns_with_regs_set)
        print(self.code_to_insn)
        #insn_id = 2

        dynamic_graph = DynamicGraph(self.starting_events)

        addr_to_df_succe_node = {}
        remote_df_prede_insn_to_succe_node = {}

        load_bit_insns = set()
        for bit_insns in self.load_insn_to_bit_ops.values():
            for bit_insn in bit_insns:
                load_bit_insns.add(bit_insn)

        store_bit_insns = set()
        for bit_insns in self.store_insn_to_bit_ops.values():
            for bit_insn in bit_insns:
                store_bit_insns.add(bit_insn)

        index = 0
        length = len(byte_seq)
        thread_id_index = 0

        other_regs_parsed = False
        print("START: " + str(starting_insns))
        thread_id = None
        ctxt = ParsingContext()
        ctxt_map = {}

        if starting_uid_byte_seq is not None:
            starting_uids = deque()
            if DEBUG_MULTIPLE: starting_uids_set = set()
            starting_uid_index = 0
            starting_uid_byte_seq_len = len(starting_uid_byte_seq)
            while starting_uid_index < starting_uid_byte_seq_len:
                starting_uid = int.from_bytes(starting_uid_byte_seq[starting_uid_index:starting_uid_index + 8], byteorder='little')
                starting_uid_index += 8
                starting_uids.append(starting_uid)
                if DEBUG_MULTIPLE: starting_uids_set.add(starting_uid)
                if DEBUG_MULTIPLE: print("Starting UID: " + str(starting_uid))
            starting_uid = starting_uids.popleft()
        while index < length:
            code = int.from_bytes(byte_seq[index:index + 2], byteorder='little')
            index += 2
            if code == 0:
                prev_thread_id = thread_id
                thread_id = int.from_bytes(thread_id_byte_seq[thread_id_index:thread_id_index + 1], byteorder='little')
                thread_id_index += 1

                # In order to be backward-compatible with single threaded traces,
                # always make a context by default in the first place,
                # only save the context to the map when we get to a new thread.
                if prev_thread_id is None: continue
                ctxt_map[prev_thread_id] = ctxt
                if thread_id in ctxt_map:
                    ctxt = ctxt_map[thread_id]
                else:
                    ctxt = ParsingContext()
                continue

            #print("Code: " + str(code))
            insn = self.code_to_insn[code]
            #print("Addr " + str(insn) + " " + hex(insn))

            parse = False
            is_starting = False
            if insn in starting_insns:
                parse = True
                is_starting = True
            elif insn in ctxt.cf_prede_insn_to_succe_node \
                    or insn in ctxt.local_df_prede_insn_to_succe_node \
                    or insn in remote_df_prede_insn_to_succe_node: #TODO, could optiimze
                parse = True
            if code in codes_to_ignore:
                parse = False

            contains_bit_op = insn in load_bit_insns or insn in store_bit_insns

            if parse is False and contains_bit_op is False:
                index += 8 #for uid
                if insn in self.insns_with_regs_set:
                    index += 8
                if insn in ctxt.bit_insn_to_node:
                    del ctxt.bit_insn_to_node[insn]

                if insn in self.load_insn_to_bit_ops:
                    for bit_insn in self.load_insn_to_bit_ops[insn]:
                        if bit_insn in ctxt.bit_insn_to_operand:
                            del ctxt.bit_insn_to_operand[bit_insn]
                continue

            uid = int.from_bytes(byte_seq[index:index + 8], byteorder='little')
            index += 8

            if insn in self.insns_with_regs_set or contains_bit_op is True:
                reg_value = int.from_bytes(byte_seq[index:index+8], byteorder='little')
                #print("Reg " + hex(reg_value))
                index += 8
            else:
                reg_value = None

            if contains_bit_op is True:
                if other_regs_parsed is True or insn not in self.insns_with_regs_set:
                    other_regs_parsed = False
                    if insn in load_bit_insns:
                        ctxt.bit_insn_to_operand[insn] = reg_value
                    if insn in store_bit_insns:
                        if insn in ctxt.bit_insn_to_node:
                            parent_node = ctxt.bit_insn_to_node[insn]
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
                            #del ctxt.bit_insn_to_node[insn]
                    continue

            if insn in ctxt.bit_insn_to_node:
                del ctxt.bit_insn_to_node[insn]

            #assert (byte_seq[index] == 58)
            #index -= 1
            static_node = self.insn_to_static_node[insn]

            #print(" pending " + str(ctxt.pending_reg_count))
            if ctxt.hasPrevValues is False and insn in self.insn_to_reg_count2:
                #print(insn_line)
                #print("has a load and a store : " + hex(insn))
                if self.insn_to_reg_count2[insn] > 1:
                    #print("has more than one reg ")
                    if ctxt.pending_reg_count == 0:
                        ctxt.pending_reg_count = self.insn_to_reg_count2[insn]
                        ctxt.pending_regs = []
                        #print(" first encountering the insn")
                    if len(ctxt.pending_regs) + 1 < ctxt.pending_reg_count:
                        ctxt.pending_regs.append(reg_value)
                        #print(" not all regs of the insn are accounted for")
                        continue
                    ctxt.pending_reg_count = 0
                else:
                    #print("has just one reg ")
                    ctxt.pending_regs = None
                #print(" all regs of the insn are accounted for " + str(ctxt.pending_regs))
                ctxt.hasPrevValues = True
                ctxt.prev_reg_value = reg_value
                ctxt.prev_pending_regs = None if ctxt.pending_regs is None else list(ctxt.pending_regs)
                continue
            else:
                #print("just one load and a store : " + hex(insn))
                if insn in self.insn_to_reg_count and self.insn_to_reg_count[insn] > 1:
                    #print("has more than one reg ")
                    if ctxt.pending_reg_count == 0:
                        ctxt.pending_reg_count = self.insn_to_reg_count[insn]
                        ctxt.pending_regs = []
                        # print(" first encountering the insn")
                    if len(ctxt.pending_regs) + 1 < ctxt.pending_reg_count:
                        ctxt.pending_regs.append(reg_value)
                        # print(" not all regs of the insn are accounted for")
                        continue
                    # print(" all regs of the insn are accounted for " + str(ctxt.pending_regs))
                    ctxt.pending_reg_count = 0
                else:
                    #print("has just one reg ")
                    ctxt.pending_regs = None

            if contains_bit_op: other_regs_parsed = True

            if starting_uid_byte_seq is not None:
                #Not every starting instruction is one that was sampled,
                # it could be the predecessor of another instruction.
                if is_starting is True:
                    if uid == starting_uid:
                        try:
                            starting_uid = starting_uids.popleft()
                        except IndexError:
                            starting_uid = -1
                            assert len(starting_uids) == 0
                    else:
                        if DEBUG_MULTIPLE:
                            assert uid not in starting_uids_set, \
                            "Expected uid: " + str(starting_uid) + " actual uid:" + str(uid) + " code: " + str(code)
                        is_starting = False

            if insn in remote_df_prede_insn_to_succe_node:
                mem_store_addr = 0
                if static_node.mem_store is not None:
                    if ctxt.hasPrevValues is True:
                        ctxt.hasPrevValues = False
                        mem_store_addr = DynamicGraph.calculate_mem_addr(ctxt.prev_reg_value, static_node.mem_store,
                                                                 None if ctxt.prev_pending_regs is None else ctxt.prev_pending_regs[0])
                        #This is a ugly solution for rep mov when the length is zero, therefore load addr can be zero
                        if reg_value == 0:
                            print("[warn] a rep mov %ds:(%rsi),%es:(%rdi) with dst addr of 0x0? ignore insn " + hex(insn))
                            continue
                    else:
                        mem_store_addr = DynamicGraph.calculate_mem_addr(reg_value, static_node.mem_store,
                                                         None if ctxt.pending_regs is None else ctxt.pending_regs[0])
                ctxt.hasPrevValues = False
                #print("[build] Store " + hex(insn) + " to " + hex(mem_store_addr))
                if (insn not in starting_insns) and (mem_store_addr not in addr_to_df_succe_node):
                    if insn not in ctxt.local_df_prede_insn_to_succe_node:
                        ctxt.hasPrevValues = False

                        if insn in self.load_insn_to_bit_ops:
                            for bit_insn in self.load_insn_to_bit_ops[insn]:
                                if bit_insn in ctxt.bit_insn_to_operand:
                                    del ctxt.bit_insn_to_operand[bit_insn]
                        continue
            ctxt.hasPrevValues = False

            #if insn not in self.insn_to_id:
            #    self.insn_to_id[insn] = insn_id
            #    insn_id += 1

            #dynamic_node = DynamicNode(self.insn_to_id[insn], static_node, id=uid)
            dynamic_node = DynamicNode(0, static_node, id=uid)
            dynamic_node.thread_id = thread_id

            assert dynamic_node.id not in dynamic_graph.dynamic_nodes
            dynamic_graph.insert_node(insn, dynamic_node)

            #if DEBUG:
            print("[dyn_dep] created Dynamic Node id: " + str(dynamic_node.id) \
                  + " Static Node id: " + str(dynamic_node.static_node.id) \
                  + " insn: " + str(dynamic_node.static_node.hex_insn) \
                  + " lines: " + ("" if dynamic_node.static_node.bb is None else str(dynamic_node.static_node.bb.lines)))

            #Note, if a variable has both a load and a store with bit ops
            # the bit mask will be associated to the store
            # and the dataflow will be broken at the load for now
            # as we will not look for further predecessors of the load
            if insn in self.load_insn_to_bit_ops:
                #assert dynamic_node.bit_ops is None
                dynamic_node.bit_ops = {}
                for bit_insn in self.load_insn_to_bit_ops[insn]:
                    if bit_insn in ctxt.bit_insn_to_operand:
                        dynamic_node.bit_ops[bit_insn] = ctxt.bit_insn_to_operand[bit_insn]
                        del ctxt.bit_insn_to_operand[bit_insn] #TODO
                dynamic_node.calculate_load_bit_mask()
            if insn in self.store_insn_to_bit_ops:
                for bit_insn in self.store_insn_to_bit_ops[insn]:
                    ctxt.bit_insn_to_node[bit_insn] = dynamic_node

            if insn in self.starting_insn_to_reg:
                dynamic_node.weight = reg_value if insn not in self.starting_insn_to_weight else self.starting_insn_to_weight[insn]
                dynamic_node.is_valid_weight = True
                dynamic_node.weight_origins.add(dynamic_node.id)
                dynamic_node.weight_paths.add(dynamic_node.static_node.hex_insn + "@" + dynamic_node.static_node.function)
                print("[dyn_dep] Appending weight " + str(reg_value) + " to node with id: " + str(dynamic_node.id))
            """
            if insn not in self.node_frequencies:
                self.node_frequencies[insn] = 0
            self.node_frequencies[insn] = self.node_frequencies[insn] + 1
            """
            if insn in ctxt.cf_prede_insn_to_succe_node:
                to_remove = set()
                for succe in ctxt.cf_prede_insn_to_succe_node[insn]:
                    assert succe.id != dynamic_node.id
                    succe.cf_predes.append(dynamic_node)
                    dynamic_node.cf_succes.append(succe)
                    #assert succe.static_node.id != dynamic_node.static_node.id
                    #assert succe.static_node.insn != dynamic_node.static_node.insn
                    # Only save the closest pred
                    # TODO, what if actually have 2 predecessors

                    for cf_pred in succe.static_node.cf_predes:
                        ni = cf_pred.insn
                        #assert cf_pred.hex_insn == hex(cf_pred.insn)
                        # if ni in ctxt.cf_prede_insn_to_succe_node and succe in ctxt.cf_prede_insn_to_succe_node[ni]:
                        #    ctxt.cf_prede_insn_to_succe_node[ni].remove(succe)
                        to_remove.add(ni)
                if insn in ctxt.cf_prede_insn_to_succe_node:
                    assert insn in to_remove
                for ni in to_remove:
                    if ni in ctxt.cf_prede_insn_to_succe_node:
                        del ctxt.cf_prede_insn_to_succe_node[ni]
                # del ctxt.cf_prede_insn_to_succe_node[insn]

            if insn in ctxt.local_df_prede_insn_to_succe_node:
                to_remove = set()
                for succe in ctxt.local_df_prede_insn_to_succe_node[insn]:
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
                    if ni in ctxt.local_df_prede_insn_to_succe_node:
                        del ctxt.local_df_prede_insn_to_succe_node[ni]


            if insn in remote_df_prede_insn_to_succe_node:
                dynamic_node.mem_store_addr = mem_store_addr
                assert mem_store_addr is not None, str(insn_line) + "\n" + str(dynamic_node)
                # assert mem_store_addr in addr_to_df_succe_node
                if mem_store_addr in addr_to_df_succe_node:
                    to_remove = set()
                    for succe in addr_to_df_succe_node[mem_store_addr]:
                        # HACK: if the src reg is smaller than the dst reg, keep looking for more writes
                        if succe.load_bit_mask is None and succe.static_node.mem_load.read_same_as_write is False:
                            if dynamic_node.static_node not in succe.static_node.df_predes:
                                print("[dyn_dep][warn] Address matched but is not a real predecessor "
                                      + str(succe.static_node.id) + " " + str(dynamic_node.static_node.id))
                                to_remove.add(succe)
                                continue
                        reg_width_match = False
                        dst_reg = succe.static_node.reg_store
                        src_reg = dynamic_node.static_node.reg_load
                        if dst_reg is not None and dst_reg != '' \
                                and src_reg is not None and src_reg != '':
                            dst_reg_size = reg_size_map[dst_reg.lower()]
                            src_reg_size = reg_size_map[src_reg.lower()]
                            if src_reg_size == dst_reg_size:
                                reg_width_match = True
                        else:
                            reg_width_match = True
                        if reg_width_match is False:
                            print("[dyn_dep][warn] one or two nodes do not have a valid register load or store "
                                  + str(succe.static_node.id) + " " + str(succe.static_node.reg_store)
                                  + str(dynamic_node.static_node.id) + " " + str(dynamic_node.static_node.reg_load))
                            continue

                        succe.df_predes.append(dynamic_node)
                        dynamic_node.df_succes.append(succe)
                        if succe.load_bit_mask is not None:
                            continue

                        to_remove.add(succe)
                    for succe in to_remove:
                        addr_to_df_succe_node[mem_store_addr].remove(succe)
                    if len(addr_to_df_succe_node[mem_store_addr]) == 0:
                        del addr_to_df_succe_node[mem_store_addr]

            if DEBUG:
                print("[dyn_dep] created Dynamic Node id: " + str(dynamic_node.id) \
                  + " static cf predes: " + str([p.id for p in dynamic_node.static_node.cf_predes]) \
                  + " static cf succes: " + str([s.id for s in dynamic_node.static_node.cf_succes]))
                print("[dyn_dep] created Dynamic Node id: " + str(dynamic_node.id) \
                  + " dynamic cf predes: " + str([p.static_node.id for p in dynamic_node.cf_predes]) \
                  + " dynamic cf succes: " + str([s.static_node.id for s in dynamic_node.cf_succes]))

            if starting_uid_byte_seq is not None:
                # We just want to parse one level of the dependencies from starting instructions.
                if is_starting is False:
                    continue
                else:
                    dynamic_node.is_starting = True
            # If a static node has both dataflow and control-flow successors, then it is probably not a branch
            # if so, and if the node has not dataflow successor, and only control flow successor,
            # then there is not need to further examine and dataflow predecessors.
            has_df_succes = True
            if len(static_node.df_succes) > 0 and len(static_node.cf_succes) > 0 and len(dynamic_node.df_succes) == 0:
                has_df_succes = False

            # If a node has the read_same_as_write flag set, then it may have a dataflow predecessor that is not examined
            # then we just use the store address as the load addresses and further look for datalfow predecessors.
            loads_memory = True if static_node.mem_load is not None else False
            #FIXME: df_predes can never be None
            if has_df_succes and static_node.df_predes or (loads_memory and static_node.mem_load.read_same_as_write):  # and insn not in self.insn_of_df_nodes_set:
                for prede in static_node.df_predes:
                    node_insn = prede.insn
                    if node_insn not in self.insn_of_df_nodes_set and node_insn not in self.insn_of_cf_nodes_set:  # Slice is not always complete
                        continue
                    # When we encounter a dataflow predecessor later,
                    # know which successors to connect to
                    if loads_memory is False:
                        if node_insn not in ctxt.local_df_prede_insn_to_succe_node:
                            ctxt.local_df_prede_insn_to_succe_node[node_insn] = {dynamic_node}
                        else:
                            ctxt.local_df_prede_insn_to_succe_node[node_insn].add(dynamic_node)
                    else:
                        if node_insn not in remote_df_prede_insn_to_succe_node:
                            remote_df_prede_insn_to_succe_node[node_insn] = {dynamic_node}
                        else:
                            remote_df_prede_insn_to_succe_node[node_insn].add(dynamic_node)

                if loads_memory is True:
                    #reg_value = result[1].rstrip('\n')
                    mem_load_addr = DynamicGraph.calculate_mem_addr(reg_value, static_node.mem_load,
                                                            None if ctxt.pending_regs is None else ctxt.pending_regs[0])
                    dynamic_node.mem_load_addr = mem_load_addr
                    # TODO, do all addresses make sense?
                    if mem_load_addr not in addr_to_df_succe_node:
                        addr_to_df_succe_node[mem_load_addr] = []
                    addr_to_df_succe_node[mem_load_addr].append(dynamic_node)
                    #print("[build] Load " + hex(insn) + " to " + hex(mem_load_addr) + " adding to pending nodes")

            # FIXME: cf_predes can never be None, no need for the test
            if static_node.cf_predes:  # and insn not in self.insn_of_df_nodes_set:
                for prede in static_node.cf_predes:
                    node_insn = prede.insn
                    if node_insn not in self.insn_of_df_nodes_set and node_insn not in self.insn_of_cf_nodes_set:  # Slice is not always complete
                        continue
                        # When we encounter a control predecessor later,
                        # know which successors to connect to
                    if node_insn not in ctxt.cf_prede_insn_to_succe_node:
                        ctxt.cf_prede_insn_to_succe_node[node_insn] = {dynamic_node}
                    else:
                        ctxt.cf_prede_insn_to_succe_node[node_insn].add(dynamic_node)
        return dynamic_graph
    
    def compare_graphs(self, graph_name1, graph_name2, insn):
        graph1 = DynamicGraph.load_graph_from_json(graph_name1)
        graph2 = DynamicGraph.load_graph_from_json(graph_name2)
        nodes1 = graph1.insn_to_dyn_nodes[insn]
        nodes2 = graph2.insn_to_dyn_nodes[insn]
        assert len(nodes1) == len(nodes2), str(len(nodes1)) + " " + str(len(nodes2))
        node_ids1 = set()
        for n in nodes1:
            node_ids1.add(n.id)

        node_ids2 = set()
        id_to_node2 = {}
        for n in nodes2:
            node_ids2.add(n.id)
            id_to_node2[n.id] = n

        #assert node_ids1 == node_ids2
        for n1 in nodes1:
            print(n1.id)
            assert n1.id in node_ids2
            n2 = id_to_node2[n1.id]
            print(n2.id)

            cf_predes_ids1 = set()
            for p in n1.cf_predes:
                cf_predes_ids1.add(p.id)

            cf_predes_ids2 = set()
            for p in n2.cf_predes:
                cf_predes_ids2.add(p.id)
                assert n2 in p.cf_succes
            print(str(cf_predes_ids1))
            print(str(cf_predes_ids2))
            assert cf_predes_ids1 == cf_predes_ids2, str(cf_predes_ids1) + " " + str(cf_predes_ids2)

            df_predes_ids1 = set()
            for p in n1.df_predes:
                df_predes_ids1.add(p.id)

            df_predes_ids2 = set()
            for p in n2.df_predes:
                df_predes_ids2.add(p.id)
                assert n2 in p.df_succes
            assert df_predes_ids1 == df_predes_ids2, str(df_predes_ids1) + " " + str(df_predes_ids2)



class ParsingContext:
    def __init__(self):
        self.pending_reg_count = 0
        self.pending_regs = None #TODO, actually can have at most one pending reg????

        self.hasPrevValues = False
        self.prev_pending_regs = None
        self.prev_reg_value = None

        #TODO
        self.cf_prede_insn_to_succe_node = {}
        self.local_df_prede_insn_to_succe_node = {}
        self.bit_insn_to_operand = {}
        self.bit_insn_to_node = {}

class DynamicGraph:
    # TODO: restructure DynamicGraph
    def __init__(self, starting_events):
        self.starting_events = starting_events
        self.starting_insns = set()
        for event in starting_events:
            curr_insn = event[1]
            self.starting_insns.add(curr_insn)

        self.insn_to_id = {}
        self.dynamic_nodes = OrderedDict()
        self.target_dir = os.path.join(curr_dir, 'dynamicGraph')
        self.node_frequencies = {}
        self.postorder_list = []
        self.reverse_postorder_list = []
        self.entry_nodes = set()
        self.exit_nodes = set()
        self.target_nodes = set()
        self.insn_to_dyn_nodes = {}
        self.id_to_node = {} #TODO, obselete now
        self.reachable_output_events_per_static_node = None
        self.result_file = None

    def toJSON(self):
        data = {}
        data["starting_events"] = self.starting_events
        #data["insn_to_id"] = self.insn_to_id

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

        if self.reachable_output_events_per_static_node is not None:
            json_reachable_output_events_per_static_node = {}
            for k in self.reachable_output_events_per_static_node:
                json_reachable_output_events_per_static_node[k] = [dn.id for dn in self.reachable_output_events_per_static_node[k]]
            data["reachable_output_events_per_static_node"] = json_reachable_output_events_per_static_node
        return data

    @staticmethod
    def fromJSON(data, static_id_to_node):
        dg = DynamicGraph(data["starting_events"])
        #dg.insn_to_id = data["insn_to_id"]

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

        #Fixme: is this obselete?
        #if "insn_to_static_node" in data:
        #    dg.insn_to_static_node = {}
        #    for func in func_to_graph:
        #        for node in func_to_graph[func].nodes_in_cf_slice.keys():
        #            dg.insn_to_static_node[node.insn] = node
        #        for node in func_to_graph[func].nodes_in_df_slice.keys():
        #            dg.insn_to_static_node[node.insn] = node

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
        if "reachable_output_events_per_static_node" in data:
            dg.reachable_output_events_per_static_node = {}
            json_reachable_output_events_per_static_node = data["reachable_output_events_per_static_node"]
            for json_k in json_reachable_output_events_per_static_node:
                k = int(json_k)
                dg.reachable_output_events_per_static_node[k] = set()
                for dn_id in json_reachable_output_events_per_static_node[json_k]:
                    dg.reachable_output_events_per_static_node[k].add(id_to_node[dn_id])
        return dg

    @staticmethod
    def load_graph_from_json(result_file):
        print("Reading from file:" + result_file)
        with open(result_file, 'r') as f:
            in_result = json.load(f)
            static_id_to_node = {}
            for graph in StaticDepGraph.func_to_graph.values():
                for sn in graph.id_to_node.values():
                    static_id_to_node[sn.id] = sn
            dynamic_graph = DynamicGraph.fromJSON(in_result, static_id_to_node)
            dynamic_graph.result_file = result_file
            return dynamic_graph

    """
    def groupNodesByInsn(self):
        for node in self.dynamic_nodes.values():
            insn = node.static_node.insn
            if insn not in self.insn_to_dyn_nodes:
                self.insn_to_dyn_nodes[insn] = set()
            self.insn_to_dyn_nodes[insn].add(node)
    """

    def insert_node(self, insn, node):
        assert node.static_node.insn == insn
        self.dynamic_nodes[node.id] = node
        if insn not in self.insn_to_dyn_nodes:
            self.insn_to_dyn_nodes[insn] = set()
        self.insn_to_dyn_nodes[insn].add(node)
        self.id_to_node[node.id] = node

    def print_node(self, prefix, n):
        print(prefix
              + " d_id: " + str(n.id) + " s_id: " + str(n.static_node.id)
              + " insn: " + n.static_node.hex_insn + " lines: " + str(n.static_node.bb.lines)
              + " cf ps: " + str([pp.id for pp in n.cf_predes])
              + " df ps: " + str([pp.id for pp in n.df_predes])
              + " cf ss: " + str([ps.id for ps in n.cf_succes])
              + " df ss: " + str([ps.id for ps in n.df_succes]))

    def build_reverse_and_none_reverse_postorder_list_helper(self, reverse):
        if reverse is True:
            self.reverse_postorder_list = []
        else:
            self.postorder_list = []

        q = deque()
        visited = set()
        for node in reversed(list(self.entry_nodes if reverse is False else self.exit_nodes)):
            q.appendleft([node, None])
        while len(q) > 0:
            (node, parent) = q.popleft()
            #print()
            #if node is not None:
            #    self.print_node("visiting ", node)
            #if parent is not None:
            #    self.print_node("parent is", parent)
            if parent is not None:
                if parent in visited:
                    continue
                visited.add(parent)
                if reverse is True:
                    self.reverse_postorder_list.append(parent)
                else:
                    self.postorder_list.append(parent)
                continue
            if node in visited:
                continue
            nodes = []
            for n in (node.cf_succes if reverse is False else node.cf_predes):
                nodes.append([n, None])
                #self.print_node("appending child ", n)
            for n in (node.df_succes if reverse is False else node.df_predes):
                nodes.append([n, None])
                #self.print_node("appending child ", n)
            if len(nodes) > 0:
                nodes.append([None, node])
                for n in reversed(nodes):
                    q.appendleft(n)
            else:
                if node in visited:
                    continue
                visited.add(node)

                if reverse is True:
                    self.reverse_postorder_list.append(node)
                else:
                    self.postorder_list.append(node)

    def build_postorder_list(self): #TODO, refactor one day and combine into one function
        self.build_reverse_and_none_reverse_postorder_list_helper(False)
        print("[dyn_graph] number of nodes in the postorder list: " + str(len(self.postorder_list)))
        #visited = set()
        #for node in self.postorder_list:
        #    #print(node.id)
        #    for s in node.cf_succes:
        #        assert s in visited, str(s.id) + " " +str(node.id)
        #    for s in node.df_succes:
        #        assert s in visited, str(s.id) + " " + str(node.id)
        #    visited.add(node)

    def build_reverse_postorder_list(self): #TODO, refactor one day and combine into one function
        self.build_reverse_and_none_reverse_postorder_list_helper(True)
        print("[dyn_graph] number of nodes in the reverese postorder list: " + str(len(self.reverse_postorder_list)))
        #visited = set()
        #for node in self.reverse_postorder_list:
        #    #print(node.id)
        #    for s in node.cf_predes:
        #        assert s in visited, str(s.id) + " " + str(node.id)
        #    for s in node.df_predes:
        #        assert s in visited, str(s.id) + " " + str(node.id)
        #    visited.add(node)

    # a node can be visited if all its predecessors are visited
    def build_reverse_postorder_list_old(self): #TODO, refactor one day and combine into one function
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
    def build_postorder_list_old(self):
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

    def sanity_check1(self):
        for n in self.dynamic_nodes.values():
            assert n in self.insn_to_dyn_nodes[n.static_node.insn]
        for nodes in self.insn_to_dyn_nodes.values():
            for n in nodes:
                assert n == self.dynamic_nodes[n.id], str(n.id)

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
                    print("TRIM Do not consider the load for bit vars: " + str(df_prede.id))
            for df_prede in to_remove:
                dnode.df_predes.remove(df_prede)
                df_prede.df_succes.remove(dnode)
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
            if len(self.insn_to_dyn_nodes[node.static_node.insn]) == 0:
                del self.insn_to_dyn_nodes[node.static_node.insn]

    def report_result(self):
        """
        print("[Report] the top 5 nodes that appeared the most number of times: ")
        top_five_insn = sorted(self.node_frequencies.items(), key=lambda d: d[1], reverse=True)[:5]
        i = 1
        for item in top_five_insn:
            insn = item[0]
            times = item[1]
            node = node.static_node
            string = "  No." + str(i) + ":\n"
            string += "     static_node id: " + str(node.id) + "\n"
            string += "     frequence: " + str(times) + "\n"
            string += "     insn addr: " + insn + "\n"
            string += "     src line: " + str(node.bb.lines) + "\n\n"
            i = i + 1

            print(string)
        """
        print("[Report]There are a total of " + str(len(self.dynamic_nodes)) + " nodes.")

    @staticmethod
    def calculate_mem_addr(reg_value, expr, off_reg_value=None): #TODO, why not move this into the dynamic node object?
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

        if expr.off1 is not None:
            addr = addr + expr.off1
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

    def verify_initial_graph_weight(self):
        bad_count = 0
        good_count = 0
        bad_nodes = set()
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
            """
            if target.weight == -1:
                bad_count += 1
                bad_nodes.add(target.id)
            else:
                good_count += 1
            """
            if target.weight != node.weight:
                #print("---------------------------------------------")
                #print("---------------------------------------------")
                #print(str(target) + "\n" + str(node))
                bad_count += 1
                bad_nodes.add(target.id)
            else:
                good_count += 1
        print("GRAPH SUMMARY0 initial 0x407240 weight propogated to 0x4071c9 correctly: " + str(good_count) + " bad: " + str(bad_count) + " " + str(bad_nodes))

        bad_count = 0
        good_count = 0
        bad_nodes = set()
        for node in self.insn_to_dyn_nodes[0x40742b]:
            target = node
            for prede in target.cf_predes:
                if prede.static_node.insn == 0x4073f4:
                    target = prede

            assert target.static_node.insn == 0x4073f4
            """
            if target.weight == -1:
                bad_count += 1
                bad_nodes.add(target.id)
            else:
                good_count += 1
            """
            if target.weight != node.weight:
                #print("---------------------------------------------")
                #print("---------------------------------------------")
                #print(str(target) + "\n" + str(node))
                bad_count += 1
                bad_nodes.add(target.id)
            else:
                good_count += 1
        print("GRAPH SUMMARY0 initial 0x40742b weight propogated to 0x4073f4 correctly: " + str(good_count) + " bad: " + str(bad_count) + " " + str(bad_nodes))

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
        nodes_not_equal = set()
        for node in self.insn_to_dyn_nodes[0x4071c9]:
            ref_node = reference.id_to_node[node.id]
            if node.weight == ref_node.weight:
                good_count += 1
            else:
                bad_count += 1
                nodes_not_equal.add(node.id)
        #print("GRAPH SUMMARY1 subsequent 0x4071c9 equal to initial graph: " + str(good_count) + " bad: " + str(bad_count) + " " + str(nodes_not_equal))

        good_count = 0
        bad_count = 0
        broken_count = 0
        connected_count = 0
        disconnected_nodes = set()
        not_equal_nodes = {}
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
            found = False
            for prede in target.cf_predes:
                if prede.static_node.insn == 0x4071c9:
                    target = prede
                    found = True
            if found is False:
                for prede in target.cf_predes:
                    if prede.static_node.insn == 0x40745d:
                        target = prede
                for prede in target.cf_predes:
                    if prede.static_node.insn == 0x4073f4:
                        target = prede
            if target.static_node.insn != 0x4071c9 and target.static_node.insn != 0x4073f4:
                print("Broken0 at " + target.static_node.hex_insn)
                broken_count += 1
                disconnected_nodes.add(node.id)
            else:
                connected_count += 1
                if node.weight == target.weight:
                    good_count += 1
                else:
                    bad_count += 1
                    not_equal_nodes[target.id] = node.id
        print("GRAPH SUMMARY2      0x40a6aa connected to 0x4071c9 or 0x4073f4: " + str(connected_count) + " bad: " + str(broken_count) + " " + str(disconnected_nodes))
        print("GRAPH SUMMARY3    0x40a6aa weight same as 0x4071c9 or 0x4073f4: " + str(good_count) + " bad: " + str(bad_count) + " " + str(not_equal_nodes))

        good_count = 0
        bad_count = 0
        broken_count = 0
        connected_count = 0
        mark_allocated_weighted = 0
        mark_allocated_not_weighted = 0
        bit_weight_same_as_ptr = 0
        bit_weight_diff_than_ptr = 0
        bad_addrs = {}
        x4093c6_not_collected = {}

        bit_weight_same_as_ptr_ignore_invalid = 0
        bit_weight_diff_than_ptr_ignore_invalid = 0
        bad_addrs_ignore_invalid = {}
        for succe_node in self.insn_to_dyn_nodes[0x4093f0]:
            node = None
            for prede in succe_node.df_predes:
                if prede.static_node.insn == 0x4096d4:
                    node = prede
            if node is None:
                for prede in succe_node.df_predes:
                    if prede.static_node.insn == 0x4093c6:
                        node = prede
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
                if hex(node.mem_load_addr) not in x4093c6_not_collected:
                    x4093c6_not_collected[hex(node.mem_load_addr)] = []
                x4093c6_not_collected[hex(node.mem_load_addr)].append(node.id)
            else:
                connected_count += 1
                if node.weight == target.weight:
                    good_count += 1
                else:
                    bad_count += 1
                if target.weight == -1:
                    mark_allocated_not_weighted += 1
                else:
                    mark_allocated_weighted += 1
                    if target.weight == cf_target.weight:
                        bit_weight_same_as_ptr += 1
                        bit_weight_same_as_ptr_ignore_invalid += 1
                    else:
                        if cf_target.weight == -1:
                            bit_weight_same_as_ptr_ignore_invalid += 1
                        else:
                            bit_weight_diff_than_ptr_ignore_invalid += 1
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
                            pass
                            #print("SUMMARY warn: " + str(pointer_def.id))
                        else:
                            pointer_def = pointer_def.df_predes[0]
                            key = pointer_def.static_node.hex_insn + "@" + pointer_def.static_node.function
                            if key not in bad_addrs:
                                bad_addrs[key] = 0
                            bad_addrs[key] = bad_addrs[key] + 1
                            if cf_target.weight != -1:
                                if key not in bad_addrs_ignore_invalid:
                                    bad_addrs_ignore_invalid[key] = 0
                                bad_addrs_ignore_invalid[key] = bad_addrs_ignore_invalid[key] + 1

        print("GRAPH SUMMARY4  0x4093c6 connected to   0x40a6aa: " + str(connected_count) + " bad: " + str(broken_count) + " " + str(x4093c6_not_collected))
        print("GRAPH SUMMARY5  0x4093c6 weight same as 0x40a6aa: " + str(good_count) + " bad: " + str(bad_count))
        print("GRAPH SUMMARY5.1  0x40a6aa has valid weight     : " + str(mark_allocated_weighted) + " bad: " + str(mark_allocated_not_weighted))
        print("GRAPH SUMMARY5.2  0x40a6aa wt same as ptr       : " + str(bit_weight_same_as_ptr) + " bad: " + str(bit_weight_diff_than_ptr))
        print("GRAPH SUMMARY5.2 " + str(len(bad_addrs)) + " " + str(bad_addrs))
        print("GRAPH SUMMARY5.2  0x40a6aa wt same as ptr ignore: " + str(bit_weight_same_as_ptr_ignore_invalid) + " bad: " + str(bit_weight_diff_than_ptr_ignore_invalid))
        print("GRAPH SUMMARY5.2 " + str(len(bad_addrs_ignore_invalid)) + " " + str(bad_addrs_ignore_invalid))
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
        forward_weight_paths = None
        nodes = set()
        nodes.add(node)
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
            if forward_weight_paths is None:
                forward_weight_paths = list(succe_or_prede.forward_weight_paths)
            elif len(succe_or_prede.forward_weight_paths) < len(forward_weight_paths):
                forward_weight_paths = list(succe_or_prede.forward_weight_paths)
            #forward_weight_paths = forward_weight_paths.union(succe_or_prede.forward_weight_paths)
        return weights, weight_origins, weight_paths, forward_weight_paths

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
                #print("in reference graph")
                if reference.id_to_node[node.id].is_valid_weight is False:
                    assert reference.id_to_node[node.id].weight == -1
                    continue
                #print("has valid weight")
                ref_node = reference.id_to_node[node.id]
                node.weight = ref_node.weight
                node.weight_origins = set(ref_node.weight_origins)
                node.weight_paths = set(ref_node.weight_paths)
                node.forward_weight_paths.append(node.static_node.hex_insn + "@" + node.static_node.function + "_" + str(node.id))
                node.is_valid_weight = True
                assert node.weight != -1

        aggregate_static_node_ids = set()
        for i in range(0,1):
            for node in self.postorder_list:  # a node will be visited only if its successors have all been visited
                weights, weight_origins, weight_paths, forward_weight_paths = self.propogate_weight_at_node(node, True)
                if len(weights) > 1:
                    weights, weight_origins, weight_paths, forward_weight_paths = self.propogate_weight_at_node(node, True, ignore_cycle=True)
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
            #for node in self.insn_to_dyn_nodes[0x4071c9]: #TODO, remove this hack!
            #    node.is_aggregate_weight = False
            #    if node.static_node.id in aggregate_static_node_ids:
            #        aggregate_static_node_ids.remove(node.static_node.id)

            for node in self.reverse_postorder_list:  # a node will be visited only if its predecessors have all been visited
                #if node.is_valid_weight is True:
                #    assert node.weight != -1
                #    continue
                weights, weight_origins, weight_paths, forward_weight_paths = self.propogate_weight_at_node(node, False,
                                                                                      check_aggregation=True, aggregate_static_node_ids=aggregate_static_node_ids)
                if len(weights) > 1:
                    weights, weight_origins, weight_paths, forward_weight_paths = self.propogate_weight_at_node(node, False,
                                                                                          check_aggregation=True, aggregate_static_node_ids=aggregate_static_node_ids,
                                                                                          ignore_cycle=True)
                if len(weights) > 1:
                    weights, weight_origins, weight_paths, forward_weight_paths = self.propogate_weight_at_node(node, False,
                                                                                          check_aggregation=True, aggregate_static_node_ids=aggregate_static_node_ids,
                                                                                          ignore_cycle=True, ignore_cf=True)
                #if len(weights) == 0:
                #    if node.static_node.is_df is True:
                #        weights, weight_origins, weight_paths = self.propogate_weight_at_node(node, False,
                #                                                                              ignore_cycle=True,
                #                                                                              ignore_cf=True)
                if len(weights) > 1:
                    node.weight = -1
                    node.is_valid_weight = False
                    node.is_aggregate_weight = True
                    node.static_node.print_node("Do not aggregate weights: " + str(node.id) + " " + str(weights))
                    continue
                if len(weights) > 0:
                    #weight_paths.add(node.static_node.hex_insn + "@" + node.static_node.function)
                    forward_weight_paths.append(node.static_node.hex_insn + "@" + node.static_node.function + "_" + str(node.id))
                    node.weight_origins = weight_origins
                    node.weight_paths = weight_paths
                    node.forward_weight_paths = forward_weight_paths
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

    def find_paths_to(self, prede_insn):
        path_count = 0
        target_insns = set()
        for target in self.target_nodes:
            target_insns.add(target.static_node.insn)
        for curr in self.insn_to_dyn_nodes[prede_insn]:
            q = deque()
            q.appendleft([curr, deque(), 0])
            while len(q) > 0:
                n, l, le = q.popleft()
                while len(l) > le:
                    l.pop()
                l.append(n)
                for s in itertools.chain(n.df_succes, n.cf_succes):
                    if s.static_node.insn in target_insns:
                        print("*****************************************")
                        print("                PATH  # " + str(path_count))
                        print("                length: " + str(len(l) + 1))
                        for pn in l:
                            print(pn)
                        print(s)
                        print("*****************************************")
                        path_count += 1
                        continue
                    q.appendleft([s, l, len(l)])

    def calc_avg_time_stamp(self):
        insn_to_time_stamp = {}
        for insn in self.insn_to_dyn_nodes:
            nodes = self.insn_to_dyn_nodes[insn]
            count = 1
            avg = 0
            for n in nodes:
                avg += (n.id - avg)/count
                count += 1
            insn_to_time_stamp[insn] = avg
        return insn_to_time_stamp

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

def verify_0x409418_result(dg):
        # sizes = {}
    # with open("weight", "r") as f:
    #    lines = f.readlines()
    #    for l in lines:
    #        segs = l.split()
    #        addr = int(segs[0], 16)
    #        if addr in sizes:
    #            if sizes[addr] != segs[1]:
    #                print(segs[1])
    #                print(sizes[addr])
    #        #print("HERE1 " + hex(addr))
    #        sizes[addr] = segs[1]

    total_weight = 0
    # for addr in sizes:
    #    total_weight+= int(sizes[addr])

    addr_not_explained = set()
    addr_explained = set()
    prede_found = 0
    prede_not_found = 0
    prede_not_found_weight = 0
    connected_predes = {}
    connected_predes_not_connected_to_malloc = {}
    connected_predes_not_connected_to_malloc1 = {}
    from_malloc = 0
    addr_from_malloc = set()
    node_to_weight = {}
    connected_count = 0
    for n in dg.insn_to_dyn_nodes[0x409379]:
        sw = deque()
        sw.append(n)
        visited = set()
        while len(sw) > 0:
            sc = sw.popleft()
            if sc in visited:
                continue
            visited.add(sc)
            if sc.static_node.insn == 0x409418:
                node_to_weight[n] = sc.weight
                """
                if sc.mem_load_addr in sizes:
                    node_to_weight[n] = sizes[sc.mem_load_addr]
                else:
                    node_to_weight[n] = 0
                """
                # print("FOUND SUCCE")
                break
            for scs in sc.df_succes:
                sw.append(scs)
            for scs in sc.cf_succes:
                sw.append(scs)

        total_weight += int(node_to_weight[n])
        if len(n.df_predes) == 0:
            prede_not_found += 1
            addr_not_explained.add(hex(n.mem_load_addr))
            prede_not_found_weight += node_to_weight[n]
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
                # 0x408038
                if c.static_node.insn == 0x4072e5:  # or c.static_node.insn == 0x408447: # or c.static_node.insn ==  0x4072e5:
                    addr_from_malloc.add(hex(n.mem_load_addr))
                    if len(malloc_nodes) == 0:
                        from_malloc += 1
                    malloc_nodes.add(c.id)
                    connected_to_malloc = True
                    # break TODO
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
                connected_predes_not_connected_to_malloc[p.static_node] = \
                    connected_predes_not_connected_to_malloc[p.static_node] + int(node_to_weight[n])  # + 1
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
    sn = StaticDepGraph.get_graph('scanblock', 4232057).insn_to_node[4232057]
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
    # total_not_connected = 0
    for p in connected_predes:
        print(p.mem_store)
        p.print_node(" connected:  ")
        # print(" count: " + str(connected_predes[p]))
        # total_not_connected += connected_predes[p]
    # print( " TOTAL COUNT: " + str(total_not_connected))
    # print( " % " + str(total_not_connected/total_weight))
    print("==============================")
    total_not_connected = 0
    for p in connected_predes_not_connected_to_malloc:
        print(p.mem_store)
        p.print_node(" connected but not to malloc:  ")
        print(" count: " + str(connected_predes_not_connected_to_malloc[p]))
        print(" % : " + str(connected_predes_not_connected_to_malloc[p] / total_weight * 100))
        print(" addrs : " + str(connected_predes_not_connected_to_malloc1[p]))
        total_not_connected += connected_predes_not_connected_to_malloc[p]
    print(" TOTAL WEIGHT connected but not to malloc: " + str(total_not_connected))
    print(" % " + str(total_not_connected / total_weight * 100))
    print(" TOTAL WEIGHT connected to malloc: " + str(connected_count))
    print(" % " + str(connected_count / total_weight * 100))
    print(" TOTAL WEIGHT not connected at all: " + str(prede_not_found_weight))
    print(" % " + str(prede_not_found_weight / total_weight * 100))
    print("==============================")
    for p in sn.df_predes:
        if p in connected_predes:
            continue
        print(p.mem_store)
        p.print_node(" not found:  ")
    # with open(os.path.join(curr_dir, 'predes'), 'w') as f:
    #    json.dump(predes, f, indent=4, ensure_ascii=False)

if __name__ == '__main__':
    start = time.time()
    #FIXME: dynamic graph logic will always reused already built dynamic graph, 
    # there is currently no option to rebuild forcefully
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--parallelize_id', dest='pa_id', type=int)
    parser.add_argument('-i', '--starting_instruction', dest='starting_insn')

    parser.add_argument('-m', '--generate_multiple', dest='generate_multiple', action='store_true')
    parser.add_argument('-mc', '--generate_multiple_in_context', dest='generate_multiple_in_context', action='store_true')
    parser.add_argument('-if', '--multiple_insns_file', dest='multiple_insns_file', type=str)

    parser.add_argument('-c', '--compare', dest='compare', action='store_true')
    parser.add_argument('-f1', '--graph_file1', dest='graph_file1', type=str)
    parser.add_argument('-f2', '--graph_file2', dest='graph_file2', type=str)

    parser.add_argument('-c1', '--detect_dyn_callees', dest='detect_dyn_callees', action='store_true')
    parser.set_defaults(detect_dyn_callees=False)
    parser.add_argument('-c2', '--parse_dyn_callees', dest='parse_dyn_callees', action='store_true')
    parser.set_defaults(parse_dyn_callees=False)

    parser.add_argument('-s', '--generate_summary', dest='generate_summary', action='store_true')
    parser.set_defaults(generate_summary=False)

    parser.add_argument('-f', '--find_paths_to', dest='find_paths_to')
    
    args = parser.parse_args()
    print("Parallel execution id is: " + str(args.pa_id))
    print("Optional starting instruction is: " + str(args.starting_insn))

    limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()

    dd = DynamicDependence(starting_events, program, program_args, program_path, starting_insn_to_weight=starting_insn_to_weight)

    if args.detect_dyn_callees is True:
        dd.detect_dynamic_callees_run_trace()
    elif args.parse_dyn_callees is True:
        dd.detect_dynamic_callees_parse_trace()
    elif args.compare is True:
        dd.prepare_to_build_dynamic_dependencies(limit)
        dd.compare_graphs(args.graph_file1, args.graph_file2, int(args.starting_insn, 16))
    elif args.generate_multiple is True:
        assert args.generate_multiple_in_context is False
        dd.prepare_to_build_dynamic_dependencies(limit)
        multiple_insns = []
        with open(args.multiple_insns_file, "r") as f:
            for l in f.readlines():
                multiple_insns.append(int(l.strip()))
        dd.build_multiple_dynamic_dependencies(multiple_insns)
    elif args.generate_multiple_in_context is True:
        assert args.generate_multiple is False
        dd.prepare_to_build_dynamic_dependencies(limit)
        multiple_insns = []
        with open(args.multiple_insns_file, "r") as f:
            for l in f.readlines():
                multiple_insns.append(int(l.strip()))
        dd.build_multiple_dynamic_dependencies_in_context(int(args.starting_insn, 16), multiple_insns)
    else:
        dd.prepare_to_build_dynamic_dependencies(limit)
        starting_insns = []
        if args.starting_insn is None:
            for event in starting_events:
                starting_insns.append(event[1])
        else:
            starting_insns.append(int(args.starting_insn, 16))

        for starting_insn in starting_insns:
            dg = dd.build_dynamic_dependencies(starting_insn, args.pa_id)

            if args.generate_summary is True:
                print("[dg] Generating summaries")
                summary = {}
                for n in dg.dynamic_nodes.values():
                    insn = n.static_node.insn
                    s = summary.get(insn, None)
                    if s == None:
                        s = set()
                        summary[insn] = s
                    for succe in itertools.chain(n.cf_succes, n.df_succes):
                       s.add(succe.static_node.insn) 
                result_file = os.path.join(curr_dir, 'cache', program, hex(starting_insn) + "_summary")
                json_summary = {}
                for insn in summary:
                    json_summary[insn] = list(summary[insn])
                with open(result_file, 'w') as f:
                    json.dump(json_summary, f, indent=4, ensure_ascii=False)
            if args.find_paths_to is not None:
                prede_insn = int(args.find_paths_to, 16)
                dg.find_paths_to(prede_insn)
    end = time.time()
    print("[dyn_graph] Total time: " + str(end - start))
