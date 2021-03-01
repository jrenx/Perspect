import json
import os
from util import *

class BasicBlock:
    def __init__(self, id, ends_in_branch):
        # TODO: if we call Dyninst twice, are the Basic block IDs guaranteed to be the same?
        self.id = id
        self.start_insn = None
        self.last_insn = None
        self.ends_in_branch = ends_in_branch
        self.predes = []
        self.succes = []

    def add_start_insn(self, start_insn):
        self.start_insn = start_insn

    def add_last_insn(self, last_insn):
        self.last_insn = last_insn

    def add_predecessors(self, predes):
        self.predes = predes

    def add_successors(self, succes):
        self.succes = succes

    def __str__(self):
        s = "     BB id: " + str(self.id) + "\n"
        s += "      first insn addr: " + str(self.start_insn) + "\n"
        s += "      last  insn addr: " + str(self.last_insn) + "\n"
        s += "      last insn is branch: " + str(self.ends_in_branch) + "\n"
        s += "      predecessors: ["
        for prede in self.predes:
            s += str(prede.id) + ","
        s = s.strip(",")
        s += "] \n"
        s += "      successors: ["
        for succe in self.succes:
            s += str(succe.id) + ","
        s = s.strip(",")
        s += "] \n"
        return s

class CFG:
    def __init__(self):
        self.all_bbs = {}

    def get_first_insn_of_every_block(self):
        insns = []
        for bb_id in self.all_bbs:
            bb = self.all_bbs[bb_id]
            insns.append(bb.start_insn)
        return insns

    def get_last_insn_of_every_block(self):
        insns = []
        for bb_id in self.all_bbs:
            bb = self.all_bbs[bb_id]
            insns.append(bb.last_insn)
        return insns

    def get_last_nsn_of_every_block_if_is_branch(self):
        insns = []
        for bb_id in self.all_bbs:
            bb = self.all_bbs[bb_id]
            if bb.ends_in_branch is True:
                insns.append(bb.last_insn)
        return insns

    def build_partial_cfg(self, insn, func, prog):
        json_bbs = getAllPredes(insn, func, prog)

        for json_bb in json_bbs:
            bb_id = int(json_bb['id'])
            ends_in_branch = False
            if int(json_bb['ends_in_branch']) == 1:
                ends_in_branch = True
            bb = BasicBlock(bb_id, ends_in_branch)

            start_insn = int(json_bb['start_insn'])
            bb.add_start_insn(start_insn)
            last_insn = int(json_bb['end_insn'])
            bb.add_last_insn(last_insn)

            self.all_bbs[bb_id] = bb

        for json_bb in json_bbs:
            bb_id = int(json_bb['id'])
            json_predes = json_bb['predes']
            predes = []
            for json_prede in json_predes:
                prede_id = int(json_prede['id'])
                predes.append(self.all_bbs[prede_id])
            self.all_bbs[bb_id].add_predecessors(predes)

            json_succes = json_bb['succes']
            succes = []
            for json_succe in json_succes:
                succe_id = int(json_succe['id'])
                succes.append(self.all_bbs[succe_id])
            self.all_bbs[bb_id].add_successors(succes)

        for bb_id in self.all_bbs:
            print(self.all_bbs[bb_id])


class MemoryLoad:
    def __init__(self, reg, shift, off):
        self.reg = reg
        self.shift = shift
        self.off = off

    def __str__(self):
        s = "Memory load: " + str(self.reg) + " * " \
            + str(self.shift) + " + " + str(self.off)
        return s


class StaticNode:
    id = 0

    def __init__(self, insn, bb):
        self.id = StaticNode.id
        StaticNode.id += 1
        self.insn = insn

        ##### for control flow #####
        self.bb = bb
        self.cf_predes = []
        self.cf_succes = []

        #####   for dataflow   #####
        # Inside each function, do not record the actual register for now
        # if a node has dataflow predecessors, it means it uses a reg
        # and the node that is the predecessor, which has dataflow successors defines the reg
        # There are 3 possibilities for the predecessor
        # 1. a constant 2. function parameter 3. memory load
        # "mem_load" describes the address of the memory load
        self.mem_load = None
        self.df_predes = []
        self.df_succes = []

    def __str__(self):
        s = "===============================================\n"
        s += "   Node id: " + str(self.id) + "\n"
        s += "      insn: " + str(self.insn) + "\n"
        s += "    ------------Basic Block--------------\n"
        if self.bb is None:
            s += "\n"
        else:
            s += str(self.bb)
        s += "    -------------------------------------\n"
        s += "    control flow predecessors: ["
        for prede in self.cf_predes:
            s += str(prede.id) + ","
        s = s.strip(",")
        s += "] \n"
        s += "    control flow successors: ["
        for succe in self.cf_succes:
            s += str(succe.id) + ","
        s = s.strip(",")
        s += "] \n"

        if self.mem_load is not None:
            s += "    " + str(self.mem_load)

        s += "    dataflow predecessors: ["
        for prede in self.df_predes:
            s += str(prede.id) + ","
        s = s.strip(",")
        s += "] \n"
        s += "    dataflow successors: ["
        for succe in self.df_succes:
            s += str(succe.id) + ","
        s = s.strip(",")
        s += "] \n"
        return s

class StaticDepGraph:
    def __init__(self):
        self.id_to_node = {}
        self.insn_to_node = {}

    def make_node(self, insn, bb):
        if insn in self.insn_to_node:
            return self.insn_to_node[insn]
        node = StaticNode(insn, bb)
        self.id_to_node[node.id] = node
        self.insn_to_node[insn] = node
        return node

    def buildDependencies(self, insn, func, prog):
        self.buildControlFlowDependencies(insn, func, prog)
        self.buildDataFlowDependencies(func, prog)

    def buildDataFlowDependencies(self, func, prog):
        reg_to_addr = []
        addr_to_node = {}
        for node_id in self.id_to_node:
            node = self.id_to_node[node_id]
            bb = node.bb
            if bb.ends_in_branch is False:
                continue
            insn = bb.last_insn
            print(hex(insn))
            reg_to_addr.append(["", insn])
            assert insn not in addr_to_node
            addr_to_node[insn] = node
        results = static_backslices(reg_to_addr, func, prog)
        for result in results:
            #reg_name = result[0]
            insn = result[1]
            loads = result[2]
            if loads is None:
                continue

            succe = addr_to_node[insn]
            for load in loads:
                prede_insn = load[0]
                prede_reg = load[1]
                shift = load[2]
                off = load[3]

                prede = self.make_node(prede_insn, None)
                prede.mem_load = MemoryLoad(prede_reg, shift, off)
                succe.df_predes.append(prede)
                prede.df_succes.append(succe)

        for node_id in self.id_to_node:
            print(str(self.id_to_node[node_id]))

    def buildControlFlowDependencies(self, insn, func, prog):
        cfg = CFG()
        cfg.build_partial_cfg(insn, func, prog)

        bb_id_to_node_id = {}

        first = True
        #TODO, might want to keep trap of the starting instruction
        for bb_id in cfg.all_bbs:
            bb = cfg.all_bbs[bb_id]
            assert bb_id == bb.id
            if first:
                node = self.make_node(insn, bb)
                first = False
            else:
                node = self.make_node(bb.last_insn, bb)

            bb_id_to_node_id[bb_id] = node.id

        for bb_id in cfg.all_bbs:
            bb = cfg.all_bbs[bb_id]
            node_id = bb_id_to_node_id[bb_id]
            node = self.id_to_node[node_id]
            for prede in bb.predes:
                prede_node_id = bb_id_to_node_id[prede.id]
                node.cf_predes.append(self.id_to_node[prede_node_id])
            for succe in bb.succes:
                succe_node_id = bb_id_to_node_id[succe.id]
                node.cf_succes.append(self.id_to_node[succe_node_id])
        for node_id in self.id_to_node:
            print(str(self.id_to_node[node_id]))

        return cfg

if __name__ == "__main__":

    static_graph = StaticDepGraph()
    static_graph.buildDependencies(0x409c55, "sweep", "909_ziptest_exe9")