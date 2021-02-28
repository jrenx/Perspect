import json
import os
from util import *

class BasicBlock:
    def __init__(self, id, ends_in_branch):
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


class StaticNode:
    id = 0
    def __init__(self, bb):
        self.id = StaticNode.id
        StaticNode.id += 1
        self.bb = bb

        self.cf_predes = []
        self.cf_succes = []

        self.defs = None
        self.uses = None

    def __str__(self):
        s = "   Node id: " + str(self.id) + "\n"
        s += "    ------------Basic Block--------------\n"
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
        return s

class StaticDepGraph:
    def __init__(self):
        self.nodes = {}

    def convert(self, cfg):
        bb_id_to_node_id = {}

        for bb_id in cfg.all_bbs:
            bb = cfg.all_bbs[bb_id]
            assert bb_id == bb.id
            node = StaticNode(bb)
            self.nodes[node.id] = node
            bb_id_to_node_id[bb_id] = node.id

        for bb_id in cfg.all_bbs:
            bb = cfg.all_bbs[bb_id]
            node_id = bb_id_to_node_id[bb_id]
            node = self.nodes[node_id]
            for prede in bb.predes:
                prede_node_id = bb_id_to_node_id[prede.id]
                node.cf_predes.append(self.nodes[prede_node_id])
            for succe in bb.succes:
                succe_node_id = bb_id_to_node_id[succe.id]
                node.cf_succes.append(self.nodes[succe_node_id])
        for node_id in self.nodes:
            print(str(self.nodes[node_id]))

if __name__ == "__main__":
    cfg = CFG()
    cfg.build_partial_cfg(0x409c55, "sweep", "909_ziptest_exe9")
    print(cfg.get_first_insn_of_every_block())

    #static_graph = StaticDepGraph()
    #static_graph.convert(cfg)

    #reg_to_addr.append(["", 4234200])
    #static_backslices(reg_to_addr, "sweep", "909_ziptest_exe9")

    reg_to_addr = []
    for insn in cfg.get_last_nsn_of_every_block_if_is_branch():
        print(hex(insn))
        reg_to_addr.append(["", insn])

    static_backslices(reg_to_addr, "sweep", "909_ziptest_exe9")


