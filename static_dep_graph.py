import json
import os
from util import *
from collections import deque

class BasicBlock:
    def __init__(self, id, ends_in_branch, is_entry, immed_dom, lines):
        # Note: if we call Dyninst twice, the Basic block IDs will change
        self.id = id
        self.start_insn = None
        self.last_insn = None
        self.lines = lines
        self.ends_in_branch = ends_in_branch
        self.is_entry = is_entry
        self.immed_dom = immed_dom
        self.backedge_targets = []
        self.predes = []
        self.succes = []

    def add_start_insn(self, start_insn):
        self.start_insn = start_insn

    def add_last_insn(self, last_insn):
        self.last_insn = last_insn

    def __str__(self):
        s = "     BB id: " + str(self.id) + "\n"
        s += "      first insn addr: " + str(hex(self.start_insn)) + "\n"
        s += "      last  insn addr: " + str(hex(self.last_insn)) + "\n"
        s += "      source lines: " + str(self.lines) + "\n"
        s += "      last insn is branch: " + str(self.ends_in_branch) + "\n"
        s += "      is entry: " + str(self.is_entry) + "\n"
        s += "      immediate dominator: " + str(self.immed_dom) + "\n"
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
        s += "      backedge targets: ["
        for target in self.backedge_targets:
            s += str(target.id) + ","
        s = s.strip(",")
        s += "] \n"
        return s

class CFG:
    def __init__(self, func, prog):
        self.func = func
        self.prog = prog

        self.id_to_bb = {}
        self.ordered_bbs = []

        self.id_to_bb_in_slice = {}
        self.ordered_bbs_in_slice = []

        self.target_bb = None
        self.entry_bbs = []
        self.postorder_list = []

    '''
    def get_first_insn_of_every_block(self):
        insns = []
        for bb_id in self.id_to_bb:
            bb = self.id_to_bb[bb_id]
            insns.append(bb.start_insn)
        return insns

    def get_last_insn_of_every_block(self):
        insns = []
        for bb_id in self.id_to_bb:
            bb = self.id_to_bb[bb_id]
            insns.append(bb.last_insn)
        return insns

    def get_last_nsn_of_every_block_if_is_branch(self):
        insns = []
        for bb_id in self.id_to_bb:
            bb = self.id_to_bb[bb_id]
            if bb.ends_in_branch is True:
                insns.append(bb.last_insn)
        return insns
    '''

    def traversalHelper(self, bb):
        #print(" Traversing bb: " + str(bb.id))
        print("[Postorder] Current bb: " + str(bb.id) + " " + str(bb.lines))
        for succe in bb.succes:
            print("[Postorder] Examining succe: " + str(succe.id) + " " + str(succe.lines))
            if succe in self.postorder_list: #TODO use a set?
                print("[Postorder] Skipping cuz already in list")
                continue
            if succe in bb.backedge_targets:
                print("[Postorder] Skipping cuz is backedge")
                continue
            if succe.id not in self.id_to_bb_in_slice:
                if succe not in self.postorder_list:
                    self.postorder_list.append(succe)
                print("[Postorder] Skipping cuz is not in slice")
                continue
            self.traversalHelper(succe)
        if bb not in self.postorder_list:
            self.postorder_list.append(bb)

    def simplify(self):
        for entry in self.entry_bbs:
            self.traversalHelper(entry)
        postorder_bb_id_list = []
        for bb in self.postorder_list:
            postorder_bb_id_list.append(bb.id)
        print("[Simplify] Postorder list: " + str(postorder_bb_id_list))
        bb_id_to_pdom_ids = {}
        for bb in self.postorder_list:
            print("[Simplify] Examining: " + str(bb.id))
            pdoms = None
            for succe in bb.succes:
                print("[Simplify]      current succe : " + str(succe.id))
                if succe.id not in bb_id_to_pdom_ids:
                    continue
                if pdoms is None:
                    pdoms = set(bb_id_to_pdom_ids[succe.id])
                else:
                    pdoms = pdoms.intersection(bb_id_to_pdom_ids[succe.id])
                print("[Simplify]      current pdom : " + str(pdoms))
            if pdoms is None:
                pdoms = set()
            pdoms.add(bb.id)
            bb_id_to_pdom_ids[bb.id] = pdoms
        #for bb_id in bb_id_to_pdom_ids:
            #print("[Simplify] " + str(bb_id) + " is post dominated by: " + str(bb_id_to_pdom_ids[bb_id]))
        for bb in self.postorder_list:
            pdoms = bb_id_to_pdom_ids[bb.id]
            pdoms.remove(bb.id)
            if len(pdoms) == 0:
                continue

            print("[Simplify] BB " + str(bb.id) + "@" + str(bb.lines) + " " \
                    " is post dominated by: " + \
                    str(pdoms))
            for prede in bb.predes:
                prede.succes.remove(bb)
                prede.succes.extend(bb.succes)
            for succe in bb.succes:
                succe.predes.remove(bb)
                succe.predes.extend(bb.predes)
            del self.id_to_bb_in_slice[bb.id]
            self.ordered_bbs_in_slice.remove(bb)

        raise Exception

    def slice(self, insn):
        self.build_cfg(insn)

        # https://stackoverflow.com/questions/35206372/understanding-stacks-and-queues-in-python/35206452
        worklist = deque()
        worklist.append(self.target_bb)
        while len(worklist) > 0:
            bb = worklist.popleft()
            if bb.id in self.id_to_bb_in_slice:
                print("Already visited: " + str(bb.id))
                continue

            print("Adding bb to slice: " + str(bb.id))
            self.id_to_bb_in_slice[bb.id] = bb
            self.ordered_bbs_in_slice.append(bb)
            for prede in bb.predes:
                #if bb in prede.backedge_targets:
                #    print("  Ignoring prede " + str(prede.id) + "because it is part of a backedge")
                #    continue
                worklist.append(prede)
        for bb in self.ordered_bbs_in_slice:
            print(str(bb))
        assert len(self.id_to_bb_in_slice) == len(self.ordered_bbs_in_slice), \
            str(len(self.id_to_bb_in_slice)) + " " + str(len(self.ordered_bbs_in_slice))
        print("Total number of basic blocks after slicing: " + str(len(self.ordered_bbs_in_slice)))

        self.simplify()

    def build_cfg(self, insn):
        json_bbs = getAllBBs(insn, self.func, self.prog)

        for json_bb in json_bbs:
            bb_id = int(json_bb['id'])

            ends_in_branch = False
            if int(json_bb['ends_in_branch']) == 1:
                ends_in_branch = True

            is_entry = False
            if int(json_bb['is_entry']) == 1:
                is_entry = True

            immed_dom = None
            if 'immed_dom' in json_bb:
                immed_dom = int(json_bb['immed_dom'])

            lines = []
            for json_line in json_bb['lines']:
                lines.append(int(json_line['line']))

            bb = BasicBlock(bb_id, ends_in_branch, is_entry, immed_dom, lines)
            if self.target_bb is None:
                self.target_bb = bb
            if is_entry:
                self.entry_bbs.append(bb)

            start_insn = int(json_bb['start_insn'])
            bb.add_start_insn(start_insn)
            last_insn = int(json_bb['end_insn'])
            bb.add_last_insn(last_insn)

            self.id_to_bb[bb_id] = bb
            self.ordered_bbs.append(bb)

        for json_bb in json_bbs:
            bb_id = int(json_bb['id'])
            json_predes = json_bb['predes']
            predes = []
            for json_prede in json_predes:
                prede_id = int(json_prede['id'])
                predes.append(self.id_to_bb[prede_id])
            self.id_to_bb[bb_id].predes = predes

            json_succes = json_bb['succes']
            succes = []
            for json_succe in json_succes:
                succe_id = int(json_succe['id'])
                succes.append(self.id_to_bb[succe_id])
            self.id_to_bb[bb_id].succes = succes

            if 'backedge_targets' in json_bb:
                json_backedge_targets = json_bb['backedge_targets']
                backedge_targets = []
                for json_backedge_target in json_backedge_targets:
                    backedge_target_id = int(json_backedge_target['id'])
                    backedge_targets.append(self.id_to_bb[backedge_target_id])
                self.id_to_bb[bb_id].backedge_targets = backedge_targets

        for bb in self.ordered_bbs:
            print(str(bb))
        assert len(self.id_to_bb) == len(self.ordered_bbs), \
            str(len(self.id_to_bb)) + " " + str(len(self.ordered_bbs))
        print("Total number of basic blocks in the entire cfg: " + str(len(self.ordered_bbs)))


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
        print("Total number of nodes: " + str(len(self.id_to_node)))

    def buildControlFlowDependencies(self, insn, func, prog):
        cfg = CFG(func, prog)
        cfg.slice(insn)

        bb_id_to_node_id = {}

        first = True
        #TODO, might want to keep trap of the starting instruction
        for bb in cfg.ordered_bbs_in_slice:
            if first:
                node = self.make_node(insn, bb)
                first = False
            else:
                node = self.make_node(bb.last_insn, bb)

            bb_id_to_node_id[bb.id] = node.id

        for bb_id in cfg.id_to_bb_in_slice:
            bb = cfg.id_to_bb_in_slice[bb_id]
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
        print("Total number of nodes: " + str(len(self.id_to_node)))
        return cfg

if __name__ == "__main__":

    static_graph = StaticDepGraph()
    static_graph.buildDependencies(0x409daa, "sweep", "909_ziptest_exe9")