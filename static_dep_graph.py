import json
import os
from sa_util import *
from rr_util import *
from pin_util import *
from collections import deque
from collections import OrderedDict

class BasicBlock:
    def __init__(self, id, ends_in_branch, is_entry, lines):
        # Note: if we call Dyninst twice, the Basic block IDs will change
        self.id = id
        self.start_insn = None
        self.last_insn = None
        self.lines = lines
        self.ends_in_branch = ends_in_branch
        self.is_entry = is_entry
        self.immed_dom = None
        self.immed_pdom = None
        self.pdoms = None
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
        if self.immed_dom is not None:
            s += "      immediate dominator: " + str(self.immed_dom.id) + "\n"
        if self.immed_pdom is not None:
            s += "      immediate post dominator: " + str(self.immed_pdom.id) + "\n"
        s += "      post dominators: "
        if self.pdoms is not None:
            s += str([pdom.id for pdom in self.pdoms])
        s += " \n"

        s += "      predecessors: ["
        s += str([prede.id for prede in self.predes])
        s += "] \n"
        s += "      successors: ["
        s += str([succe.id for succe in self.succes])
        s += "] \n"
        s += "      backedge targets: ["
        s += str([target.id for target in self.backedge_targets])
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

        postorder_map = {}
        for i in range(len(self.postorder_list)):
            postorder_map[self.postorder_list[i].id] = i

        print("[Simplify] Postorder list: " + str([bb.id for bb in self.postorder_list]))
        bb_id_to_pdom_ids = {}
        for bb in self.postorder_list:
            print("[Simplify] Examining: " + str(bb.id))
            pdom_ids = None
            for succe in bb.succes:
                print("[Simplify]      current succe : " + str(succe.id))
                if succe.id not in bb_id_to_pdom_ids:
                    continue
                if pdom_ids is None:
                    pdom_ids = set(bb_id_to_pdom_ids[succe.id])
                else:
                    pdom_ids = pdom_ids.intersection(bb_id_to_pdom_ids[succe.id])
                print("[Simplify]      current pdom : " + str(pdom_ids))
            if pdom_ids is None:
                pdom_ids = set()
            pdom_ids.add(bb.id)
            bb_id_to_pdom_ids[bb.id] = pdom_ids
        #for bb_id in bb_id_to_pdom_ids:
            #print("[Simplify] " + str(bb_id) + " is post dominated by: " + str(bb_id_to_pdom_ids[bb_id]))

        print("[Simplify] " + str(postorder_map))
        for bb in self.postorder_list:
            pdom_ids = bb_id_to_pdom_ids[bb.id]
            pdom_ids.remove(bb.id)
            if len(pdom_ids) == 0:
                continue

            bb.pdoms = []
            for pdom_id in pdom_ids:
                bb.pdoms.append(self.id_to_bb[pdom_id])

            print("[Simplify] BB " + str(bb.id) + "@" + str(bb.lines) + " " \
                    " is post dominated by: " + \
                    str([pdom.id for pdom in bb.pdoms]))

            pdom_id_to_range = {}
            for pdom_id in pdom_ids:
                pdom_id_to_range[postorder_map[pdom_id]] = pdom_id
            for pdom_id_pair in reversed(sorted(pdom_id_to_range.items())):
                bb.immed_pdom = self.id_to_bb[pdom_id_pair[1]]
                break
            print("[Simplify] BB " + str(bb.id) + "@" + str(bb.lines) + " " \
                    " is immediately post dominated by: " + \
                    str(bb.immed_pdom.id))

        ignore_set = set() # call it ignore set
        for bb in reversed(self.postorder_list):
            print("[Simplify] can BB: " + str(bb.id) + " " + str(bb.lines) + " be removed? immed pdom is " \
                  + (str(bb.immed_pdom.id) if bb.immed_pdom is not None else str(bb.immed_pdom)))
            if bb.immed_pdom is None:
                print("[Simplify]   BB has no immed pdom")
                continue

            if bb.immed_pdom.id not in self.id_to_bb_in_slice:
                print("[Simplify]   immed pdom not in slice")
                continue

            if bb in ignore_set:
                print("[Simplify]   BB is already removed or cannot be removed")
                continue
            all_succes_before_immed_pdom = set()
            worklist = deque()
            worklist.append(bb)
            while len(worklist) > 0:
                child_bb = worklist.popleft()
                print("[Simplify]   child BB: " + str(child_bb.id) + \
                      " " + str(child_bb.lines) + \
                      " pdoms are " + str([pdom.id for pdom in child_bb.pdoms] \
                        if child_bb.pdoms is not None else str(child_bb.pdoms)))
                if child_bb is bb.immed_pdom:
                    print("[Simplify]   child: " + str(child_bb.id) + \
                          " is the immed pdom: " + str(bb.immed_pdom.id))
                    continue
                assert bb.immed_pdom in child_bb.pdoms
                all_succes_before_immed_pdom.add(child_bb)
                for succe in child_bb.succes:
                    worklist.append(succe)

            if self.target_bb in all_succes_before_immed_pdom:
                ignore_set.union(all_succes_before_immed_pdom)
                continue

            #remove_set.add(bb) not really needed
            for prede in bb.predes:
                prede.succes.remove(bb)
                if bb.immed_pdom not in prede.succes:
                    prede.succes.append(bb.immed_pdom)
                if prede not in bb.immed_pdom.predes:
                    bb.immed_pdom.predes.append(prede)
            for child_bb in all_succes_before_immed_pdom:
                print("[Simplify] Removing BB: " + str(child_bb.id) + " " + str(child_bb.lines))
                if child_bb in bb.immed_pdom.predes:
                    bb.immed_pdom.predes.remove(child_bb)
                del self.id_to_bb_in_slice[child_bb.id]
                self.ordered_bbs_in_slice.remove(child_bb)
                ignore_set.add(child_bb)

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

        print("=======================================================")
        for bb in self.ordered_bbs_in_slice:
            print(str(bb))
        assert len(self.id_to_bb_in_slice) == len(self.ordered_bbs_in_slice), \
            str(len(self.id_to_bb_in_slice)) + " " + str(len(self.ordered_bbs_in_slice))
        print("Total number of basic blocks after slicing: " + str(len(self.ordered_bbs_in_slice)))

        self.simplify()

        print("=======================================================")
        for bb in self.ordered_bbs_in_slice:
            print(str(bb))
        print("Total number of basic blocks after simplifying: " + str(len(self.ordered_bbs_in_slice)))

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

            lines = []
            for json_line in json_bb['lines']:
                lines.append(int(json_line['line']))

            bb = BasicBlock(bb_id, ends_in_branch, is_entry, lines)
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

            immed_dom_id = None
            if 'immed_dom' in json_bb:
                immed_dom_id = int(json_bb['immed_dom'])
                bb.immed_dom = self.id_to_bb[immed_dom_id]

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
        s += "      insn: " + str(hex(self.insn)) + "\n"
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
        self.nodes_in_cf_slice = []
        self.nodes_in_df_slice = []

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
        for node in self.nodes_in_cf_slice:
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
                if prede not in self.nodes_in_df_slice:
                    self.nodes_in_df_slice.append(prede)
                prede.mem_load = MemoryLoad(prede_reg, shift, off)
                succe.df_predes.append(prede)
                prede.df_succes.append(succe)

        for node in self.nodes_in_df_slice:
            print(str(node))
        print("Total number of nodes in local dataflow slice: " + str(len(self.nodes_in_df_slice)))

    def buildControlFlowDependencies(self, insn, func, prog):
        cfg = CFG(func, prog)
        cfg.slice(insn)

        bb_id_to_node_id = {}

        first = True
        #TODO, might want to keep trap of the starting instruction
        for bb in cfg.ordered_bbs:
            if first:
                node = self.make_node(insn, bb)
                first = False
            else:
                node = self.make_node(bb.last_insn, bb)
                #TODO,does it matter if we use the first instruction instead?
            bb_id_to_node_id[bb.id] = node.id
            if bb.id in cfg.id_to_bb_in_slice:
                self.nodes_in_cf_slice.append(node)

        for bb_id in cfg.id_to_bb:
            bb = cfg.id_to_bb[bb_id]
            node_id = bb_id_to_node_id[bb_id]
            node = self.id_to_node[node_id]
            for prede in bb.predes:
                prede_node_id = bb_id_to_node_id[prede.id]
                node.cf_predes.append(self.id_to_node[prede_node_id])
            for succe in bb.succes:
                succe_node_id = bb_id_to_node_id[succe.id]
                node.cf_succes.append(self.id_to_node[succe_node_id])
        for node in self.nodes_in_cf_slice:
            print(str(node))
        print("Total number of nodes in control flow slice: " + str(len(self.nodes_in_cf_slice)))
        return cfg

if __name__ == "__main__":

    static_graph = StaticDepGraph()
    static_graph.buildDependencies(0x409daa, "sweep", "909_ziptest_exe9")
