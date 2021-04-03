import json
import os
import os.path
from sa_util import *
from rr_util import *
from pin_util import *
from collections import deque
from collections import OrderedDict

DEBUG_CFG = False
DEBUG_SIMPLIFY = False
DEBUG_SLICE = False
VERBOSE = False
curr_dir = os.path.dirname(os.path.realpath(__file__))


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
        self.backedge_sources = []
        self.predes = []
        self.succes = []

    def toJSON(self):
        data = {}
        data["id"] = self.id
        data["start_insn"] = self.start_insn
        data["last_insn"] = self.last_insn
        data["lines"] = self.lines
        data["ends_in_branch"] = self.ends_in_branch
        data["is_entry"] = self.is_entry
        if self.immed_dom:
            data["immed_dom"] = self.immed_dom.id
        if self.immed_pdom:
            data["immed_pdom"] = self.immed_pdom.id
        if self.pdoms:
            data["pdoms"] = []
            for n in self.pdoms:
                data["pdoms"].append(n.id)

        data["backedge_targets"] = []
        for n in self.backedge_targets:
            data["backedge_targets"].append(n.id)

        data["backedge_sources"] = []
        for n in self.backedge_sources:
            data["backedge_sources"].append(n.id)

        data["predes"] = []
        for n in self.predes:
            data["predes"].append(n.id)

        data["succes"] = []
        for n in self.succes:
            data["succes"].append(n.id)
        return data

    @staticmethod
    def fromJSON(data):
        id = data['id']
        ends_in_branch = data['ends_in_branch']
        is_entry = data['is_entry']
        lines = data['lines']
        bb = BasicBlock(id, ends_in_branch, is_entry, lines)
        bb.start_insn = data['start_insn']
        bb.last_insn = data['last_insn']
        bb.lines = data['lines']
        bb.ends_in_branch = data['ends_in_branch']
        bb.is_entry = data['is_entry']

        if 'immed_dom' in data:
            bb.immed_dom = data['immed_dom']
        if 'immed_pdom' in data:
            bb.immed_pdom = data['immed_pdom']
        if 'pdoms' in data:
            bb.pdoms = data['pdoms']
        bb.backedge_targets = data['backedge_targets']
        bb.predes = data['predes']
        bb.succes = data['succes']
        return bb

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

        s += "      predecessors: "
        s += str([prede.id for prede in self.predes])
        s += " \n"
        s += "      successors: "
        s += str([succe.id for succe in self.succes])
        s += " \n"
        s += "      backedge targets: "
        s += str([target.id for target in self.backedge_targets])
        s += " \n"
        s += "      backedge sources: "
        s += str([source.id for source in self.backedge_sources])
        s += " \n"
        return s


class CFG:
    def __init__(self, func, prog):
        self.func = func
        self.prog = prog

        self.id_to_bb = {} #Includes all the Basic Blocks in the function
        self.ordered_bbs = [] #Includes all the Basic Blocks in the function

        self.id_to_bb_in_slice = {} #Includes only the Basic Blocks in the slice
        self.ordered_bbs_in_slice = [] #Includes only the Basic Blocks in the slice

        self.target_bbs = set()
        self.entry_bbs = []
        self.postorder_list = []

        self.built = False
        self.sliced = False

    def toJSON(self):
        data = {}
        data["func"] = self.func
        data["prog"] = self.prog

        data["ordered_bbs"] = []
        for n in self.ordered_bbs:
            data["ordered_bbs"].append(n.toJSON())

        data["ordered_bbs_in_slice"] = []
        for n in self.ordered_bbs_in_slice:
            data["ordered_bbs_in_slice"].append(n.id)

        data["target_bbs"] = []
        for n in self.target_bbs:
            data["target_bbs"].append(n.id)

        data["entry_bbs"] = []
        for n in self.entry_bbs:
            data["entry_bbs"].append(n.id)

        data["postorder_list"] = []
        for n in self.postorder_list:
            data["postorder_list"].append(n.id)

        data["built"] = self.built
        data["sliced"] = self.sliced
        return data

    @staticmethod
    def fromJSON(data):
        func = data["func"]
        prog = data["prog"]

        cfg = CFG(func, prog)

        for n in data["ordered_bbs"]:
            bb = BasicBlock.fromJSON(n)
            cfg.ordered_bbs.append(bb)
            cfg.id_to_bb[bb.id] = bb

        for bb in cfg.ordered_bbs:
            if bb.immed_dom:
                bb.immed_dom = cfg.id_to_bb[bb.immed_dom]

            if bb.immed_pdom:
                bb.immed_pdom = cfg.id_to_bb[bb.immed_pdom]

            if bb.pdoms:
                pdoms = []
                for id in bb.pdoms:
                    pdoms.append(cfg.id_to_bb[id])
                bb.pdoms = pdoms

            backedge_targets = []
            for id in bb.backedge_targets:
                backedge_targets.append(cfg.id_to_bb[id])
            bb.backedge_targets = backedge_targets

            predes = []
            for id in bb.predes:
                predes.append(cfg.id_to_bb[id])
            bb.predes = predes

            succes = []
            for id in bb.succes:
                succes.append(cfg.id_to_bb[id])
            bb.succes = succes

        for n in data["ordered_bbs_in_slice"]:
            cfg.id_to_bb_in_slice[n] = cfg.id_to_bb[n]
            cfg.ordered_bbs_in_slice.append(cfg.id_to_bb[n])

        for n in data["target_bbs"]:
            cfg.target_bbs.add(cfg.id_to_bb[n])

        for n in data["entry_bbs"]:
            cfg.entry_bbs.append(cfg.id_to_bb[n])

        for n in data["postorder_list"]:
            cfg.postorder_list.append(cfg.id_to_bb[n])

        cfg.built = data["built"]
        cfg.sliced = data["sliced"]
        return cfg

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
    def getBB(self, insn):
        for bb in self.ordered_bbs:
            if bb.start_insn <= insn <= bb.last_insn:
                return bb
        print("bb for " + hex(insn) + " not found")
        raise Exception
        #return None

    def postorderTraversal(self, bb, visited):
        #print(" Traversing bb: " + str(bb.id))
        if DEBUG_SIMPLIFY: print("[Postorder] Current bb: " + str(bb.id) + " " + str(bb.lines))
        for succe in bb.succes:
            if DEBUG_SIMPLIFY: print("[Postorder] Examining succe: " + str(succe.id) + " " + str(succe.lines))
            if succe in visited:
                if DEBUG_SIMPLIFY: print("[Postorder] Skipping cuz visited")
                continue
            if succe in bb.backedge_targets:
                if DEBUG_SIMPLIFY: print("[Postorder] Skipping cuz is backedge")
                continue
            visited.add(succe)
            """
            if succe.id not in self.id_to_bb_in_slice:
                if succe not in self.postorder_list:
                    self.postorder_list.append(succe)
                if DEBUG_SIMPLIFY: print("[Postorder] Skipping cuz is not in slice")
                continue
            """
            self.postorderTraversal(succe, visited)
        if bb not in self.postorder_list:
            self.postorder_list.append(bb)

    def simplify(self, final=False):
        for entry in self.entry_bbs:
            visited = set([])
            self.postorderTraversal(entry, visited)

        postorder_map = {}
        for i in range(len(self.postorder_list)):
            postorder_map[self.postorder_list[i].id] = i

        if DEBUG_SIMPLIFY: print("[Simplify] Postorder list: " + str([bb.lines for bb in self.postorder_list]))
        if DEBUG_SIMPLIFY: print("[Simplify] Postorder list: " + str([bb.id for bb in self.postorder_list]))
        bb_id_to_pdom_ids = {}

        retry = True
        while retry:
            retry = False
            for bb in self.postorder_list:
                if DEBUG_SIMPLIFY: print("[Simplify] Examining: " + str(bb.id))
                pdom_ids = None
                for succe in bb.succes:
                    if DEBUG_SIMPLIFY: print("[Simplify]      current succe : " + str(succe.id))
                    if succe.id not in bb_id_to_pdom_ids:
                        if succe in bb.backedge_targets:
                            retry = True
                            if DEBUG_SIMPLIFY: print("[Simplify]      ignoring, is a backedge ")
                        continue
                    if pdom_ids is None:
                        pdom_ids = set(bb_id_to_pdom_ids[succe.id])
                    else:
                        pdom_ids = pdom_ids.intersection(bb_id_to_pdom_ids[succe.id])
                    if DEBUG_SIMPLIFY: print("[Simplify]      current pdom : " + str(pdom_ids))
                if pdom_ids is None:
                    pdom_ids = set()
                pdom_ids.add(bb.id)
                bb_id_to_pdom_ids[bb.id] = pdom_ids
        #for bb_id in bb_id_to_pdom_ids:
            #print("[Simplify] " + str(bb_id) + " is post dominated by: " + str(bb_id_to_pdom_ids[bb_id]))

        if DEBUG_SIMPLIFY: print("[Simplify] " + str(postorder_map))
        for bb in self.postorder_list:
            pdom_ids = bb_id_to_pdom_ids[bb.id]
            pdom_ids.remove(bb.id)
            bb.pdoms = []
            if len(pdom_ids) == 0:
                continue

            for pdom_id in pdom_ids:
                bb.pdoms.append(self.id_to_bb[pdom_id])

            if DEBUG_SIMPLIFY: print("[Simplify] BB " + str(bb.id) + "@" + str(bb.lines) + " " \
                    " is post dominated by: " + \
                    str([pdom.lines for pdom in bb.pdoms]))

            bb_id_to_range = {}
            for pdom_id in pdom_ids:
                bb_id_to_range[postorder_map[pdom_id]] = pdom_id
            bb_id_to_range[postorder_map[bb.id]] = bb.id
            if DEBUG_SIMPLIFY: print("[Simplify] ordered post dominators: " + \
                    str([self.id_to_bb[bb_id_pair[1]].lines for bb_id_pair in reversed(sorted(bb_id_to_range.items()))]))

            for bb_id_pair in reversed(sorted(bb_id_to_range.items())):
                bb.immed_pdom = self.id_to_bb[bb_id_pair[1]]
                break

            found = False
            for bb_id_pair in reversed(sorted(bb_id_to_range.items())):
                if found is True:
                    bb.immed_pdom = self.id_to_bb[bb_id_pair[1]]
                    break
                if bb.id == bb_id_pair[1]:
                    found = True

            if DEBUG_SIMPLIFY: print("[Simplify] BB " + str(bb.id) + "@" + str(bb.lines) + " " \
                    " is immediately post dominated by: " + \
                    str(bb.immed_pdom.lines))

        remove_count = 0
        ignore_set = set() # call it ignore set
        updated_set = set()
        for bb in reversed(self.postorder_list):
            if DEBUG_SIMPLIFY: print("[Simplify] can BB: " + str(bb.id) + " " + str(bb.lines) + " be removed? immed pdom is " \
                  + (str(bb.immed_pdom.id) if bb.immed_pdom is not None else str(bb.immed_pdom)) + " "\
                  + (str(bb.immed_pdom.lines) if bb.immed_pdom is not None else str(bb.immed_pdom)))
            if bb.immed_pdom is None:
                if DEBUG_SIMPLIFY: print("[Simplify]   BB has no immed pdom")
                continue

            if bb.immed_pdom.id not in self.id_to_bb_in_slice:
                if DEBUG_SIMPLIFY: print("[Simplify]   immed pdom not in slice")
                continue

            if bb in ignore_set:
                if DEBUG_SIMPLIFY: print("[Simplify]   BB is already removed or cannot be removed")
                continue
            all_succes_before_immed_pdom = set()
            worklist = deque()
            worklist.append(bb)
            visited = set([])
            while len(worklist) > 0:
                child_bb = worklist.popleft()
                if child_bb in visited:
                    if DEBUG_SIMPLIFY: print('[Simplify]   child BB already visited, ignore: ' + str(child_bb.id))
                    continue
                visited.add(child_bb)
                if DEBUG_SIMPLIFY: print("[Simplify]   child BB: " + str(child_bb.id) + \
                      " " + str(child_bb.lines) + \
                      " pdoms are " + str([pdom.lines for pdom in child_bb.pdoms] \
                        if child_bb.pdoms is not None else str(child_bb.pdoms)))
                if DEBUG_SIMPLIFY: print("[Simplify]   child BB: " + str(child_bb.id) + \
                      " " + str(child_bb.lines) + \
                      " pdoms are " + str([pdom.id for pdom in child_bb.pdoms] \
                        if child_bb.pdoms is not None else str(child_bb.pdoms)))
                if child_bb is bb.immed_pdom:
                    if DEBUG_SIMPLIFY: print("[Simplify]   child: " + str(child_bb.id) + \
                          " is the immed pdom: " + str(bb.immed_pdom.id))
                    continue
                assert bb.immed_pdom in child_bb.pdoms
                all_succes_before_immed_pdom.add(child_bb)
                for succe in child_bb.succes:
                    worklist.append(succe)

            if len(self.target_bbs.intersection(all_succes_before_immed_pdom)) > 0:
                #ignore_set.union(all_succes_before_immed_pdom) #FIXME, do not assign after union why???
                if final is True:
                    if DEBUG_SIMPLIFY:
                        print("[simplify] Cannot remove node because target is a child BB, but updating immed pdom: " \
                          + str(bb.immed_pdom.lines) + " " + str(bb.immed_pdom.id))
                    if bb.immed_pdom.id in updated_set:
                        if DEBUG_SIMPLIFY:
                            print("[simplify] already updated immed pdom: " \
                              + str(bb.immed_pdom.lines) + " " + str(bb.immed_pdom.id))
                        continue
                    updated_set.add(bb.immed_pdom.id)
                    has_backedge = False
                    for child_bb in all_succes_before_immed_pdom:
                        if child_bb in bb.immed_pdom.predes:
                            bb.immed_pdom.predes.remove(child_bb)
                            assert bb.immed_pdom in child_bb.succes
                            child_bb.succes.remove(bb.immed_pdom)
                        if len(child_bb.backedge_targets) > 0:
                            has_backedge = True
                    if has_backedge is True:
                        for prede in bb.predes:
                            prede.backedge_targets.append(bb.immed_pdom)
                            bb.immed_pdom.backedge_sources.append(prede)
                    if bb not in bb.immed_pdom.predes:
                        bb.immed_pdom.predes.append(bb)
                    #for prede in bb.predes:
                    #    if prede not in bb.immed_pdom.predes:
                    #        bb.immed_pdom.predes.append(prede)
                    if DEBUG_SIMPLIFY:
                        print("[simplify] new predecessors are: " + str([prede.lines for prede in bb.immed_pdom.predes]))
                continue

            #remove_set.add(bb) not really needed
            all_predes = []
            all_predes.extend(bb.predes)
            if final is True:
                if DEBUG_SIMPLIFY:
                    print("[simplify] Updating the predecessors and successors for bb: " + str(bb.id))
                for prede in bb.predes:
                    if bb in prede.succes:
                        prede.succes.remove(bb)
                    if bb.immed_pdom not in prede.succes:
                        prede.succes.append(bb.immed_pdom)
                    if prede not in bb.immed_pdom.predes:
                        bb.immed_pdom.predes.append(prede)

            has_backedge = False
            for child_bb in all_succes_before_immed_pdom:
                if DEBUG_SIMPLIFY:
                    print("[Simplify] Removing child BB: " + str(child_bb.id) + " " + str(child_bb.lines))
                if len(child_bb.backedge_targets) > 0:
                    has_backedge = True
                remove_count += 1
                if final is True:
                    if child_bb in bb.immed_pdom.predes:
                        bb.immed_pdom.predes.remove(child_bb)
                if child_bb.id in self.id_to_bb_in_slice:
                    del self.id_to_bb_in_slice[child_bb.id]
                if child_bb in self.ordered_bbs_in_slice:
                    self.ordered_bbs_in_slice.remove(child_bb)
                ignore_set.add(child_bb)
            if final is True and has_backedge is True:
                for prede in all_predes:
                    prede.backedge_targets.append(bb.immed_pdom)
                    bb.immed_pdom.backedge_sources.append(prede)
        if DEBUG_SIMPLIFY:
            print("[Simplify] Total number of BBs removed: " + str(remove_count))

    def slice(self, final=False):
        self.sliced = True
        # Find all the control flow predecessors of the given instruction
        # https://stackoverflow.com/questions/35206372/understanding-stacks-and-queues-in-python/35206452
        worklist = deque()
        for bb in self.target_bbs:
            worklist.append(bb)
        visited = set([])
        while len(worklist) > 0:
            bb = worklist.popleft()
            if bb.id in visited:
                if DEBUG_SLICE: print("Already visited: " + str(bb.id))
                continue
            visited.add(bb.id)

            if DEBUG_SLICE: print("Adding bb to slice: " + str(bb.id))
            self.id_to_bb_in_slice[bb.id] = bb
            if bb not in self.ordered_bbs_in_slice:
                self.ordered_bbs_in_slice.append(bb)
            for prede in bb.predes:
                if bb in prede.backedge_targets:
                    if DEBUG_SLICE: print("  Ignoring prede " + str(prede.id) + " because it is part of a backedge")
                    continue
                worklist.append(prede)

        if DEBUG_SLICE: print("=======================================================")
        if DEBUG_SLICE:
            for bb in self.ordered_bbs_in_slice:
                print(str(bb))
        assert len(self.id_to_bb_in_slice) == len(self.ordered_bbs_in_slice), \
            str(len(self.id_to_bb_in_slice)) + " " + str(len(self.ordered_bbs_in_slice))
        print("[static_dep] Total number of basic blocks after slicing: " + str(len(self.ordered_bbs_in_slice)) + \
              str([bb.id for bb in self.ordered_bbs_in_slice]))

        # Simplify the slice
        self.simplify(final)

        if DEBUG_SLICE: print("=======================================================")
        if DEBUG_SLICE:
            for bb in self.ordered_bbs_in_slice:
                print(str(bb))
        assert len(self.id_to_bb_in_slice) == len(self.ordered_bbs_in_slice), \
            str(len(self.id_to_bb_in_slice)) + " " + str(len(self.ordered_bbs_in_slice))
        print("[static_dep] Total number of basic blocks after simplifying: " + str(len(self.ordered_bbs_in_slice)) + \
              str([bb.id for bb in self.ordered_bbs_in_slice]))

    def build(self, insn):
        self.built = True
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
            #if self.target_bb is None:
            #    self.target_bb = bb
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
                for json_backedge_target in json_backedge_targets:
                    backedge_target_id = int(json_backedge_target['id'])
                    self.id_to_bb[bb_id].backedge_targets.append(self.id_to_bb[backedge_target_id])
                    self.id_to_bb[backedge_target_id].backedge_sources.append(self.id_to_bb[bb_id])
        #if DEBUG_CFG:
        for bb in self.ordered_bbs:
            print(str(bb))
        assert len(self.id_to_bb) == len(self.ordered_bbs), \
            str(len(self.id_to_bb)) + " " + str(len(self.ordered_bbs))
        print("[static_dep] number of basic blocks in the entire cfg: " + str(len(self.ordered_bbs)))


class MemoryAccess:
    def __init__(self, reg, shift, off, off_reg, is_bit_var):
        self.reg = reg
        self.shift = shift
        self.off = off
        self.off_reg = off_reg
        self.is_bit_var = is_bit_var

    def toJSON(self):
        return self.__dict__

    @staticmethod
    def fromJSON(data):
        return MemoryAccess(data['reg'], data['shift'], data['off'], data['off_reg'], data['is_bit_var'])

    def __str__(self):
        s = " address: " + str(self.reg) + " * " \
            + str(self.shift) + " + " + str(self.off)
        if self.off_reg is not None:
            s += " * " + str(self.off_reg)
        if self.is_bit_var is not None:
            s += " is bit var: " + str(self.is_bit_var)# + "\n"
        return s


class StaticNode:
    id = 0

    def __init__(self, insn, bb, function, id=None):
        if id is not None:
            self.id = id
        else:
            self.id = StaticNode.id #TODO, incremenet ID here?
            StaticNode.id += 1
        self.insn = insn #FIXME, this is long type right
        self.hex_insn = hex(insn)
        self.function = function #FIXME, maybe rename this to func?
        self.explained = False

        ##### for control flow #####
        self.is_cf = False
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
        self.is_df = False
        self.mem_load = None
        self.reg_load = None

        self.mem_store = None # none-local data flow dependency
        self.reg_store = None # local data flow dependency FIXME fill in something

        self.df_predes = []
        self.df_succes = []

    def toJSON(self):
        data = {}

        data["id"] = self.id
        data["insn"] = self.insn  # FIXME, this is long type right
        data["function"] = self.function  # FIXME, maybe rename this to func?
        data["explained"] = self.explained

        data["is_cf"] = self.is_cf
        if self.bb:
            data["bb"] = self.bb.id #json.dumps(node.bb, cls=BasicBlockEncoder)

        data["cf_predes"] = []
        for n in self.cf_predes:
            data["cf_predes"].append(n.id)
        data["cf_succes"] = []
        for n in self.cf_succes:
            data["cf_succes"].append(n.id)

        data["is_df"] = self.is_df
        data["mem_load"] = self.mem_load if self.mem_load is None or not isinstance(self.mem_load, MemoryAccess) else \
                                        self.mem_load.toJSON()
        data["reg_load"] = self.reg_load

        data["mem_store"] = self.mem_store if self.mem_store is None or not isinstance(self.mem_store, MemoryAccess) else \
                                        self.mem_store.toJSON()
        data["reg_store"] = self.reg_store

        data["df_predes"] = []
        for n in self.df_predes:
            data["df_predes"].append(n.id)
        data["df_succes"] = []
        for n in self.df_succes:
            data["df_succes"].append(n.id)
        return data

    @staticmethod
    def fromJSON(data):
        id = data["id"]
        insn = data["insn"]
        function = data["function"]
        bb = data["bb"] if 'bb' in data else None #TODO, assign actual BB later

        sn = StaticNode(insn, bb, function, id)

        sn.explained = data["explained"]
        sn.is_cf = data["is_cf"]
        if "bb" in data:
            sn.bb = data["bb"]

        sn.cf_predes = data['cf_predes']
        sn.cf_succes = data['cf_succes']
        sn.is_df = data["is_df"]

        sn.mem_load = data["mem_load"]
        if isinstance(sn.mem_load, dict):
            sn.mem_load = MemoryAccess.fromJSON(sn.mem_load)
        sn.reg_load = data["reg_load"]
        sn.mem_store = data["mem_store"]
        if isinstance(sn.mem_store, dict):
            sn.mem_store = MemoryAccess.fromJSON(sn.mem_store)
        sn.reg_store = data["reg_store"]

        sn.df_predes = data['df_predes']
        sn.df_succes = data['df_succes']
        return sn

    @staticmethod
    def fromJSON_finish(sn, all_id_to_node):
        cf_predes = []
        for id in sn.cf_predes:
            cf_predes.append(all_id_to_node[id])
        sn.cf_predes = cf_predes

        cf_succes = []
        for id in sn.cf_succes:
            cf_succes.append(all_id_to_node[id])
        sn.cf_succes = cf_succes

        df_predes = []
        for id in sn.df_predes:
            df_predes.append(all_id_to_node[id])
        sn.df_predes = df_predes

        df_succes = []
        for id in sn.df_succes:
            df_succes.append(all_id_to_node[id])
        sn.df_succes = df_succes

    def __eq__(self, other):
        if not isinstance(other, StaticNode):
            return NotImplemented
        return self.insn == other.insn #FIXME: should be good enough right cuz insns are unique

    def __hash__(self):
        # necessary for instances to behave sanely in dicts and sets.
        return self.insn

    def __str__(self):
        s = "===============================================\n"
        s += "   Node id: " + str(self.id) + "__\n"
        s += " insn addr: " + str(hex(self.insn)) + "\n"
        if self.bb is not None:
            s += "      lines: " + str(self.bb.lines) + "\n"
        s += "      func: " + self.function + "\n"
        s += "     is df: " + str(self.is_df) + "\n"
        s += "     is cf: " + str(self.is_cf) + "\n"
        s += "     explained: " + str(self.explained) + "\n"
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
            s += "     memory load " + str(self.mem_load) + "\n"

        if self.reg_load is not None:
            s += "    register load " + str(self.reg_load) + "\n"

        if self.mem_store is not None:
            s += "     memory store " + str(self.mem_store) + "\n"

        if self.reg_store is not None:
            s += "    register store " + str(self.reg_store) + "\n"

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

    def contains_bit_var(self):
        if self.mem_store is not None:
            if self.mem_store.is_bit_var is not None:
                return self.mem_store.is_bit_var
        if self.mem_load is not None:
            if self.mem_load.is_bit_var is not None:
                return self.mem_load.is_bit_var
            else:
                return False

class StaticDepGraph:
    func_to_graph = {}
    pending_nodes = {}
    rr_result_cache = {}
    sa_result_cache = {}
    reverse_postorder_list = []
    postorder_list = []

    def __init__(self, func, prog):
        self.func = func
        self.prog = prog
        self.cfg = None

        self.id_to_node = {}
        self.insn_to_node = {}

        self.bb_id_to_node_id = {}

        self.nodes_in_cf_slice = set([])
        self.nodes_in_df_slice = set([])
        if func in StaticDepGraph.pending_nodes:
            for n in StaticDepGraph.pending_nodes[func]:
                self.id_to_node[n.id] = n
                self.insn_to_node[n.insn] = n
            del StaticDepGraph.pending_nodes[func]

    def toJSON(self):
        data = {}
        data["func"] = self.func
        data["prog"] = self.prog
        data["cfg"] = self.cfg if self.cfg is None else self.cfg.toJSON()

        data["id_to_node"] = []
        for n in self.id_to_node.values():
            data["id_to_node"].append(n.toJSON())

        data["bb_id_to_node_id"] = self.bb_id_to_node_id

        data["nodes_in_cf_slice"] = []
        for n in self.nodes_in_cf_slice:
            data["nodes_in_cf_slice"].append(n.id)

        data["nodes_in_df_slice"] = []
        for n in self.nodes_in_df_slice:
            data["nodes_in_df_slice"].append(n.id)
        return data

    @staticmethod
    def fromJSON(data, all_id_to_node):
        func = data["func"]
        prog = data["prog"]
        sg = StaticDepGraph(func, prog)
        if "cfg" in data:
            sg.cfg = CFG.fromJSON(data["cfg"])
        sg.bb_id_to_node_id = data["bb_id_to_node_id"]

        print("Current function: " + func)
        for n in data["id_to_node"]:
            sn = StaticNode.fromJSON(n)
            sg.id_to_node[sn.id] = sn
            all_id_to_node[sn.id] = sn
            sg.insn_to_node[sn.insn] = sn

        for n in data["nodes_in_cf_slice"]:
            sg.nodes_in_cf_slice.add(sg.id_to_node[n])

        for n in data["nodes_in_df_slice"]:
            sg.nodes_in_df_slice.add(sg.id_to_node[n])

        for sn in sg.id_to_node.values():
            if sn.bb:
                sn.bb = sg.cfg.id_to_bb[sn.bb]
        return sg

    @staticmethod
    def fromJSON_finish(sg, all_id_to_node):
        for sn in sg.id_to_node.values():
            StaticNode.fromJSON_finish(sn, all_id_to_node)

    @staticmethod
    def writeJSON(json_file):
        out_result = []
        out_pending = []
        for func in StaticDepGraph.func_to_graph:
            out_result.append(StaticDepGraph.func_to_graph[func].toJSON())
        for func in StaticDepGraph.pending_nodes:
            pending = {}
            pending['func'] = func
            pending['nodes'] = []
            for node in StaticDepGraph.pending_nodes[func]:
                pending['nodes'].append(node.toJSON())
            out_pending.append(pending)
        out = {"out_result": out_result, "out_pending": out_pending}
        with open(json_file, 'w') as f:
            # out.write(json.dumps(dynamic_result))
            json.dump(out, f, indent=4, ensure_ascii=False)

    @staticmethod
    def loadJSON(json_file):
        with open(json_file, 'r') as f:
            in_result = json.load(f)
        all_id_to_node = {}
        pending_nodes = {}
        for json_func_to_nodes in in_result["out_pending"]:
            func = json_func_to_nodes["func"]
            json_nodes = json_func_to_nodes["nodes"]
            nodes = []
            for json_node in json_nodes:
                node = StaticNode.fromJSON(json_node)
                nodes.append(node)
                all_id_to_node[node.id] = node
            pending_nodes[func] = nodes

        func_to_graph = {}
        for json_graph in in_result["out_result"]:
            graph = StaticDepGraph.fromJSON(json_graph, all_id_to_node)
            func_to_graph[graph.func] = graph
        for func in func_to_graph:
            StaticDepGraph.fromJSON_finish(func_to_graph[func], all_id_to_node)
        for func in pending_nodes:
            for node in pending_nodes[func]:
                StaticNode.fromJSON_finish(node, all_id_to_node)
        return func_to_graph, pending_nodes

    def make_or_get_df_node(self, insn, bb, function): #TODO: think this through again
        node = self.make_node(insn, bb, function)
        if node.explained is True:
            if node.is_df is True:
                #assert node.is_cf is False, str(node)
                return node
            #if node.is_cf is True:
                #assert node.is_df is False
                #node.is_cf = False
        node.is_df = True
        #node.is_cf = False
        node.explained = False
        return node

    def make_or_get_cf_node(self, insn, bb, function):
        node = self.make_node(insn, bb, function)
        if node.explained is True:
            if node.is_cf is True:
                return node
        #if node.is_df is not True:
        if node.bb is None:
            node.bb = bb
        node.is_cf = True
        node.explained = False
        return node

    def make_node(self, insn, bb, function):
        if insn in self.insn_to_node:
            return self.insn_to_node[insn]
        node = StaticNode(insn, bb, function)
        if function in StaticDepGraph.func_to_graph:
            graph = StaticDepGraph.func_to_graph[function]
            graph.id_to_node[node.id] = node
            graph.insn_to_node[insn] = node
            assert function not in StaticDepGraph.pending_nodes
        else:
            if function not in StaticDepGraph.pending_nodes:
                StaticDepGraph.pending_nodes[function] = []
            StaticDepGraph.pending_nodes[function].append(node)
        return node

    def get_closest_dep_branch(self, node): #TODO, is getting the farthest one
        # TODO, what if has no direct cf predecessor, is that possible?
        succes = set([])
        for succe in node.df_succes:
            if succe.bb is not None and succe.bb.ends_in_branch:
                succes.add(succe.bb)
        last_bb = None
        for bb in self.cfg.postorder_list:
            if bb in succes:
                last_bb = bb
                #break
        return last_bb if last_bb is None else self.id_to_node[self.bb_id_to_node_id[last_bb.id]]

    def get_farthest_target(self, node):
        visited = set([])
        reachable_targets = set([])
        worklist = deque()
        worklist.append(node.bb)
        #print("All target BBs: " + str([bb.id for bb in self.cfg.target_bbs]))
        while (len(worklist) > 0):
            bb = worklist.popleft()
            #print("Current BB: " + str(bb))
            if bb in visited:
                continue
            visited.add(bb)
            if bb in self.cfg.target_bbs:
                reachable_targets.add(bb)
            for succe in bb.succes:
                worklist.append(succe)
        #print("All reachable BBs: " + str([bb.id for bb in reachable_targets]))
        #print("All BBs in post order list: " + str([bb.id for bb in self.cfg.postorder_list]))
        #print("All BBs in cfg: " + str([bb.id for bb in self.cfg.ordered_bbs]))

        last_bb = None
        for bb in self.cfg.postorder_list:
            if bb in reachable_targets:
                last_bb = bb
                break
        return self.id_to_node[self.bb_id_to_node_id[last_bb.id]]

    @staticmethod
    def build_dependencies(insn, func, prog, limit=10000):
        start = time.time()
        key = str(insn) + "_" + str(func) + "_" + str(prog) + "_" + str(limit)
        result_file = os.path.join(curr_dir, 'cache', 'static_graph_result_' + key)
        if os.path.isfile(result_file):
            func_to_graph, pending_nodes = StaticDepGraph.loadJSON(result_file)
            StaticDepGraph.func_to_graph = func_to_graph
            StaticDepGraph.pending_nodes = pending_nodes
            return True

        rr_result_file = os.path.join(curr_dir, 'cache', 'rr_results_' + prog + '.json')
        rr_result_size = 0
        if os.path.exists(rr_result_file):
            with open(rr_result_file) as file:
                StaticDepGraph.rr_result_cache = json.load(file)
                rr_result_size = len(StaticDepGraph.rr_result_cache)

        sa_result_size = 0
        sa_result_file = os.path.join(curr_dir, 'cache', 'sa_results_' + prog + '.json')
        if os.path.exists(sa_result_file):
            with open(sa_result_file) as cache_file:
                StaticDepGraph.sa_result_cache = json.load(cache_file)
                sa_result_size = len(StaticDepGraph.sa_result_cache)

        try:
            #StaticDepGraph.func_to_callsites = get_func_to_callsites(prog)
            iteration = 0
            worklist = deque()
            worklist.append([insn, func, prog, None])
            while len(worklist) > 0:
                if iteration >= limit:
                    break
                iteration += 1
                print("[static_dep] Running analysis at iteration: " + str(iteration))
                curr_insn, curr_func, curr_prog, curr_node = worklist.popleft()
                if curr_node is not None and curr_node.explained:
                    print("[static_dep] Node already explained, skipping ...")
                    print ("[static_dep] " + str(curr_node))
                    continue
                new_nodes = StaticDepGraph.build_dependencies_in_function(curr_insn, curr_func, curr_prog, curr_node)
                for new_node in new_nodes:
                    worklist.append([new_node.insn, new_node.function, prog, new_node]) #FIMXE, ensure there is no duplicate work

            total_count = 0
            for func in StaticDepGraph.func_to_graph:
                graph = StaticDepGraph.func_to_graph[func]
                target_bbs = set([])
                graph.build_control_flow_dependencies(target_bbs, True)
                graph.merge_data_flow_nodes(graph.nodes_in_df_slice, True)
                for n in graph.nodes_in_cf_slice:
                    print(str(n))
                for n in graph.nodes_in_df_slice:
                    print(str(n))

            for func in StaticDepGraph.func_to_graph:
                print("[static_dep] " + func + " has " + str(len(StaticDepGraph.func_to_graph[func].nodes_in_cf_slice)) + " cf nodes and " \
                      + str(len(StaticDepGraph.func_to_graph[func].nodes_in_df_slice)) + " df nodes")
                total_count += len(StaticDepGraph.func_to_graph[func].nodes_in_cf_slice)
                total_count += len(StaticDepGraph.func_to_graph[func].nodes_in_df_slice)
            print("[static_dep] Total number of static nodes: " + str(total_count))
        except Exception as e:
            print("Caught exception: " + str(e))
            raise e
        except KeyboardInterrupt:
            print('Interrupted')
        finally:
            pass

        if rr_result_size != len(StaticDepGraph.rr_result_cache):
            print("Persisting rr result file")
            with open(rr_result_file, 'w') as f:
                json.dump(StaticDepGraph.rr_result_cache, f)
        if sa_result_size != len(StaticDepGraph.sa_result_cache):
            print("Persisting sa result file")
            with open(sa_result_file, 'w') as f:
                json.dump(StaticDepGraph.sa_result_cache, f)
        print("Persisting static graph result file")
        StaticDepGraph.writeJSON(result_file)
        end = time.time()
        print("[static_dep] static analysis took a total time of: " + str(end - start))
        return False

    @staticmethod
    def build_dependencies_in_function(insn, func, prog, df_node = None):
        iter = 0
        print("[static_dep] ")
        print("[static_dep] Building dependencies for function: " + str(func))
        print("[static_dep] Existing dataflow node: ")
        print("[static_dep] " + str(df_node))
        target_bbs = set([])

        if func in StaticDepGraph.func_to_graph:
            graph = StaticDepGraph.func_to_graph[func]
        else:
            graph = StaticDepGraph(func, prog)
            StaticDepGraph.func_to_graph[func] = graph
            graph.build_control_flow_nodes(insn)
            if len(graph.cfg.ordered_bbs) == 0:
                print("[static_dep][warn] Failed to load the cfg for function: "
                      + func + " ignoring the function...")
                return set([])
            target_bbs.add(graph.cfg.ordered_bbs[0])
            graph.build_control_flow_dependencies(target_bbs)
            #callsites = StaticDepGraph.func_to_callsites[func]
        """
        if df_node is not None:
            assert df_node.bb is None
            graph.merge_data_flow_nodes([df_node])
            #TODO, also need to do dataflow tracing for this one!!
        """

        all_defs_in_diff_func = set([])

        new_local_defs_found = True
        while new_local_defs_found:
            new_local_defs_found = False
            print("[static_dep] Building dependencies for function: " + str(func) + " iteration: " + str(iter))
            iter += 1
            defs_in_same_func, defs_in_diff_func = graph.build_data_flow_dependencies(func, prog, df_node)
            all_defs_in_diff_func = all_defs_in_diff_func.union(defs_in_diff_func)
            if len(graph.cfg.ordered_bbs) == 0:
                print("[static_dep][warn] Previously failed to load the cfg for function: "
                      + func + " ignoring the function...")
                return all_defs_in_diff_func
            if len(defs_in_same_func) > 0:
                new_bbs = [graph.cfg.getBB(defn.insn) for defn in defs_in_same_func]
                target_bbs = target_bbs.union(new_bbs)
                graph.build_control_flow_dependencies(target_bbs)
                new_local_defs_found = True
            if df_node is not None:
                if df_node.is_cf is False:
                    assert df_node.bb is None, df_node
                defs_in_same_func.add(df_node)
                if df_node not in graph.nodes_in_df_slice:
                    graph.nodes_in_df_slice.add(df_node)
                df_node = None
                # TODO, also need to do dataflow tracing for this one!!
            graph.merge_data_flow_nodes(defs_in_same_func)

        return all_defs_in_diff_func


    #FIXME, think about if this makes sense
    def merge_data_flow_nodes(self, df_nodes, final=False):
        if len(self.cfg.ordered_bbs) == 0:
            print("[static_dep][warn] Failed to load the cfg, ignoring merging the datanode...")
            return
        if final is False:
            return
        for node in df_nodes:
            assert node.is_df is True
            if not final: assert node.explained is False, str(node)
            node.explained = True
            bb = self.cfg.getBB(node.insn)
            node.bb = bb
            for prede in bb.predes:
                if prede in bb.backedge_sources:
                    continue
                prede_node_id = self.bb_id_to_node_id[prede.id]
                if self.id_to_node[prede_node_id] not in node.cf_predes:
                    node.cf_predes.append(self.id_to_node[prede_node_id])
            for succe in bb.succes:
                if succe in bb.backedge_targets:
                    continue
                succe_node_id = self.bb_id_to_node_id[succe.id]
                if self.id_to_node[succe_node_id] not in node.cf_succes:
                    node.cf_succes.append(self.id_to_node[succe_node_id])

    def build_data_flow_dependencies(self, func, prog, df_node = None):
        print("[static_dep] Building dataflow dependencies local in function: " + str(func))
        defs_in_same_func = set([])
        defs_in_diff_func = set([])

        slice_starts = []
        addr_to_node = {}
        for node in self.nodes_in_cf_slice:
            #assert node.is_cf is True, str(node) TODO
            if node.explained is True:
                continue
            node.explained = True
            bb = node.bb
            assert bb is not None, str(node)
            if bb.ends_in_branch is False:
                continue
            succe_count = 0
            for succe in bb.succes:
                if succe.id in self.cfg.id_to_bb_in_slice:
                    succe_count += 1
            print("succe_count: " + str(succe_count) + " of bb " + str(bb.lines))
            if succe_count == 0:
                continue

            insn = bb.last_insn
            #print(hex(insn))
            slice_starts.append(["", insn, func, False])
            assert insn not in addr_to_node
            addr_to_node[insn] = node
        if df_node is not None: #TODO, registers?
            regLoad = "" if df_node.reg_load is None else df_node.reg_load
            slice_starts.append([regLoad, df_node.insn, df_node.function, df_node.contains_bit_var()])
            #TODO for now, just ignore those that writes to memory in SA
            assert df_node.insn not in addr_to_node
            addr_to_node[df_node.insn] = df_node

        results = static_backslices(slice_starts, prog, StaticDepGraph.sa_result_cache)
        for result in results:
            #reg_name = result[0]
            insn = result[1]
            loads = result[2]
            if loads is None: #TODO, how is this possible?
                continue

            succe = addr_to_node[insn]
            for load in loads:
                prede_insn = load[0]
                prede_reg = load[1]
                shift = load[2]
                off = load[3]
                off_reg = load[4]
                read_same_as_write = load[5]
                is_bit_var = load[6]
                type = load[7]
                curr_func = load[8]
                if read_same_as_write is True:
                    continue
                assert shift != '', str(load)
                assert off != '', str(load)

                prede = self.make_or_get_df_node(prede_insn, None, curr_func) #TODO, might need to include func here too
                if prede.explained is False:
                    #if prede not in self.nodes_in_df_slice:
                    #    self.nodes_in_df_slice.append(prede)
                    if type == 'memread':
                        prede.mem_load = MemoryAccess(prede_reg, shift, off, off_reg, is_bit_var)
                        prede.reg_write = '' #TODO put actual register name here
                    elif type == 'regread':
                        prede.reg_load = prede_reg
                    elif type == 'empty':
                        pass
                    else:
                        print("type not supported " + str(type))
                        #raise Exception
                    if curr_func != func:
                        defs_in_diff_func.add(prede)
                    else:
                        defs_in_same_func.add(prede)
                #else:
                    #assert prede.mem_load is not None or prede.reg_load is not None, str(prede)
                succe.df_predes.append(prede)
                prede.df_succes.append(succe)


        print("[static_dep] Found " + str(len(defs_in_same_func)) + " dataflow nodes local in function ")
        tmp_defs_in_same_func = set([])

        print("[static_dep] Building dataflow dependencies non-local to function: " + str(func))
        for node in defs_in_same_func:
            if VERBOSE: print(str(node))
            #assert node.is_cf is False
            assert node.is_df is True
            assert node.explained is False
            print("[static_dep] Looking for dataflow dependencies potentially non-local to function: " + str(func) \
                  + " for read " + str(node.mem_load) + " @ " + hex(node.insn))

            if node.mem_load is None:
                print("[warn] node does not have memory load?")
                continue

            branch_insn = None
            target_insn = None
            closest_dep_branch_node = self.get_closest_dep_branch(node)
            if closest_dep_branch_node is not None:
                farthest_target_node = self.get_farthest_target(closest_dep_branch_node)
                print("Closest dependent branch is at " + str(branch_insn))
                print("Farthest target is at " + str(target_insn))
                branch_insn = closest_dep_branch_node.bb.last_insn
                target_insn = farthest_target_node.insn
            results = []
            try:
                results = rr_backslice(prog, branch_insn, target_insn, #4234305, 0x409C41 | 4234325, 0x409C55
                                   node.insn, node.mem_load.reg, node.mem_load.shift, node.mem_load.off,
                                   node.mem_load.off_reg, StaticDepGraph.rr_result_cache) #, StaticDepGraph.rr_result_cache)
            except Exception as e:
                print("Calling RR failed")
                print(str(e))
            print("[static_dep] found " + str(len(results)) + " dataflow dependencies non-local to function")
            if VERBOSE: print(results)
            for result in results:
                # reg_name = result[0]
                load = result[0]
                prede_insn = result[1]
                curr_func = result[2]
                if load is None: #TODO why?
                    continue

                prede_reg = load[0]
                shift = '0' if load[1] == '' else load[1]
                off = '0' if load[2] == '' else load[2]

                #print(str(prede_insn))
                prede = self.make_or_get_df_node(prede_insn, None, curr_func)
                if prede.explained is False:
                    prede.mem_store = MemoryAccess(prede_reg, shift, off, None, node.mem_load.is_bit_var)
                    prede.reg_load = ''  # TODO put actual register name here
                    if curr_func != func:
                        defs_in_diff_func.add(prede)
                    else:
                        tmp_defs_in_same_func.add(prede)
                else:
                    if prede.mem_store is None and prede.reg_load is None:
                        print('[static_dep][warn] predecessor already explained '
                              'but no memory store or register load found?' + str(prede))
                node.df_predes.append(prede)
                prede.df_succes.append(node)

        defs_in_same_func = defs_in_same_func.union(tmp_defs_in_same_func)
        print("[static_dep] Total number of new nodes in local  dataflow slice: " + str(len(defs_in_same_func)) + " " + \
              str([hex(node.insn) for node in defs_in_same_func]))
        if VERBOSE:
            for node in defs_in_same_func:
                print(str(node))

        print("[static_dep] Total number of new nodes in remote dataflow slice: " + str(len(defs_in_diff_func)) + " " + \
              str([hex(node.insn) for node in defs_in_diff_func]))
        if VERBOSE:
            for node in defs_in_diff_func:
                print(str(node))

        self.nodes_in_df_slice = self.nodes_in_df_slice.union(set(defs_in_same_func))
        print("[static_dep] Total number of nodes in data flow slice: " + str(len(self.nodes_in_df_slice)) + " " + \
              str([hex(node.insn) for node in self.nodes_in_df_slice]))


        return defs_in_same_func, defs_in_diff_func

    def build_control_flow_nodes(self, insn):
        self.cfg = CFG(self.func, self.prog)
        # Build the control flow graph for the entire function then slice
        self.cfg.build(insn)  # FIXME: for now, order the BBs such that the one that contains insn appears first

        first = True
        # FIXME, make the logic less awkward?
        for bb in self.cfg.ordered_bbs:
            if first:
                node = self.make_or_get_cf_node(insn, bb, self.func)
                first = False
            else:
                node = self.make_or_get_cf_node(bb.last_insn, bb, self.func)
            if node is None:
                continue
            self.bb_id_to_node_id[bb.id] = node.id
            if bb.id in self.cfg.id_to_bb_in_slice:
                self.nodes_in_cf_slice.add(node)


        print("[static_dep] Total initial number of nodes in control flow slice: " + str(len(self.nodes_in_cf_slice)) + " " + \
              str([hex(self.id_to_node[node_id].insn) for node_id in self.id_to_node]))
        if VERBOSE:
            for node_id in self.id_to_node:
                print(str(self.id_to_node[node_id]))


    def build_control_flow_dependencies(self, target_bbs, final=False):
        self.cfg.target_bbs = self.cfg.target_bbs.union(target_bbs)
        self.cfg.slice(final)

        for bb_id in self.cfg.id_to_bb_in_slice:
            bb = self.cfg.id_to_bb[bb_id]
            node_id = self.bb_id_to_node_id[bb_id]
            node = self.id_to_node[node_id]
            if final is True:
                node.cf_predes = []
                node.cf_succes = []
            for prede in bb.predes:
                #assert prede not in bb.backedge_targets, str(bb)
                if prede in bb.backedge_sources:
                    continue
                prede_node_id = self.bb_id_to_node_id[prede.id]
                if self.id_to_node[prede_node_id] not in node.cf_predes:
                    node.cf_predes.append(self.id_to_node[prede_node_id])
            for succe in bb.succes:
                if succe in bb.backedge_targets:
                    continue
                succe_node_id = self.bb_id_to_node_id[succe.id]
                if self.id_to_node[succe_node_id] not in node.cf_succes:
                    node.cf_succes.append(self.id_to_node[succe_node_id])
            if node not in self.nodes_in_cf_slice:
                self.nodes_in_cf_slice.add(node)
        print("[static_dep] Total number of nodes in control flow slice: " + str(len(self.nodes_in_cf_slice)) + " " + \
              str([hex(node.insn) for node in self.nodes_in_cf_slice]))
        if VERBOSE:
            for node in self.nodes_in_cf_slice:
                print(str(node))

    """
    def print_node(self, prefix, n): #fixme refactor this later
        print(prefix
              + " d_id: " + str(n.id) + " s_id: " + str(n.static_node.id)
              + " insn: " + n.static_node.hex_insn + " lines: " + str(n.static_node.bb.lines)
              + " cf ps: " + str([pp.id for pp in n.cf_predes])
              + " df ps: " + str([pp.id for pp in n.df_predes])
              + " cf ss: " + str([ps.id for ps in n.cf_succes])
              + " df ss: " + str([ps.id for ps in n.df_succes]))
    """

if __name__ == "__main__":
    StaticDepGraph.build_dependencies(0x409daa, "sweep", "909_ziptest_exe9", 50)
    #StaticDepGraph.build_dependencies(0x409418, "scanblock", "909_ziptest_exe9")
    json_file = os.path.join(curr_dir, 'static_graph_result')
    StaticDepGraph.writeJSON(json_file)
    func_to_graph, pending_nodes = StaticDepGraph.loadJSON(json_file)
    assert(len(func_to_graph) == len(StaticDepGraph.func_to_graph))
    for func in func_to_graph:
        assert func_to_graph[func].func == StaticDepGraph.func_to_graph[func].func
        assert func_to_graph[func].prog == StaticDepGraph.func_to_graph[func].prog
        assert len(func_to_graph[func].id_to_node) == len(StaticDepGraph.func_to_graph[func].id_to_node)
        #print(str(StaticDepGraph.func_to_graph[func].bb_id_to_node_id)) #TODO this is empty!
        assert len(func_to_graph[func].insn_to_node) == len(StaticDepGraph.func_to_graph[func].insn_to_node),\
            str(len(func_to_graph[func].insn_to_node)) + " " + str(len(StaticDepGraph.func_to_graph[func].insn_to_node))
        assert len(func_to_graph[func].bb_id_to_node_id) == len(StaticDepGraph.func_to_graph[func].bb_id_to_node_id)
        assert len(func_to_graph[func].nodes_in_cf_slice) == len(StaticDepGraph.func_to_graph[func].nodes_in_cf_slice)
        assert len(func_to_graph[func].nodes_in_df_slice) == len(StaticDepGraph.func_to_graph[func].nodes_in_df_slice)