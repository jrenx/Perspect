import json
import os
import os.path
from util import *
from sa_util import *
from rr_util import *
from pin_util import *
from collections import deque
from collections import OrderedDict
import itertools
import sys, traceback
import socket
import time
import argparse

DEBUG_CFG = False
DEBUG_SIMPLIFY = False
DEBUG_SLICE = False
VERBOSE = False
curr_dir = os.path.dirname(os.path.realpath(__file__))
TRACKS_DIRECT_CALLER = True
# = False
USE_BPATCH = False
HOST, PORT = "localhost", 9999

num_processor = 16

class BasicBlock:
    def __init__(self, id, ends_in_branch, is_entry, lines):
        # Note: if we call Dyninst twice, the Basic block IDs will change
        self.id = id
        self.start_insn = None
        self.last_insn = None
        self.lines = lines
        self.ends_in_branch = ends_in_branch
        self.is_entry = is_entry
        self.is_new_entry = False
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
        data["is_new_entry"] = self.is_new_entry
        if self.immed_dom is not None:
            data["immed_dom"] = self.immed_dom.id
        if self.immed_pdom is not None:
            data["immed_pdom"] = self.immed_pdom.id
        if self.pdoms is not None:
            data["pdoms"] = []
            for n in self.pdoms:
                data["pdoms"].append(n.id)

        data["backedge_targets"] = []
        for n in self.backedge_targets:
            data["backedge_targets"].append(n.id)
        data["backedge_targets"].sort()

        data["backedge_sources"] = []
        for n in self.backedge_sources:
            data["backedge_sources"].append(n.id)
        data["backedge_sources"].sort()

        data["predes"] = []
        for n in self.predes:
            data["predes"].append(n.id)
        data["predes"].sort()

        data["succes"] = []
        for n in self.succes:
            data["succes"].append(n.id)
        data["succes"].sort()

        return data

    @staticmethod
    def fromJSON(data):
        id = data['id']
        ends_in_branch = data['ends_in_branch']
        is_entry = True if data['is_entry'] == 1 else False
        lines = data['lines']
        bb = BasicBlock(id, ends_in_branch, is_entry, lines)
        bb.start_insn = data['start_insn']
        bb.last_insn = data['last_insn']
        bb.lines = data['lines']
        bb.ends_in_branch = data['ends_in_branch']
        bb.is_entry = data['is_entry']
        bb.is_new_entry = data['is_new_entry']

        if 'immed_dom' in data:
            bb.immed_dom = data['immed_dom']
        if 'immed_pdom' in data:
            bb.immed_pdom = data['immed_pdom']
        if 'pdoms' in data:
            bb.pdoms = data['pdoms']
        bb.backedge_targets = data['backedge_targets']
        bb.backedge_sources = data['backedge_sources']
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
        self.entry_bbs = set()
        self.postorder_list = []

        self.built = False
        self.sliced = False
        self.jsonified = False

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
        data["target_bbs"].sort()

        data["entry_bbs"] = []
        for n in self.entry_bbs:
            data["entry_bbs"].append(n.id)
        data["entry_bbs"].sort()

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
        cfg.jsonified = True

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

            backedge_sources = []
            for id in bb.backedge_sources:
                backedge_sources.append(cfg.id_to_bb[id])
            bb.backedge_sources = backedge_sources

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
            cfg.entry_bbs.add(cfg.id_to_bb[n])

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

    def contains_insn(self, insn):
        for bb in self.ordered_bbs:
            if bb.start_insn <= insn <= bb.last_insn:
                return True
        return False


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

    def simplify(self, final=False, finalfinal=False):
        print("[static_dep] Simplifying for function: "
              + str(self.func) + " is final: " + str(final) + " is finalfinal: " + str(finalfinal)
              + " target BBs are: " + str([t_bb.id for t_bb in self.target_bbs]))
        for entry in self.entry_bbs:
            visited = set()
            self.postorderTraversal(entry, visited)

        postorder_map = {}
        for i in range(len(self.postorder_list)):
            postorder_map[self.postorder_list[i].id] = i

        if DEBUG_SIMPLIFY: print("[Simplify] Postorder list: " + str([bb.lines for bb in self.postorder_list]))
        if DEBUG_SIMPLIFY: print("[Simplify] Postorder list: " + str([bb.id for bb in self.postorder_list]))
        bb_id_to_pdom_ids = {}

        if finalfinal is not True:
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
                            else:
                                pdom_ids = set()
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
        ignore_set = set()
        visited_pdom_set = set() #FIXME maybe extra
        updated_set = set()
        for bb in reversed(self.postorder_list):
            if DEBUG_SIMPLIFY:
                print("[Simplify] can BB: " + str(bb.id) + " " + str(bb.lines) + " be removed? immed pdom is " \
                  + (str(bb.immed_pdom.id) if bb.immed_pdom is not None else str(bb.immed_pdom)) + " "\
                  + (str(bb.immed_pdom.lines) if bb.immed_pdom is not None else str(bb.immed_pdom)))
            if bb.immed_pdom is None:
                if DEBUG_SIMPLIFY: print("[Simplify]   BB has no immed pdom")
                continue

            if bb.immed_pdom.id not in self.id_to_bb_in_slice:
                if DEBUG_SIMPLIFY: print("[Simplify]   immed pdom not in slice")
                continue
            
            if finalfinal is True:
                if bb.immed_pdom in visited_pdom_set:
                    if DEBUG_SIMPLIFY: print("[Simplify]   BB's immed pdom is already encountered")
                    continue

            if bb in ignore_set:
                if DEBUG_SIMPLIFY: print("[Simplify]   BB is already removed or cannot be removed")
                continue
            all_succes_before_immed_pdom = set()
            worklist = deque()
            worklist.append(bb)
            visited = set()
            ignore = False
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
                if finalfinal is True:
                    if bb.immed_pdom not in child_bb.pdoms:
                        ignore = True
                        break
                assert bb.immed_pdom in child_bb.pdoms
                all_succes_before_immed_pdom.add(child_bb)
                for succe in child_bb.succes:
                    worklist.append(succe)

            if ignore is True:
                if DEBUG_SIMPLIFY:
                    print("[Simplify]   a child BB was a successor of the immed_pdom, possible have been aggressively simplified")
                continue
            if len(self.target_bbs.intersection(all_succes_before_immed_pdom)) > 0:
                #or len(self.entry_bbs.intersection(all_succes_before_immed_pdom)) > 0:
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
                            if DEBUG_SIMPLIFY: print("[simplify]   For bb " + str(bb.immed_pdom.id) + " remove " + str(child_bb.id) + " from predes")
                            assert bb.immed_pdom in child_bb.succes
                            child_bb.succes.remove(bb.immed_pdom)
                            if DEBUG_SIMPLIFY: print("[simplify]   For bb " + str(child_bb.id) + " remove " + str(
                                bb.immed_pdom.id) + " from succes")
                        if len(child_bb.backedge_targets) > 0:
                            has_backedge = True
                    if DEBUG_SIMPLIFY: print("[simplify] has backedge? " + str(has_backedge))

                    if finalfinal is False:
                        if bb not in bb.immed_pdom.predes:
                            bb.immed_pdom.predes.append(bb)
                            if DEBUG_SIMPLIFY: print("[simplify]   For bb " + str(bb.immed_pdom.id) + " add " + str(
                                bb.id) + " to predes")
                        if bb.immed_pdom not in bb.succes:
                            bb.succes.append(bb.immed_pdom)
                            if DEBUG_SIMPLIFY: print("[simplify]   For bb " + str(bb.id) + " add " + str(
                                bb.immed_pdom.id) + " to succes")
                        if has_backedge is True:
                            if bb.immed_pdom not in bb.backedge_targets:
                                bb.backedge_targets.append(bb.immed_pdom)
                            if bb not in bb.immed_pdom.backedge_sources:
                                bb.immed_pdom.backedge_sources.append(bb)
                    else:
                        if has_backedge is False:
                            visited_pdom_set.add(bb.immed_pdom)
                            for prede in bb.predes:
                                if prede not in bb.immed_pdom.predes:
                                    bb.immed_pdom.predes.append(prede)
                                    if DEBUG_SIMPLIFY: print("[simplify]   For bb " + str(bb.immed_pdom.id) + " add " + str(
                                        prede.id) + " to predes")
                                if bb.immed_pdom not in prede.succes:
                                    prede.succes.append(bb.immed_pdom)
                                    if DEBUG_SIMPLIFY: print("[simplify]   For bb " + str(prede.id) + " add " + str(
                                        bb.immed_pdom.id) + " to succes")
                    #for prede in bb.predes:
                    #    if prede not in bb.immed_pdom.predes:
                    #        bb.immed_pdom.predes.append(prede)
                    if DEBUG_SIMPLIFY:
                        print("[simplify] new predecessors are: " + str([prede.lines for prede in bb.immed_pdom.predes]))
                continue

            if TRACKS_DIRECT_CALLER:
                if len(self.entry_bbs.intersection(all_succes_before_immed_pdom)) > 0:
                    """
                    if len(bb.predes) != 0:
                        for eb in self.entry_bbs:
                            print("Entry: " + str(eb.id))
                        print("BB: " + str(bb.id))
                        print("Immed dom: " + str(bb.immed_pdom.id))
                        assert False
                    """
                    assert bb.is_entry or bb.is_new_entry
                    self.entry_bbs.remove(bb)
                    self.entry_bbs.add(bb.immed_pdom)
                    if DEBUG_SIMPLIFY: print("Replacing entry BB " + str(bb.id) + " with " + str(bb.immed_pdom.id))
                    bb.immed_pdom.is_new_entry = True

            #remove_set.add(bb) not really needed
            all_predes = []
            all_predes.extend(bb.predes)
            if final is True:
                if DEBUG_SIMPLIFY:
                    print("[simplify] Updating the predecessors and successors for bb: " + str(bb.id))
                for prede in bb.predes:
                    if bb in prede.succes:
                        prede.succes.remove(bb)
                    if prede.succes in bb.predes: #newly added
                        bb.predes.remove(prede.succes) #newly added
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
                        child_bb.succes.remove(bb.immed_pdom) #newly added

                    for prede in bb.predes: #newly added
                        if child_bb in prede.succes:
                            prede.succes.remove(child_bb)
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

        #if DEBUG_SLICE:
        print("[static_dep] Slicing for function: " + self.func)
        print("[static_dep] Targets for slicing: " + str([bb.id for bb in self.target_bbs]))
        for bb in self.target_bbs:
            worklist.append(bb)
        visited = set()
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
        #for bb in self.ordered_bbs:
        #    print(str(bb))
        if final is True: self.simplify(final, finalfinal=True)
        #for bb in self.ordered_bbs:
        #    print(str(bb))

        if DEBUG_SLICE: print("=======================================================")
        if DEBUG_SLICE:
            for bb in self.ordered_bbs_in_slice:
                print(str(bb))
        assert len(self.id_to_bb_in_slice) == len(self.ordered_bbs_in_slice), \
            str(len(self.id_to_bb_in_slice)) + " " + str(len(self.ordered_bbs_in_slice))
        print("[static_dep] Total number of basic blocks after simplifying: " + str(len(self.ordered_bbs_in_slice)) + \
              str([bb.id for bb in self.ordered_bbs_in_slice]))

    def build(self, insn):
        for i in range(0,5):
            try:
                self.built = True
                if USE_BPATCH is True:
                    json_bbs = getAllBBs(StaticDepGraph.binary_ptr, insn, self.func, self.prog, \
                                     bb_result_cache=StaticDepGraph.bb_result_cache, \
                                     overwrite_cache=False if i == 0 else True)
                else:
                    json_bbs = getAllBBs2(StaticDepGraph.binary_ptr2, StaticDepGraph.binary_ptr, insn, self.func, self.prog, \
                                     bb_result_cache=StaticDepGraph.bb_result_cache, \
                                     overwrite_cache=False if i == 0 else True)


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
                        self.entry_bbs.add(bb)

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
                return
            except Exception as e:
                print("Caught exception: " + str(e))
                print(str(e))
                print("-" * 60)
                traceback.print_exc(file=sys.stdout)
                print("-" * 60)
                time.sleep(5)
                continue
        raise Exception("Building CFG failed twice.")

class BitOperation:
    def __init__(self, insn, operand, operation):
        self.insn = insn
        self.operand = operand.lower()
        self.operation = operation

    def __str__(self):
        s = "BIT OP insn " + hex(self.insn) + " operand " \
            + str(self.operand) + " operation " + str(self.operation)
        return s

    def toJSON(self):
        data = {}
        data["insn"] = self.insn
        data["operand"] = self.operand
        data["operation"] = self.operation
        return data

    @staticmethod
    def fromJSON(data):
        bo = BitOperation(data['insn'], data['operand'], data['operation'])
        return bo

class MemoryAccess:
    def __init__(self, reg, shift, off, off_reg, is_bit_var, off1=None):
        self.reg = reg.lower() if reg is not None else reg
        self.shift = shift
        self.off = MemoryAccess.convert_offset(off) if off is not None else None
        self.off_reg = off_reg.lower() if off_reg is not None else off_reg
        self.is_bit_var = is_bit_var
        self.bit_operations = None
        self.read_same_as_write = False
        self.off1 = MemoryAccess.convert_offset(off1) if off1 is not None else None

    @staticmethod
    def convert_offset(off):
        off_str = hex(off)
        if off_str.startswith("0xf"):
            if len(off_str) == 10: #32bit
                new_off = -((~off+1)&0xffffffff)
                print("[rr] " + str(off) + " Likely a negative offset, convert it to " + str(new_off))
                return new_off
            if len(off_str) == 18: #64bit
                new_off = -((~off+1)&0xffffffffffffffff)
                print("[rr] " + str(off) + " Likely a negative offset, convert it to " + str(new_off))
                return new_off
        return off

    def add_bit_operationses(self, bit_operationses):
        if bit_operationses is None:
            return
        for bit_operations in bit_operationses:
            self.add_bit_operations(bit_operations)

    def add_bit_operations(self, bit_operations):
        if len(bit_operations) == 0:
            return
        # overwrite = False
        # if self.bit_operations is not None:
        #    overwrite = True
        #    print("BEFORE " + str(self.bit_operations))
        if self.bit_operations is None:
            self.bit_operations = []
        bos = []
        for bo in bit_operations:
            bos.append(BitOperation(bo[0], bo[1], bo[2]))
        self.bit_operations.append(bos)
        # if overwrite is True:
        #    print("AFTER " + str(self.bit_operations))

    #def toJSON(self):
    #    data = {}
    #    data["reg"] = self.reg
    #    data["shift"] = self.shift
    #    data["off"] = self.off
    #    data["off_reg"] = self.off_reg
    #    data["is_bit_var"] = self.is_bit_var
    #    if self.bit_operations is not None:
    #        data["bit_operations"] = []
    #        for bit_operation in self.bit_operations:
    #            data["bit_operations"].append(bit_operation.toJSON())
    #    data["read_same_as_write"] = 0 if self.read_same_as_write is False else 1
    #    return data

    def toJSON(self):
        data = {}
        data["reg"] = self.reg
        data["shift"] = self.shift
        data["off"] = self.off
        data["off1"] = self.off1
        data["off_reg"] = self.off_reg
        data["is_bit_var"] = self.is_bit_var
        if self.bit_operations is not None:
            data["bit_operations"] = []
            for bos in self.bit_operations:
                json_bos = []
                data["bit_operations"].append(json_bos)
                for bo in bos:
                    json_bos.append(bo.toJSON())
        data["read_same_as_write"] = 0 if self.read_same_as_write is False else 1
        return data

    @staticmethod
    def fromJSON(data):
        ma = MemoryAccess(data['reg'], data['shift'], data['off'], data['off_reg'], data['is_bit_var'], data['off1'] if 'off1' in data else None)
        ma.read_same_as_write = False if data['read_same_as_write'] == 0 else True
        if "bit_operations" in data:
            bit_operations = []
            for json_bos in data["bit_operations"]:
                bos = []
                for json_bo in json_bos:
                    bos.append(BitOperation.fromJSON(json_bo))
                if len(bos) > 0:
                    bit_operations.append(bos)
        #TODO: sometimes there could be empty bit operations ... why?
            if len(bit_operations) > 0:
                ma.bit_operations = bit_operations
        return ma

    def __str__(self):
        s = " address: " + str(self.reg) + " * " \
            + str(self.shift) + " + " + str(self.off)
        if self.off_reg is not None:
            s += " * " + str(self.off_reg)
        if self.is_bit_var is not None:
            s += " is bit var: " + str(self.is_bit_var)# + "\n"
        s += " read same as write: " + str(self.read_same_as_write)
        if self.bit_operations is not None:
            for bos in self.bit_operations:
                s += "\n" + str([str(bo) for bo in bos])
        return s

class StaticNode:
    id = 0
    group_id = 0
    def __init__(self, insn, bb, function, id=None, file=None, line=None):
        if id is not None:
            self.id = id
            if StaticNode.id <= id:
                StaticNode.id = id + 1
        else:
            self.id = StaticNode.id #TODO, incremenet ID here?
            StaticNode.id += 1
        self.group_id = -1
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

        self.backedge_targets = set()
        self.backedge_sources = set()

        # For grouping together nodes with a OR relation
        self.group_ids = None
        self.group_insns = None
        self.virtual_nodes = []

        self.is_intermediate_node = False

        #if GENERATE_INSN_MAPPING is True:
        #    if file is None and line is None:
        #        file, line = get_line(insn, StaticDepGraph.prog)
        self.file = file
        self.line = line
        #if GENERATE_INSN_MAPPING is True:
        #    StaticDepGraph.insert_file_line_to_map(file, line)
        self.index = None
        self.total_count = None

    def print_node(self, prefix): #FIXME change the one in dynamic graph
        print(prefix
              + " s_id: " + str(self.id)
              + " insn: " + self.hex_insn
              + " func: " + self.function
              + " lines: " + (str(self.bb.lines) if isinstance(self.bb, BasicBlock) else str(self.bb))
              + " cf ps: " + str([pp.id for pp in self.cf_predes])
              + " df ps: " + str([pp.id for pp in self.df_predes])
              + " cf ss: " + str([ps.id for ps in self.cf_succes])
              + " df ss: " + str([ps.id for ps in self.df_succes]))

    def toJSON(self):
        data = {}

        data["id"] = self.id
        data["insn"] = self.insn  # FIXME, this is long type right
        data["hex_insn"] = self.hex_insn  # FIXME, this is long type right
        data["lines"] = self.bb.lines if self.bb is not None else []  # FIXME, this is long type right
        data["function"] = self.function  # FIXME, maybe rename this to func?
        data["explained"] = self.explained

        data["is_cf"] = self.is_cf
        if self.bb:
            data["bb"] = self.bb.id #json.dumps(node.bb, cls=BasicBlockEncoder)

        data["cf_predes"] = []
        for n in self.cf_predes:
            data["cf_predes"].append(n.id)
        data["cf_predes"].sort()

        data["cf_succes"] = []
        for n in self.cf_succes:
            data["cf_succes"].append(n.id)
        data["cf_succes"].sort()

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
        data["df_predes"].sort()

        data["df_succes"] = []
        for n in self.df_succes:
            data["df_succes"].append(n.id)
        data["df_succes"].sort()

        data["node_backedge_targets"] = list(self.backedge_targets)
        data["node_backedge_targets"].sort()
        data["node_backedge_sources"] = list(self.backedge_sources)
        data["node_backedge_sources"].sort()
        """
        data["backedges"] = []
        for n in self.backedges:
            data["backedges"].append(n.id)
        """
        data["group_ids"] = self.group_ids
        data["group_insns"] = self.group_insns
        if self.is_intermediate_node is True:
            data["is_intermediate_node"] = self.is_intermediate_node
        #if GENERATE_INSN_MAPPING:
        data["file"] = self.file
        data["line"] = self.line
        if self.index is not None:
            data["index"] = self.index
        if self.total_count is not None:
            data["total_count"] = self.total_count
        return data

    @staticmethod
    def fromJSON(data):
        id = data["id"]
        insn = data["insn"]
        function = data["function"]
        bb = data["bb"] if 'bb' in data else None #TODO, assign actual BB later

        file = None
        line = None
        if "file" in data and "line" in data:
            file = data["file"]
            line = data["line"]

        sn = StaticNode(insn, bb, function, id, file, line)
        #StaticDepGraph.insn_to_node[sn.insn] = sn

        if "index" in data:
            sn.index = data["index"]
        if "total_count" in data:
            sn.total_count = data["total_count"]

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
        if sn.reg_load is not None and '::' in sn.reg_load:
            sn.reg_load = sn.reg_load.split("::")[1]

        sn.mem_store = data["mem_store"]
        if isinstance(sn.mem_store, dict):
            sn.mem_store = MemoryAccess.fromJSON(sn.mem_store)
        sn.reg_store = data["reg_store"]
        if sn.reg_store is not None and '::' in sn.reg_store:
            sn.reg_store = sn.reg_store.split("::")[1]

        sn.df_predes = data['df_predes']
        sn.df_succes = data['df_succes']

        sn.backedge_targets = set(data['node_backedge_targets'])
        sn.backedge_sources = set(data['node_backedge_sources'])

        sn.group_ids = data["group_ids"]
        sn.group_insns = data["group_insns"]
        if sn.group_ids is not None:
            for group_id in sn.group_ids:
                if group_id > StaticNode.group_id:
                    StaticNode.group_id = group_id + 1
                if group_id not in StaticDepGraph.group_to_nodes:
                    StaticDepGraph.group_to_nodes[group_id] = set()
                StaticDepGraph.group_to_nodes[group_id].add(sn)

        if "is_intermediate_node" in data:
            sn.is_intermediate_node = data["is_intermediate_node"]
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

        """
        backedges = []
        for id in sn.backedges:
            backedges.append(all_id_to_node[id])
        sn.backedges = backedges
        """

    def __eq__(self, other):
        if not isinstance(other, StaticNode):
            return NotImplemented
        return self.insn == other.insn and self.function == other.function #FIXME: should be good enough right cuz insns are unique

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
        return False

class StaticDepGraph:
    func_to_graph = {}
    func_to_duplicate_count = {}

    pending_nodes = {}

    result_file = None
    rr_result_cache = {}
    sa_result_cache = {}
    bb_result_cache = {}

    func_to_callsites = None
    func_hot_and_cold_path_map = None

    starting_nodes = []
    reverse_postorder_list = []
    # successor always after predecessor
    postorder_list = []
    postorder_ranks = {}

    entry_nodes = set()
    exit_nodes = set()

    pending_callsite_nodes = []

    group_to_nodes = {}
    insn_to_node = {}

    file_to_line_to_nodes = {}
    prog = None #FIXME, stop passing prog around, there is only one prog per analysis

    def __init__(self, func, prog):
        self.func = func
        self.prog = prog
        self.cfg = None

        self.id_to_node = {}
        self.insn_to_node = {}

        self.bb_id_to_node_id = {}

        self.nodes_in_cf_slice = {}
        self.nodes_in_df_slice = {}
        self.none_df_starting_nodes = set()

        self.pending_callsite_nodes = []

        #if func in StaticDepGraph.pending_nodes:
        #    for n in StaticDepGraph.pending_nodes[func].values():
        #        self.id_to_node[n.id] = n
        #        self.insn_to_node[n.insn] = n
        #    del StaticDepGraph.pending_nodes[func]
        self.changed = True

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
        for n in self.nodes_in_cf_slice.keys():
            data["nodes_in_cf_slice"].append(n.id)
        data["nodes_in_cf_slice"].sort()

        data["nodes_in_df_slice"] = []
        for n in self.nodes_in_df_slice.keys():
            data["nodes_in_df_slice"].append(n.id)
        data["nodes_in_df_slice"].sort()

        data["none_df_starting_nodes"] = []
        for n in self.none_df_starting_nodes:
            data["none_df_starting_nodes"].append(n.id)
        data["none_df_starting_nodes"].sort()
        return data

    @staticmethod
    def fromJSON(data, all_id_to_node):
        func = data["func"]
        prog = data["prog"]
        sg = StaticDepGraph.make_graph(func, prog)
        sg.changed = False
        if "cfg" in data:
            sg.cfg = CFG.fromJSON(data["cfg"])

        sg.bb_id_to_node_id = {}
        for key in data["bb_id_to_node_id"]:
            sg.bb_id_to_node_id[int(key)] = data["bb_id_to_node_id"][key]

        for n in data["id_to_node"]:
            sn = StaticNode.fromJSON(n)
            sg.id_to_node[sn.id] = sn
            all_id_to_node[sn.id] = sn
            sg.insn_to_node[sn.insn] = sn

        for n in data["nodes_in_cf_slice"]:
            sg.nodes_in_cf_slice[sg.id_to_node[n]] = sg.id_to_node[n]

        for n in data["nodes_in_df_slice"]:
            sg.nodes_in_df_slice[sg.id_to_node[n]] = sg.id_to_node[n]

        if "none_df_starting_nodes" in data:
            for n in data["none_df_starting_nodes"]:
                sg.none_df_starting_nodes.add(sg.id_to_node[n])

        for sn in sg.id_to_node.values():
            if sn.bb is not None:
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
        for graph in StaticDepGraph.func_to_graph.values():
            out_result.append(graph.toJSON())
        for func in StaticDepGraph.pending_nodes:
            pending = {}
            pending['func'] = func
            pending['nodes'] = []
            for node in StaticDepGraph.pending_nodes[func].values():
                pending['nodes'].append(node.toJSON())
            out_pending.append(pending)
        postorder_list = []
        for n in StaticDepGraph.postorder_list:
            postorder_list.append(n.id)
        reverse_postorder_list = []
        for n in StaticDepGraph.reverse_postorder_list:
            reverse_postorder_list.append(n.id)
        out = {"starting_nodes": [n.id for n in StaticDepGraph.starting_nodes],
               "out_result": out_result, "out_pending": out_pending,
               "graph_postorder_list": postorder_list,
               "graph_reverse_postorder_list": reverse_postorder_list}
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
            nodes = {}
            for json_node in json_nodes:
                if 'bb' in json_node and json_node['bb'] is not None:
                    #FIXME: eventually remove this,
                    # any merged node which have a bb should have been removed from the pending map
                    continue
                node = StaticNode.fromJSON(json_node)
                nodes[node.insn] = node
                all_id_to_node[node.id] = node
            pending_nodes[func] = nodes

        for json_graph in in_result["out_result"]:
            graph = StaticDepGraph.fromJSON(json_graph, all_id_to_node)
        for graph in StaticDepGraph.func_to_graph.values():
            StaticDepGraph.fromJSON_finish(graph, all_id_to_node)
        to_remove = set()
        for func in pending_nodes:
            for node in pending_nodes[func].values():
                StaticNode.fromJSON_finish(node, all_id_to_node)
            if func not in StaticDepGraph.func_to_graph:
                continue
            for curr_func in itertools.chain(StaticDepGraph.get_duplicate_names(func), [func]):
                graph = StaticDepGraph.func_to_graph[curr_func]
                #to_remove.add(graph.func)
                for pending_node in pending_nodes[func].values():
                    if graph.cfg.contains_insn(pending_node.insn):
                        graph.id_to_node[pending_node.id] = pending_node
                        graph.insn_to_node[pending_node.insn] = pending_node

        #for func in to_remove:
        #    del pending_nodes[func]

        postorder_list = []
        for json_node in in_result["graph_postorder_list"]:
            postorder_list.append(all_id_to_node[json_node])

        reverse_postorder_list = []
        for json_node in in_result["graph_reverse_postorder_list"]:
            reverse_postorder_list.append(all_id_to_node[json_node])

        starting_nodes = []
        if "starting_nodes" in in_result:
            for n_id in in_result["starting_nodes"]:
                starting_nodes.append(all_id_to_node[n_id])

        StaticDepGraph.pending_nodes = pending_nodes
        StaticDepGraph.postorder_list = postorder_list
        StaticDepGraph.reverse_postorder_list = reverse_postorder_list
        StaticDepGraph.starting_nodes = starting_nodes
        return

    @staticmethod
    def make_or_get_df_node(insn, bb, function): #TODO: think this through again
        #if insn in StaticDepGraph.insn_to_node:
        #    node = StaticDepGraph.insn_to_node[insn]
        #else:
        node = StaticDepGraph.make_node(insn, bb, function)
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

    @staticmethod
    def make_or_get_cf_node(insn, bb, function, graph=None):
        #TODO: refactor these complicated logic ...
        #if insn in StaticDepGraph.insn_to_node:
        #    node = StaticDepGraph.insn_to_node[insn]
        #else:
        node = StaticDepGraph.make_node(insn, bb, function, graph)
        if node.explained is True:
            if node.is_cf is True:
                return node
        #if node.is_df is not True:
        if node.bb is None:
            node.bb = bb
        node.is_cf = True
        node.explained = False
        return node

    @staticmethod
    def make_node(insn, bb, function, graph=None):
        #print("Making node for insn: " + hex(insn) + "@" + function)

        node = None
        if graph is None:
            graph = StaticDepGraph.get_graph(function, insn)

        if graph is not None:
            node = graph.insn_to_node.get(insn, None)
            if node is not None:
                return node
        node_from_pending = False
        pending = StaticDepGraph.pending_nodes.get(function, None)
        if pending is not None:
            node = pending.get(insn, None)
            node_from_pending = node is not None

        if node is None:
            node = StaticNode(insn, bb, function)
            print("Creating node id: " + str(node.id))
            #assert insn not in StaticDepGraph.insn_to_node
            #StaticDepGraph.insn_to_node[insn] = node

        if graph is not None:
            graph.id_to_node[node.id] = node
            graph.insn_to_node[insn] = node
            if node_from_pending:
                del pending[node.insn]
            #assert function not in StaticDepGraph.pending_nodes
        else:
            if pending is None:
                pending = {}
                StaticDepGraph.pending_nodes[function] = pending
            pending[node.insn] = node
            #assert function not in StaticDepGraph.func_to_graph
        return node

    @staticmethod
    def get_graph(func, insn):
        graph = StaticDepGraph.func_to_graph.get(func, None)
        if graph is not None and graph.cfg.contains_insn(insn) is False:
            dup_count = 1
            while True:
                graph = StaticDepGraph.func_to_graph.get(func + "DUPLICATE_" + str(dup_count), None)
                if graph is None:
                    break
                if graph.cfg.contains_insn(insn) is True:
                    break
                dup_count += 1
        return graph

    @staticmethod
    def make_graph(func, prog):
        graph = StaticDepGraph(func, prog)
        count = StaticDepGraph.func_to_duplicate_count.get(func, -1)
        count += 1
        StaticDepGraph.func_to_duplicate_count[func] = count

        if count == 0:
            StaticDepGraph.func_to_graph[func] = graph
        else:
            StaticDepGraph.func_to_graph[func + "DUPLICATE_" + str(count)] = graph
        return graph

    @staticmethod
    def get_duplicate_names(func):
        duplicate_names = []
        if func in StaticDepGraph.func_to_duplicate_count:
            for i in range(StaticDepGraph.func_to_duplicate_count[func]):
                duplicate_names.append(func + "DUPLICATE_" + str(i + 1))
        return duplicate_names

    def get_closest_dep_branch(self, node): #TODO, is getting the farthest one
        # TODO, what if has no direct cf predecessor, is that possible?
        #print("===========================")
        succes = set()
        for succe in node.df_succes:
            if succe.bb is not None and succe.bb.ends_in_branch:
                succes.add(succe.bb)
                #print(succe)
        last_bb = None
        for bb in self.cfg.postorder_list:
            if bb in succes:
                last_bb = bb
                #break
        if last_bb is None:
            return None
        return last_bb if last_bb is None else self.id_to_node[self.bb_id_to_node_id[last_bb.id]]

    def get_farthest_target(self, node):
        visited = set()
        reachable_targets = set()
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
        if last_bb is None:
            return None
        return self.id_to_node[self.bb_id_to_node_id[last_bb.id]]

    @staticmethod
    def build_key(starting_events):
        key = ""
        for i in range(len(starting_events)):
            event = starting_events[i]
            reg = event[0]
            insn = event[1]
            key += reg + "_" + hex(insn)
            if i + 1 < len(starting_events):
                key += "_"
        return key
    @staticmethod
    def build_file_names(starting_events, prog, limit):
        result_dir = os.path.join(curr_dir, 'cache', prog)
        if not os.path.exists(result_dir):
            os.makedirs(result_dir)

        key = StaticDepGraph.build_key(starting_events)
        result_file = os.path.join(result_dir, 'static_graph_' + str(limit) + "_" + key)
        indice_file = os.path.join(result_dir, 'indices_' + key)
        return result_dir, result_file, indice_file, key

    @staticmethod
    def build_indices(starting_events, prog, limit, align_indices=False,
                        our_source_code_dir=None, other_source_code_dir=None):
        start = time.time()
        result_dir, result_file, indice_file, key = StaticDepGraph.build_file_names(starting_events, prog, limit)
        StaticDepGraph.result_file = result_file
        StaticDepGraph.prog = prog

        a = time.time()
        StaticDepGraph.loadJSON(result_file)
        b = time.time()
        print("[static_dep] Finished loading graph, took: " + str(b - a))

        if align_indices is False:
            StaticDepGraph.generate_file_line_for_all_reachable_nodes(prog, our_source_code_dir)
            StaticDepGraph.binary_ptr = setup(prog)
            StaticDepGraph.build_binary_indices(prog)
            StaticDepGraph.output_indices_mapping(indice_file)
            StaticDepGraph.writeJSON(result_file)
        else:
            assert os.path.exists(indice_file)
            StaticDepGraph.align_indices(our_source_code_dir, other_source_code_dir)
            StaticDepGraph.output_indices_mapping(indice_file)
            StaticDepGraph.writeJSON(result_file)

    @staticmethod
    def build_dependencies(starting_events, prog, limit, use_cached_static_graph=True, parallelize_rr=False):
        start = time.time()
        result_dir, result_file, indice_file, key = StaticDepGraph.build_file_names(starting_events, prog, limit)
        StaticDepGraph.result_file = result_file
        StaticDepGraph.prog = prog
        if use_cached_static_graph and os.path.isfile(result_file):
            a = time.time()
            StaticDepGraph.loadJSON(result_file)
            b = time.time()
            print("[static_dep] Finished loading graph, took: " + str(b-a))
            #StaticDepGraph.print_graph_info()
            return True

        rr_result_file = os.path.join(result_dir, 'rr_results_' + prog + '.json')
        rr_result_size = 0
        if os.path.exists(rr_result_file):
            with open(rr_result_file) as file:
                StaticDepGraph.rr_result_cache = json.load(file)
                rr_result_size = len(StaticDepGraph.rr_result_cache)

        sa_result_size = 0
        sa_result_file = os.path.join(result_dir, 'sa_results_' + prog + '.json')
        if os.path.exists(sa_result_file):
            with open(sa_result_file) as cache_file:
                StaticDepGraph.sa_result_cache = json.load(cache_file)
                sa_result_size = len(StaticDepGraph.sa_result_cache)

        bb_result_size = 0
        bb_result_file = os.path.join(result_dir, 'bb_results_' + prog + '.json')
        if os.path.exists(bb_result_file):
            with open(bb_result_file) as cache_file:
                StaticDepGraph.bb_result_cache = json.load(cache_file)
                bb_result_size = len(StaticDepGraph.bb_result_cache)

        try:
            total_node_count = 0
            StaticDepGraph.func_to_callsites, StaticDepGraph.func_hot_and_cold_path_map = get_func_to_callsites(prog)
            StaticDepGraph.binary_ptr = setup(prog)
            if USE_BPATCH is False:
                StaticDepGraph.binary_ptr2 = setup2(prog)
            #print(StaticDepGraph.func_to_callsites)
            iteration = 0
            worklist = deque()
            for event in starting_events:
                reg = event[0]
                insn = event[1]
                func = event[2]
                node = StaticDepGraph.make_or_get_cf_node(insn, None, func)
                if node not in StaticDepGraph.starting_nodes:
                    StaticDepGraph.starting_nodes.append(node)
                if reg is not None:
                    node.reg_load = reg
                worklist.append([insn, func, prog, node])
            while len(worklist) > 0:
                if iteration >= limit:
                    break
                if iteration % 10 == 0 and iteration > 0:
                    if rr_result_size != len(StaticDepGraph.rr_result_cache):
                        print("Persisting rr result file")
                        with open(rr_result_file, 'w') as f:
                            json.dump(StaticDepGraph.rr_result_cache, f, indent=4)
                    if sa_result_size != len(StaticDepGraph.sa_result_cache):
                        print("Persisting sa result file")
                        with open(sa_result_file, 'w') as f:
                            json.dump(StaticDepGraph.sa_result_cache, f, indent=4)
                iteration += 1
                curr_insn, curr_func, curr_prog, curr_node = worklist.popleft()
                print("[static_dep] Running analysis at iteration: "
                      + str(iteration) + " insn: " + hex(curr_insn) + " func: " + curr_func)
                if curr_node is not None and curr_node.explained:
                    print("[static_dep] Node already explained, skipping ...")
                    print ("[static_dep] " + str(curr_node))
                    continue

                node_count_before = 0
                graph = StaticDepGraph.get_graph(curr_func, curr_insn)
                if graph is not None:
                    node_count_before += len(graph.nodes_in_cf_slice)
                    node_count_before += len(graph.nodes_in_df_slice)

                new_nodes = StaticDepGraph.build_dependencies_in_function(curr_insn, curr_func, curr_prog, curr_node)
                for new_node in new_nodes:
                    worklist.append([new_node.insn, new_node.function, prog, new_node]) #FIMXE, ensure there is no duplicate work

                node_count_after = 0
                graph = StaticDepGraph.get_graph(curr_func, curr_insn)
                if graph is not None:
                    node_count_after += len(graph.nodes_in_cf_slice)
                    node_count_after += len(graph.nodes_in_df_slice)
                total_node_count += (node_count_after - node_count_before)
                print("[static_dep] Current node count: " + str(total_node_count))
                if total_node_count > limit:
                    break
            print("[static_dep] No more events to analyze.")
            if parallelize_rr is False:
                for graph in StaticDepGraph.func_to_graph.values():
                    if graph.changed is False:
                        continue
                    graph.build_control_flow_dependencies(set(), final=True)
                    graph.merge_nodes(graph.nodes_in_df_slice, final=True)
                    if TRACKS_DIRECT_CALLER: graph.merge_callsite_nodes()
                for graph in StaticDepGraph.func_to_graph.values():
                    if graph.changed is False:
                        continue
                    graph.merge_nodes(graph.none_df_starting_nodes, final=True, interprocedural_set=([e[1] for e in starting_events]))
                    for n in graph.nodes_in_cf_slice.keys():
                        print(str(n))
                    for n in graph.nodes_in_df_slice.keys():
                        print(str(n))
                    graph.remove_extra_nodes(set([e[1] for e in starting_events]))

                StaticDepGraph.sanity_check()
                StaticDepGraph.find_entry_and_exit_nodes()
                StaticDepGraph.build_reverse_postorder_list()
                StaticDepGraph.build_postorder_list()
                StaticDepGraph.detect_df_backedges()
                #if GENERATE_INSN_MAPPING:
                #    StaticDepGraph.build_binary_indices(prog)
                #    StaticDepGraph.output_indices_mapping(indice_file)
                StaticDepGraph.print_graph_info()
        except Exception as e:
            print("Caught exception: " + str(e))
            print(str(e))
            print("-" * 60)
            traceback.print_exc(file=sys.stdout)
            print("-" * 60)
        except AssertionError as ae:
            print("Failed assertion: " + str(ae))
        except KeyboardInterrupt:
            print('Interrupted')
        finally:
            pass

        if rr_result_size != len(StaticDepGraph.rr_result_cache):
            print("Persisting rr result file")
            with open(rr_result_file, 'w') as f:
                json.dump(StaticDepGraph.rr_result_cache, f, indent=4)
        if sa_result_size != len(StaticDepGraph.sa_result_cache):
            print("Persisting sa result file")
            with open(sa_result_file, 'w') as f:
                json.dump(StaticDepGraph.sa_result_cache, f, indent=4)

        if bb_result_size != len(StaticDepGraph.bb_result_cache):
            print("Persisting bb result file")
            with open(bb_result_file, 'w') as f:
                json.dump(StaticDepGraph.bb_result_cache, f, indent=4)

        if parallelize_rr is False:
            print("Persisting static graph result file")
            StaticDepGraph.writeJSON(result_file)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Connect to server and send data
                sock.connect((HOST, PORT))
                sock.sendall(bytes("FIN" + "\n", "utf-8"))
                print("[main] sending to socket: FIN")
        end = time.time()
        print("[static_dep] static analysis took a total time of: " + str(end - start))
        return False

    @staticmethod
    def output_indices_mapping(result_file):
        indices = []
        inner_indices = []
        for graph in StaticDepGraph.func_to_graph.values():
            for node in itertools.chain(graph.none_df_starting_nodes, \
                                        graph.nodes_in_cf_slice.keys(), \
                                        graph.nodes_in_df_slice.keys()):
                if node.explained is False:
                    continue
                indices.append([node.file, node.line, node.index, node.total_count])

                is_inner = True
                for p in itertools.chain(node.cf_predes, node.df_predes):
                    if p.explained is False:
                        is_inner = False
                        break
                if is_inner is False:
                    continue
                inner_indices.append([node.file, node.line, node.index, node.total_count])
        with open(result_file, 'w') as f:
            json.dump(indices, f, indent=4)
        with open(result_file + "_inner", 'w') as f:
            json.dump(inner_indices, f, indent=4)

    @staticmethod
    def insert_file_line_to_map(node, file, line):
        if file is not None and line is not None:
            lines = StaticDepGraph.file_to_line_to_nodes.get(file, None)
            if lines is None:
                lines = {}
                StaticDepGraph.file_to_line_to_nodes[file] = lines
            nodes = lines.get(line, None)
            if nodes is None:
                nodes = set()
                lines[line] = nodes
            nodes.add(node)

    @staticmethod
    def generate_file_line_for_all_reachable_nodes(prog, our_source_code_dir=None):
        a = time.time()
        all_insns = set()
        for graph in StaticDepGraph.func_to_graph.values():
            for node in itertools.chain(graph.none_df_starting_nodes,
                                        graph.nodes_in_cf_slice.keys(),
                                        graph.nodes_in_df_slice.keys()):
                all_insns.add(node.insn)
                #if len(all_insns) > 100:
                #    break

        all_insns = list(all_insns)
        ret = execute_cmd_in_parallel([hex(insn) for insn in all_insns], 'get_file_line.sh', 'insns_', num_processor, prog)

        assert(len(ret) == len(all_insns))
        insn_to_file_line = {}
        i = 0
        print("[indices] total number of file lines to parse: " + str(len(ret)))
        for l in ret:
            file, line = parse_get_line_output(l)
            insn = all_insns[i]
            i += 1
            assert insn not in insn_to_file_line
            insn_to_file_line[insn] = [file, line]
            print("[indices] initial parse insn: " + hex(insn) + " file: " + file + " line: " + str(line))

        for graph in StaticDepGraph.func_to_graph.values():
            for node in itertools.chain(graph.none_df_starting_nodes,
                                        graph.nodes_in_cf_slice.keys(),
                                        graph.nodes_in_df_slice.keys()):
                print("[indices] Looking for file and line for " + hex(node.insn), flush=True)
                assert node.insn in insn_to_file_line
                #if node.insn not in insn_to_file_line:
                #    continue
                file_line = insn_to_file_line[node.insn]
                node.file = file_line[0] if our_source_code_dir is None else \
                    file_line[0][file_line[0].startswith(our_source_code_dir) and len(our_source_code_dir):]
                node.line = file_line[1]
                print("[indices] assignment insn: " + hex(node.insn) + " file " + node.file + " line " + str(node.line), flush=True)
                StaticDepGraph.insert_file_line_to_map(node, node.file, node.line)
        b = time.time()
        print("[indices] generate file line for all reachable_nodes took: " + str(b-a), flush=True)

    @staticmethod
    def build_binary_indices(prog):
        a = time.time()

        all_file_lines_map = {}
        for file in StaticDepGraph.file_to_line_to_nodes:
            for line in StaticDepGraph.file_to_line_to_nodes[file]:
                file_line = file.split("/")[-1] + ":" + str(line)
                all_file_lines_map[file + ":" + str(line)] = file_line

        all_file_lines = []
        all_file_lines_inputs = []
        for k in all_file_lines_map:
            all_file_lines.append(k)
            all_file_lines_inputs.append(all_file_lines_map[k])

        ret = execute_cmd_in_parallel(all_file_lines_inputs, 'get_insn_offsets.sh', 'file_lines_', num_processor, prog)

        file_line_to_offsets = {}
        i = 0
        group = set()
        for l in ret:
            if l.strip() != "DELIMINATOR":
                group.add(l.strip())
                continue
            file_line = all_file_lines[i]
            assert file_line not in file_line_to_offsets
            offsets = []
            file_line_to_offsets[file_line] = offsets
            for o in group:
                start, end = parse_insn_offsets(o)
                offsets.append([start, end])
            group = set()
            i += 1

        for file in StaticDepGraph.file_to_line_to_nodes:
            for line in StaticDepGraph.file_to_line_to_nodes[file]:
                file_line = file + ":" + str(line)
                #if file_line not in file_line_to_offsets:
                #    continue
                offsets = file_line_to_offsets[file_line]
                print("[indices] Offsets are: " + str(offsets))
                nodes = StaticDepGraph.file_to_line_to_nodes[file][line]
                all_nodes = set(nodes)
                for start_end in itertools.chain(offsets, [[float('inf'), float('-inf')]]):
                    start = start_end[0]
                    end = start_end[1]

                    node_list = []
                    addrs = []
                    func = None
                    nodes_to_remove = set()
                    for n in all_nodes:
                        include = True
                        if n.insn > end or n.insn < start:
                            include = False
                            distances = []
                            for se in offsets:
                                distances.append([abs(se[0] - n.insn), se[0]])
                            distances = sorted(distances, key=lambda pair: pair[0])

                            for pair in distances:
                                if pair[1] == start:
                                    include = True
                                    print("[indices] Include insn: " + hex(n.insn) + " to " + str(start_end))
                                break
                        if include is False:
                            continue

                        func = n.function
                        node_list.append(n)
                        addrs.append(n.insn)
                        if n.insn > end: end = n.insn + 1
                        if n.insn < start: start = n.insn
                        nodes_to_remove.add(n)
                    if len(nodes_to_remove) == 0:
                        continue
                    all_nodes = all_nodes.difference(nodes_to_remove)
                    indices = get_addr_indices(StaticDepGraph.binary_ptr, func, start, end, addrs)
                    print(indices)
                    print(len(node_list))
                    print(len(indices))
                    assert(len(indices) == len(node_list) + 1)
                    total_count = indices[-1] if (len(indices) == len(node_list) + 1) else None
                    for i in range(len(node_list)):
                        index = indices[i]
                        node_list[i].index = index if index >= 0 else None
                        node_list[i].total_count = total_count
        assert(len(all_nodes) == 0)
        b = time.time()
        print("[indices] build binary indices took: " + str(b-a))

    @staticmethod
    def align_indices(our_source_code_dir, other_source_code_dir):
        a = time.time()
        print("[indices] Directory containing the source codes: " + str(our_source_code_dir) + " " + str(other_source_code_dir))
        files = set()
        for graph in StaticDepGraph.func_to_graph.values():
            for node in itertools.chain(graph.none_df_starting_nodes,
                                        graph.nodes_in_cf_slice.keys(),
                                        graph.nodes_in_df_slice.keys()):
                if node.file is not None:
                    files.add(node.file)

        file_to_mapping = {}
        file_to_skip = set()
        file_path_changed = set()
        for file in files:
            f1 = os.path.join(our_source_code_dir, file)
            f2 = os.path.join(other_source_code_dir, file)
            print("[indices] comparing two files orig: " + str(f1) + " " + str(f2))
            if not os.path.exists(f1):
                f1 = find_file(our_source_code_dir, file)
                file_path_changed.add(file)
            if not os.path.exists(f2):
                f2 = find_file(other_source_code_dir, file)
                file_path_changed.add(file)
            print("[indices] comparing two files: " + str(f1) + " " + str(f2))
            if f1 is None or f2 is None:
                print("[indices] file not found: " + str(file))
                file_to_skip.add(file)
                continue
            map, _ = diff_two_files_and_create_line_mapps(f1, f2)
            file_to_mapping[file] = map

        seen = set()
        for graph in StaticDepGraph.func_to_graph.values():
            for node in itertools.chain(graph.none_df_starting_nodes,
                                        graph.nodes_in_cf_slice.keys(),
                                        graph.nodes_in_df_slice.keys()):
                if node.insn in seen:
                    continue
                seen.add(node.insn)
                if node.file in file_to_skip:
                    print("[indices] Skipping file that could not be found: " + str(node.file))
                    continue
                map = file_to_mapping[node.file]
                assert node.line in map, node.file + " " + str(node.line) + " " + hex(node.insn)
                old_line = node.line
                node.line = map[node.line]
                old_file = node.file
                if node.file in file_path_changed:
                    node.file = node.file.split("/")[-1]
                print("[indices] Changing " + old_file + ":" + str(old_line) + " to " + node.file + ":" + str(node.line))
        b = time.time()
        print("[indices] realign file line for all reachable_nodes took: " + str(b-a))

    @staticmethod
    def print_graph_info():
        return
        total_count = 0
        for func in StaticDepGraph.func_to_graph:
            print("[static_dep] " + func + " has " + str(
                len(StaticDepGraph.func_to_graph[func].nodes_in_cf_slice)) + " cf nodes and " \
                  + str(len(StaticDepGraph.func_to_graph[func].nodes_in_df_slice)) + " df nodes")
            total_count += len(StaticDepGraph.func_to_graph[func].nodes_in_cf_slice)
            total_count += len(StaticDepGraph.func_to_graph[func].nodes_in_df_slice)
        print("[static_dep] Total number of static nodes: " + str(total_count))
        print("[static_dep] total number of nodes in the postorder list: "
              + str(len(StaticDepGraph.postorder_list)))
        """
        for func in StaticDepGraph.func_to_graph:
            print("[static_dep] " + func + " has " + str(
                len(StaticDepGraph.func_to_graph[func].nodes_in_cf_slice)) + " cf nodes")
            for n in StaticDepGraph.func_to_graph[func].nodes_in_cf_slice:
                if n not in StaticDepGraph.postorder_list:
                    print(n)
            print("[static_dep] " + func + " has " + str(
                len(StaticDepGraph.func_to_graph[func].nodes_in_df_slice)) + " df nodes")
            for n in StaticDepGraph.func_to_graph[func].nodes_in_df_slice:
                if n not in StaticDepGraph.postorder_list:
                    print(n)
        """

    @staticmethod
    def build_dependencies_in_function(insn, func, prog, initial_node):
        new_nodes = set()
        df_node = None
        if initial_node.is_df is True:
            df_node = initial_node
        iter = 0
        print("[static_dep] ", flush=True)
        print("[static_dep] Building dependencies for function: " + str(func))
        print("[static_dep] Existing node: ")
        print("[static_dep] " + str(initial_node))
        target_bbs = set()

        #make sure to find map the instruction to the function that contains it
        # in case there is a duplicate copy of the function in the binary
        graph = StaticDepGraph.get_graph(func, insn)
        if graph is not None:
            assert (graph.cfg.contains_insn(insn) is True)
            # cf nodes are not merged, they are discarded after info is pasted in!
            if initial_node.is_df is False:
                bb = graph.cfg.getBB(insn)
                target_bbs.add(bb)
                graph.build_control_flow_dependencies(target_bbs)
        else:
            graph = StaticDepGraph.make_graph(func, prog)

            graph.build_control_flow_nodes(insn)
            if len(graph.cfg.ordered_bbs) == 0:
                print("[static_dep][warn] Failed to load the cfg for function: "
                      + func + " ignoring the function...")
                return new_nodes

            if func in StaticDepGraph.pending_nodes:
                print("[static_dep] Adding pending nodes for function: " + func)
                for pending_node in StaticDepGraph.pending_nodes[func].values():
                    if not graph.cfg.contains_insn(pending_node.insn):
                        continue
                    graph.id_to_node[pending_node.id] = pending_node
                    graph.insn_to_node[pending_node.insn] = pending_node
                    del StaticDepGraph.pending_nodes[pending_node.insn]
                    #FIXME: remoe after?

            target_bbs.add(graph.cfg.ordered_bbs[0])
            graph.build_control_flow_dependencies(target_bbs)

            if TRACKS_DIRECT_CALLER:
                if func in StaticDepGraph.func_to_callsites:
                    callsites = StaticDepGraph.func_to_callsites[func]
                    print("[static_dep] Instantiating callsites for: " + func)
                    for c in callsites:
                        new_node = StaticDepGraph.make_or_get_cf_node(c[0], None, c[1])
                        new_nodes.add(new_node)
                        graph.pending_callsite_nodes.append(new_node)
        if initial_node.is_df is False:
            graph.none_df_starting_nodes.add(initial_node)
        """
        if df_node is not None:
            assert df_node.bb is None
            graph.merge_nodes([df_node])
            #TODO, also need to do dataflow tracing for this one!!
        """

        all_defs_in_diff_func = set()
        df_nodes = []
        if df_node is not None:
            df_nodes.append(df_node)
        new_local_defs_found = True
        while new_local_defs_found:
            new_local_defs_found = False
            print("[static_dep] Building dependencies for function: " + str(func) + " iteration: " + str(iter))
            iter += 1
            defs_in_same_func, intermediate_defs_in_same_func, defs_in_diff_func = graph.build_data_flow_dependencies(func, prog, df_nodes)
            all_defs_in_diff_func = all_defs_in_diff_func.union(defs_in_diff_func)
            if len(graph.cfg.ordered_bbs) == 0:
                print("[static_dep][warn] Previously failed to load the cfg for function: "
                      + func + " ignoring the function...")
                return all_defs_in_diff_func
            if len(defs_in_same_func) > 0 or len(intermediate_defs_in_same_func) > 0:
                new_bbs = [graph.cfg.getBB(defn.insn) for defn in defs_in_same_func]
                target_bbs = target_bbs.union(new_bbs)
                #new_bbs = [graph.cfg.getBB(defn.insn) for defn in intermediate_defs_in_same_func]
                #target_bbs = target_bbs.union(new_bbs)
                graph.build_control_flow_dependencies(target_bbs)
                new_local_defs_found = True
            for df_node in df_nodes:
                if df_node.explained is False: #TODO, an explained df node always used to have a BB
                    df_node.explained = True
                if df_node.is_cf is False and df_node.bb is not None:
                        continue
                    #assert df_node.bb is None, df_node
                defs_in_same_func.add(df_node)
                if df_node not in graph.nodes_in_df_slice:
                    graph.nodes_in_df_slice[df_node] = df_node
                #df_node = None
                # TODO, also need to do dataflow tracing for this one!!
            graph.merge_nodes(defs_in_same_func)
            df_nodes = list(intermediate_defs_in_same_func)

        new_nodes = all_defs_in_diff_func.union(new_nodes)
        return new_nodes

    def merge_callsite_nodes(self):
        print("[static_dep] Merging callsites nodes for graph: " + self.func)
        for entry_bb in self.cfg.entry_bbs:
            n = self.id_to_node[self.bb_id_to_node_id[entry_bb.id]]
            for callsite in self.pending_callsite_nodes:
                if n not in callsite.cf_succes:
                    callsite.cf_succes.append(n)
                if callsite not in n.cf_predes:
                    n.cf_predes.append(callsite)

    #FIXME, think about if this makes sense
    def merge_nodes(self, nodes, final=False, interprocedural_set=set()):
        print("[static_dep] Merging nodes for graph: " + self.func)
        if len(self.cfg.ordered_bbs) == 0:
            print("[static_dep][warn] Failed to load the cfg, ignoring merging the datanode...")
            return
        #if final is False:
        #     return
        # could happen that we try to merge the node with the same node,
        # in that case it should just work too
        for node in nodes:
            #assert node.is_df is True
            if not final and node.explained is True:
                print("[static_dep][warn] Node already explained, why merge again?")
                print(node)
            node.explained = True
            if final is False:
                continue
            bb = self.cfg.getBB(node.insn)
            node.bb = bb
            for prede in bb.predes:
                if prede in bb.backedge_sources:
                    continue
                prede_node_id = self.bb_id_to_node_id[prede.id]
                prede_node = self.id_to_node[prede_node_id]
                if prede_node not in node.cf_predes:
                    node.cf_predes.append(prede_node)
                if node not in prede_node.cf_succes:
                    prede_node.cf_succes.append(node)
            #This is specifically for the case of merging none df starting nodes
            # where the node is a starting event, ie first insn of a function
            # it needs to inherit the non local cf predes of the node created for the same BB
            # ie. the caller sites.
            if node.insn in interprocedural_set:
                twin_node_id = self.bb_id_to_node_id[bb.id]
                twin_node = self.id_to_node[twin_node_id]
                for prede_node in twin_node.cf_predes:
                    if prede_node not in node.cf_predes:
                        node.cf_predes.append(prede_node)
                    if node not in prede_node.cf_succes:
                        prede_node.cf_succes.append(node)
            """
            for succe in bb.succes:
                if succe in bb.backedge_targets:
                    continue
                succe_node_id = self.bb_id_to_node_id[succe.id]
                if self.id_to_node[succe_node_id] not in node.cf_succes:
                    node.cf_succes.append(self.id_to_node[succe_node_id])
            """

    def build_local_data_flow_dependencies(self, loads, succe, func,
                                           defs_in_same_func, intermediate_defs_in_same_func, defs_in_diff_func,
                                           prog):
        if loads is None or len(loads) == 0:
            return

        group = False if len(loads) <= 1 else True
        group_size = 0
        nodes = []
        for load in loads:
            prede, group_size = self.build_single_local_data_flow_dependency(load, succe, func, group, group_size,
                                                                             defs_in_same_func, intermediate_defs_in_same_func, defs_in_diff_func,
                                                                             prog)
            if prede is None:
                assert group_size is None
                continue
            nodes.append(prede)
        if group is True:
            print("Creating new group id: " + str(StaticNode.group_id) + " size " + str(group_size) + " parent " + hex(
                succe.insn))
            StaticNode.group_id += 1
        return nodes

    def build_single_local_data_flow_dependency(self, load, succe, func, group, group_size,
                                                defs_in_same_func, intermediate_defs_in_same_func, defs_in_diff_func,
                                                prog):
        prede_insn = load[0]
        prede_reg = load[1]
        shift = load[2]
        off = load[3]
        off_reg = load[4]
        read_same_as_write = load[5]
        is_bit_var = load[6]
        if succe.is_intermediate_node is True and succe.contains_bit_var() is True and is_bit_var is False:
            is_bit_var = True
        type = load[7]
        curr_func = load[8]
        # move definition to a different function if necessary
        if curr_func == func and self.cfg.contains_insn(prede_insn) is False:
            if len(StaticDepGraph.func_hot_and_cold_path_map) > 0 and  curr_func in StaticDepGraph.func_hot_and_cold_path_map:
                new_curr_func = StaticDepGraph.func_hot_and_cold_path_map[curr_func]
                print("[sg/warn] Changing the function name from " + curr_func + " to " + new_curr_func)
                curr_func = new_curr_func
            else:
                print("[sg/warn] Ignoring definition " + hex(prede_insn) + " which likely belongs to a duplicate of  " + curr_func)
                return None, None
        #if len(load) >= 10 and load[9] is not None and load[9] != '':
        dst_reg = load[9]
        #else:
        #    insn_to_func = []
        #    insn_to_func.append([str(prede_insn), curr_func])
        #    results1 = get_reg_read_or_written(StaticDepGraph.binary_ptr, insn_to_func, False)
        #    dst_reg = results1[0][2].lower()

        bit_ops = None
        if len(load) >= 11:
            bit_ops = load[10]

        assert shift != '', str(load)
        assert off != '', str(load)
        # print(succe)
        # if succe.insn == prede_insn and read_same_as_write is False:
        #    print("[static_dep][warn]Ignoring the predecessor as it is the same as the successor: ")
        #    print(succe)
        # else:
        prede = StaticDepGraph.make_or_get_df_node(prede_insn, None,
                                                   curr_func)  # TODO, might need to include func here too
        if group is True:
            if prede.group_insns is None:
                prede.group_insns = []
            if succe.insn in prede.group_insns:
                group is False
            else:
                prede.group_insns.append(succe.insn)
                if prede.group_ids is None:
                    prede.group_ids = []
                prede.group_ids.append(StaticNode.group_id)
                group_size += 1
                if StaticNode.group_id not in StaticDepGraph.group_to_nodes:
                    StaticDepGraph.group_to_nodes[StaticNode.group_id] = set()
                StaticDepGraph.group_to_nodes[StaticNode.group_id].add(prede)
        # print(prede)
        if prede == succe and read_same_as_write is False:
            if succe.mem_load is None:
                succe.explained = False
            # TODO, sometimes statically slicing the same node end up returning the same node cuz its a mem read
            #     still keep explaining!
            # TODO, need better scheme for checking I guess
        if prede.explained is False or read_same_as_write is True:
            if type == 'memread':
                if off_reg is not None and off_reg.lower() == 'ds':
                    print("[warn] ignoring the offset register DS")
                    off_reg = ''
                    off = 0
                if prede.mem_load is None:
                    prede.mem_load = MemoryAccess(prede_reg, shift, off, off_reg, is_bit_var)
                prede.mem_load.add_bit_operationses(bit_ops)
                prede.reg_store = dst_reg  # TODO put actual register name here
                if read_same_as_write is True and succe.mem_store is not None: 
                    # this is a hack, if there is no mem store then don't worry about the mem load...
                    prede.mem_load.read_same_as_write = True
                    succe.mem_store.read_same_as_write = True
                    succe.mem_store.add_bit_operationses(bit_ops)
                else:
                    prede.mem_load.read_same_as_write = False
            elif type == 'regread':
                prede.reg_load = prede_reg.lower()
            elif type == 'empty':
                return prede, group_size# pass
            else:
                print("type not supported " + str(type))
                # raise Exception

        if prede != succe:
            if prede not in succe.df_predes:
                succe.df_predes.append(prede)
            if succe not in prede.df_succes:
                prede.df_succes.append(succe)
            # This could only happen when the analysis goes into another function
            # and is instructed to stop even if it could make further progress
            # therefore could stop at a memory load (stack load) explanable by static analysis
            if succe.mem_load is not None:
                succe.mem_load = None
        if prede.explained is False:
            if len(load) >= 12 and load[11] is True: # and prede != succe:
                intermediate_defs_in_same_func.add(prede)
                prede.is_intermediate_node = True
            elif curr_func != func:
                defs_in_diff_func.add(prede)
            else:
                if prede.reg_load is not None and prede.mem_load is None and prede != succe:
                    # TODO, should make this prettier,
                    # but sometimes dyninst will stop slicing at reg load
                    # possibly cuz the reg is pass by reference?
                    # in this case, wanna slice again, in the next iteration
                    defs_in_diff_func.add(prede)
                    print("Dyninst stopped at reg load? slice again")
                    print(prede)
                else:
                    defs_in_same_func.add(prede)
        # if read_same_as_write is True:
        #    prede.explained = True
        # else:
        # assert prede.mem_load is not None or prede.reg_load is not None, str(prede)
        return prede, group_size

    def build_data_flow_dependencies(self, func, prog, df_nodes=[]):
        print("[static_dep] Building dataflow dependencies local in function: " + str(func))
        defs_in_same_func = set()
        intermediate_defs_in_same_func = set()
        defs_in_diff_func = set()

        slice_starts = []
        addr_to_node = {}
        for node in self.nodes_in_cf_slice.keys():
            #assert node.is_cf is True, str(node) TODO
            if node in df_nodes: #TODO, sometimes it could be a df node too...
                continue
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
        for df_node in df_nodes: #TODO, registers?
            if df_node.explained is True:
                continue
            #TODO, change this later, the RR analysis should really return the src reg being loaded
            if df_node.mem_load is not None:
                regLoad = ""
            elif df_node.reg_load is not None and df_node.reg_load != "":
                regLoad = df_node.reg_load
            else:
                regLoad = "SPECIAL"
            slice_starts.append([regLoad.lower(), df_node.insn, df_node.function,
                                 df_node.contains_bit_var() if df_node.is_intermediate_node is False else False])
            #TODO for now, just ignore those that writes to memory in SA
            assert df_node.insn not in addr_to_node
            addr_to_node[df_node.insn] = df_node

        results = static_backslices(StaticDepGraph.binary_ptr, slice_starts, prog, StaticDepGraph.sa_result_cache)
        for result in results:
            #reg_name = result[0]
            insn = result[1]
            loads = result[2]
            succe = addr_to_node[insn]
            self.build_local_data_flow_dependencies(loads, succe, func,
                                                    defs_in_same_func, intermediate_defs_in_same_func, defs_in_diff_func,
                                                    prog)
        print("[static_dep] Found " + str(len(defs_in_same_func)) + " dataflow nodes local in function ")


        print("[static_dep] Building dataflow dependencies non-local to function: " + str(func))
        for node in defs_in_same_func:
            if VERBOSE: print(str(node))
            #assert node.is_cf is False
            assert node.is_df is True
            if node.explained is True:
                continue
            #assert node.explained is False
            print("[static_dep] Looking for dataflow dependencies potentially non-local to function: " + str(func) \
                  + " for read " + str(node.mem_load) + " @ " + hex(node.insn))
            print(node)

            if node.mem_load is None:
                node.explained = True
                print("[warn] node does not have memory load?")
                continue

            if node.mem_load.read_same_as_write is True:
                node.explained = True
                print("Node read same as write, do no watch using RR...")
                continue

            branch_insn = None
            target_insn = None
            closest_dep_branch_node = self.get_closest_dep_branch(node)
            if closest_dep_branch_node is not None:
                farthest_target_node = self.get_farthest_target(closest_dep_branch_node)
                if farthest_target_node is not None:
                    branch_insn = closest_dep_branch_node.bb.last_insn
                    target_insn = farthest_target_node.insn
                    print("Closest dependent branch is at " + hex(branch_insn))
                    print("Farthest target is at " + hex(target_insn))
                else:
                    print("[warn] closest dep branch is found but not the farthest target node?")
            try:
                results = rr_backslice(StaticDepGraph.binary_ptr, prog, branch_insn, target_insn, #4234305, 0x409C41 | 4234325, 0x409C55
                                   node.insn, node.mem_load.reg, node.mem_load.shift, node.mem_load.off,
                                   node.mem_load.off_reg, StaticDepGraph.rr_result_cache) #, StaticDepGraph.rr_result_cache)
            except Exception as e:
                print("Calling RR failed")
                #print(str(e))
                #print("-" * 60)
                #traceback.print_exc(file=sys.stdout)
                #print("-" * 60)
                #raise e
                continue
            print("[static_dep] found " + str(len(results)) + " dataflow dependencies non-local to function")

            print(str(results))
            if VERBOSE: print(results)
            for result in results:
                # reg_name = result[0]
                load = result[0]
                prede_insn = result[1]
                curr_func = result[2]
                #if len(result) > 3 and result[3] is not None and result[3] != '':
                src_reg = result[3]
                #else:
                #    insn_to_func = []
                #    insn_to_func.append([str(prede_insn), curr_func])
                #    results1 = get_reg_read_or_written(StaticDepGraph.binary_ptr, insn_to_func, True)
                #    src_reg = results1[0][2].lower()

                if load is None: #TODO why?
                    continue

                prede_reg = load[0]
                if load[1] == '':  #TODO, when get time, re-run rr, no need to check already fixed
                    shift = 0
                elif isinstance(load[1], str):
                    shift = int(load[1], 16)
                else:
                    shift = load[1]

                if load[2] == '':  #TODO, when get time, re-run rr, no need to check already fixed
                    off = 0
                elif isinstance(load[2], str):
                    off = int(load[2], 16)
                else:
                    off = load[2]

                off_reg = None
                if len(load) >=4:
                    #print("Found offset reg")
                    if load[3] == '':
                        off_reg = None
                    else:
                        off_reg = load[3]
                if len(load) >= 13:
                    off1 = load[12]

                #print(hex(prede_insn))
                prede = self.make_or_get_df_node(prede_insn, None, curr_func)
                if prede.explained is False:
                    prede.mem_store = MemoryAccess(prede_reg, shift, off, off_reg, node.mem_load.is_bit_var)
                    prede.reg_load = src_reg  # TODO put actual register name here
                    if curr_func != func :
                        defs_in_diff_func.add(prede)
                    elif self.cfg.contains_insn(prede_insn) is False:
                        print("[static_dep][warn] Found a remote definition in the duplicate of the same function: " + hex(prede_insn))
                        defs_in_diff_func.add(prede)
                    else:
                        intermediate_defs_in_same_func.add(prede)
                else:
                    if prede.mem_store is None and prede.reg_load is None:
                        print('[static_dep][warn] predecessor already explained '
                              'but no memory store or register load found?' + str(prede))

                if prede != node:
                    node.df_predes.append(prede)
                    prede.df_succes.append(node)
                else:
                    node.mem_load.read_same_as_write = True
                    node.mem_store.read_same_as_write = True
            node.explained = True

        print("[static_dep] Total number of      new     nodes in local dataflow slice: " + str(len(defs_in_same_func)) + " " + \
              str([hex(node.insn) for node in defs_in_same_func]))
        if VERBOSE:
            for node in defs_in_same_func:
                print(str(node))

        print("[static_dep] Total number of intermediate nodes in local dataflow slice: " + str(len(intermediate_defs_in_same_func)) + " " + \
              str([hex(node.insn) for node in intermediate_defs_in_same_func]))
        if VERBOSE:
            for node in intermediate_defs_in_same_func:
                print(str(node))

        print("[static_dep] Total number of     new      nodes in remote dataflow slice: " + str(len(defs_in_diff_func)) + " " + \
              str([hex(node.insn) for node in defs_in_diff_func]))
        if VERBOSE:
            for node in defs_in_diff_func:
                print(str(node))

        for d in defs_in_same_func:
            if d not in self.nodes_in_df_slice:
                self.nodes_in_df_slice[d] = d
        print("[static_dep] Total number of nodes in data flow slice: " + str(len(self.nodes_in_df_slice)) + " " + \
              str([hex(node.insn) for node in self.nodes_in_df_slice.keys()]))

        return defs_in_same_func, intermediate_defs_in_same_func, defs_in_diff_func

    def build_control_flow_nodes(self, insn):
        print("[static_dep] Building control flow nodes for graph: " + self.func + " starting from: " + hex(insn))
        self.cfg = CFG(self.func, self.prog)
        # Build the control flow graph for the entire function then slice
        self.cfg.build(insn)  # FIXME: for now, order the BBs such that the one that contains insn appears first
        #first = True
        # FIXME, make the logic less awkward?
        for bb in self.cfg.ordered_bbs:
            #if first:
                #node = StaticDepGraph.make_or_get_cf_node(insn, bb, self.func)
                #first = False
            #else:
                #node = StaticDepGraph.make_or_get_cf_node(bb.last_insn, bb, self.func)
            node = StaticDepGraph.make_or_get_cf_node(bb.last_insn, bb, self.func, self)
            if node.function != self.func:
                if self.func == "__wt_page_alloc" and node.function.startswith("__wt_page_inmem.") or \
                        node.function == "__wt_page_alloc" and self.func.startswith("__wt_page_inmem."):
                    pass
                else:
                    assert StaticDepGraph.func_hot_and_cold_path_map[node.function] == self.func, node.function + " " + self.func + " " + hex(bb.last_insn)
                    assert StaticDepGraph.func_hot_and_cold_path_map[self.func] == node.function, node.function + " " + self.func + " " + hex(bb.last_insn)
                self.id_to_node[node.id] = node
                self.insn_to_node[node.insn] = node

            if node is None:
                continue
            self.bb_id_to_node_id[bb.id] = node.id
            if bb.id in self.cfg.id_to_bb_in_slice:
                self.nodes_in_cf_slice[node] = node

        print("[static_dep] Total initial number of nodes in control flow slice: " + str(len(self.nodes_in_cf_slice)) + " " + \
              str([hex(self.id_to_node[node_id].insn) for node_id in self.id_to_node]))
        if VERBOSE:
            for node_id in self.id_to_node:
                print(str(self.id_to_node[node_id]))


    def build_control_flow_dependencies(self, target_bbs, final=False):
        if final is False:
            self.changed = True
        self.cfg.target_bbs = self.cfg.target_bbs.union(target_bbs)
        if self.cfg.jsonified is True and final is False:
            print("Re-constructing the CFG for " + self.func)
            orig_start_insn_to_bb = {}
            for bb in self.cfg.ordered_bbs:
                assert bb.start_insn not in orig_start_insn_to_bb
                orig_start_insn_to_bb[bb.start_insn] = bb
                # print(bb)
                bb.backedge_targets = []
                bb.backedge_sources = []
                bb.predes = []
                bb.succes = []
            # print("=====================================================")
            if len(self.cfg.ordered_bbs) == 0:
                print("[warn] function " + self.func + " has no BBs.")
                return
            cfg = CFG(self.func, self.prog)
            cfg.build(self.cfg.ordered_bbs[0].start_insn)
            # new_start_insn_to_bb = {}
            # print("=====================================================")
            id_map = {}
            for bb in cfg.ordered_bbs:
                # assert bb.start_insn not in new_start_insn_to_bb
                # new_start_insn_to_bb[bb.start_insn] = bb
                orig_bb = orig_start_insn_to_bb[bb.start_insn]
                id_map[bb.id] = orig_bb.id
                orig_bb.backedge_targets = [orig_start_insn_to_bb[b.start_insn] for b in bb.backedge_targets]
                orig_bb.backedge_sources = [orig_start_insn_to_bb[b.start_insn] for b in bb.backedge_sources]
                orig_bb.predes = [orig_start_insn_to_bb[b.start_insn] for b in bb.predes]
                orig_bb.succes = [orig_start_insn_to_bb[b.start_insn] for b in bb.succes]
                # print(orig_bb)
            print("BB id mappings: " + str(id_map))
            self.cfg.jsonified = False
        # print(self.bb_id_to_node_id)

        self.cfg.slice(final)

        if final is True:
            for bb_id in self.cfg.id_to_bb:
                node_id = self.bb_id_to_node_id[bb_id]
                node = self.id_to_node[node_id]
                node.cf_predes = []
                node.cf_succes = []

        for bb_id in self.cfg.id_to_bb_in_slice:
            bb = self.cfg.id_to_bb[bb_id]
            node_id = self.bb_id_to_node_id[bb_id]
            node = self.id_to_node[node_id]

            #print("BB id: " + str(bb_id) + " node insn: " + hex(node.insn))
            #if final is True:
            #    node.cf_predes = []
            #    node.cf_succes = []
            for prede in bb.predes:
                #assert prede not in bb.backedge_targets, str(bb)
                if prede in bb.backedge_sources:
                    continue
                if prede.id not in self.cfg.id_to_bb_in_slice:
                    continue
                prede_node_id = self.bb_id_to_node_id[prede.id]
                if self.id_to_node[prede_node_id] not in node.cf_predes:
                    node.cf_predes.append(self.id_to_node[prede_node_id])
            for succe in bb.succes:
                if succe in bb.backedge_targets:
                    continue
                if succe.id not in self.cfg.id_to_bb_in_slice:
                    continue
                succe_node_id = self.bb_id_to_node_id[succe.id]
                if self.id_to_node[succe_node_id] not in node.cf_succes:
                    node.cf_succes.append(self.id_to_node[succe_node_id])
            if node not in self.nodes_in_cf_slice:
                self.nodes_in_cf_slice[node] = node

        print("[static_dep] Total number of nodes in control flow slice: " + str(len(self.nodes_in_cf_slice)) + " " + \
              str([hex(node.insn) for node in self.nodes_in_cf_slice.keys()]))
        if VERBOSE:
            for node in self.nodes_in_cf_slice.keys():
                print(str(node))

    def remove_extra_nodes(self, targets):
        #TODO, technically, all slice nodes should be in id_to_node ...
        all_nodes = set()
        all_nodes = all_nodes.union(self.id_to_node.values())
        print("Removing extra nodes for " + self.func + " " +
              str([n.id for n in all_nodes]))
        #all_nodes = all_nodes.union(self.nodes_in_df_slice)
        #all_nodes = all_nodes.union(self.nodes_in_cf_slice)
        for node in all_nodes:
            if len(node.cf_succes) > 0 or len(node.df_succes) > 0:
                continue

            worklist = deque()
            worklist.append(node)
            while len(worklist) > 0:
                curr = worklist.popleft()
                graph = StaticDepGraph.get_graph(curr.function, curr.insn)
                if graph is None:
                    continue
                print(curr)
                if len(curr.cf_succes) == 0 and len(curr.df_succes) == 0:
                    if curr.insn in targets:
                        continue
                    if curr in graph.nodes_in_cf_slice:
                        del graph.nodes_in_cf_slice[curr]
                        curr.print_node("Removing node from cf slice because it has no successors: ")
                    if curr in graph.nodes_in_df_slice:
                        del graph.nodes_in_df_slice[curr]
                        curr.print_node("Removing node from df slice because it has no successors: ")
                    for p in node.cf_predes:
                        if node in p.cf_succes:
                            p.cf_succes.remove(node)
                            worklist.append(p)
                    for p in node.df_predes:
                        if node in p.df_succes:
                            p.df_succes.remove(node)
                            worklist.append(p)

        print("[static_dep] Total number of nodes in control flow slice after trimming: " + str(len(self.nodes_in_cf_slice)) + " " + \
              str([hex(node.insn) for node in self.nodes_in_cf_slice.keys()]))
        if VERBOSE:
            for node in self.nodes_in_cf_slice.keys():
                print(str(node))

    @staticmethod
    def find_entry_and_exit_nodes():
        print("[static_dep] Finding the entry and exit nodes.")
        assert len(StaticDepGraph.entry_nodes) == 0
        assert len(StaticDepGraph.exit_nodes) == 0
        for graph in StaticDepGraph.func_to_graph.values():
            pending = StaticDepGraph.pending_nodes[graph.func] if graph.func in StaticDepGraph.pending_nodes else []
            nodes = set()
            for node in itertools.chain(graph.id_to_node.values(), pending.values()):
                nodes.add(node)
            for node in nodes:
                if node.explained and node not in graph.nodes_in_df_slice and node not in graph.nodes_in_cf_slice:
                    continue
                if len(node.cf_predes) == 0 and len(node.df_predes) == 0 and \
                    len(node.cf_succes) == 0 and len(node.df_succes) == 0:
                    continue
                if len(node.cf_predes) == 0 and len(node.df_predes) == 0:
                    if node in StaticDepGraph.entry_nodes: continue
                    assert node not in StaticDepGraph.exit_nodes
                    StaticDepGraph.entry_nodes.add(node)
                if len(node.cf_succes) == 0 and len(node.df_succes) == 0:
                    if node in StaticDepGraph.exit_nodes: continue
                    assert node not in StaticDepGraph.entry_nodes, node
                    StaticDepGraph.exit_nodes.add(node)

        print("\n[static_dep] total number of entry nodes: " + str(len(StaticDepGraph.entry_nodes)))
        print("===========================================================================")
        for entry in StaticDepGraph.entry_nodes:
            print(entry)
        print("===========================================================================")
        print("\n[static_dep] total number of exit nodes: " + str(len(StaticDepGraph.exit_nodes)))
        print("===========================================================================")
        for exit in StaticDepGraph.exit_nodes:
            print(exit)
        print("===========================================================================")

        print("[static_dep] total number of entry nodes: " + str(len(StaticDepGraph.entry_nodes)))
        print("[static_dep] total number of exit nodes: " + str(len(StaticDepGraph.exit_nodes)))

    @staticmethod
    def build_reverse_postorder_list_helper(node, visited):
        print("[static_dep] Building reverse postorder list.")
        if node in visited:
            return
        visited.add(node)
        for s in node.cf_succes:
            StaticDepGraph.build_reverse_postorder_list_helper(s, visited)
        for s in node.df_succes:
            StaticDepGraph.build_reverse_postorder_list_helper(s, visited)
        StaticDepGraph.reverse_postorder_list.append(node)
        return

    # a node can be visited if all its predecessors are visited
    @staticmethod
    def build_reverse_postorder_list_old(): #TODO, save the postorder list too #FIXME: as a potential of stack overflow
        StaticDepGraph.reverse_postorder_list = []
        visited = set()
        for node in StaticDepGraph.entry_nodes:
            StaticDepGraph.build_reverse_postorder_list_helper(node, visited)
        print("[static_dep] total number of nodes in the reverse postorder list: "
              + str(len(StaticDepGraph.reverse_postorder_list)))

    @staticmethod
    def build_reverse_and_none_reverse_postorder_list_helper(reverse):
        q = deque()
        visited = set()
        for node in reversed(list(StaticDepGraph.entry_nodes if reverse is True else StaticDepGraph.starting_nodes)):
            q.appendleft([node, None])
        while len(q) > 0:
            (node, parent) = q.popleft()
            if node in visited:
                if parent is not None:
                    StaticDepGraph.reverse_postorder_list.append(parent)
                continue
            visited.add(node)
            nodes = []
            for n in (node.cf_succes if reverse is True else node.cf_predes):
                nodes.append([n, None])
            for n in (node.df_succes if reverse is True else node.df_predes):
                nodes.append([n, None])
            if len(nodes) > 0:
                nodes[-1][1] = node
                for n in reversed(nodes):
                    q.appendleft(n)
            else:
                StaticDepGraph.reverse_postorder_list.append(node)

    @staticmethod
    def build_reverse_postorder_list():
        StaticDepGraph.build_reverse_and_none_reverse_postorder_list_helper(True)

    @staticmethod
    def build_postorder_list():
        StaticDepGraph.build_reverse_and_none_reverse_postorder_list_helper(False)

    @staticmethod
    def build_postorder_list_helper(node, visited):
        #node.print_node("postorder_list visiting node: ")
        if node.explained is False:
            return
        if node in visited:
            return
        visited.add(node)
        for s in node.cf_predes: #FIXME change to p
            StaticDepGraph.build_postorder_list_helper(s, visited)
        for s in node.df_predes:
            StaticDepGraph.build_postorder_list_helper(s, visited)
        StaticDepGraph.postorder_list.append(node)

    """
    # a node can be visited if all its successors are visited
    @staticmethod
    def build_postorder_list(): #TODO, save the postorder list too #FIXME: as a potential of stack overflow
        visited = set()
        for node in StaticDepGraph.exit_nodes:
            StaticDepGraph.build_postorder_list_helper(node, visited)
        print("[static_dep] total number of nodes in the postorder list: "
              + str(len(StaticDepGraph.postorder_list)))
    """

    @staticmethod
    def build_postorder_list_old(): #TODO, save the postorder list too #FIXME: as a potential of stack overflow
        print("[static_dep] Building postorder list.")
        StaticDepGraph.postorder_list = []
        visited = set()
        for node in StaticDepGraph.starting_nodes:
            StaticDepGraph.build_postorder_list_helper(node, visited)
        print("[static_dep] total number of nodes in the postorder list: "
              + str(len(StaticDepGraph.postorder_list)))

    @staticmethod
    def build_postorder_ranks():
        StaticDepGraph.postorder_ranks = {}
        index = 0
        for node in StaticDepGraph.postorder_list:
            StaticDepGraph.postorder_ranks[node] = index
            index += 1

    @staticmethod
    def detect_df_backedges_helper(node, visited_cf_nodes, visited_df_nodes, new_funcs):
        if node in visited_df_nodes:
            return
        visited_df_nodes.add(node)
        for cf_prede in node.cf_predes:
            if cf_prede in visited_cf_nodes:
                node.backedge_targets.add(cf_prede.insn)
                cf_prede.backedge_sources.add(node.insn)
                print("Backedge detected: " )
                node.print_node(" source: ")
                cf_prede.print_node(" target: ")
            new_funcs.add(cf_prede.function)
        for df_prede in node.df_predes:
            StaticDepGraph.detect_df_backedges_helper(df_prede, visited_cf_nodes, visited_df_nodes, new_funcs)
            new_funcs.add(df_prede.function)

    @staticmethod
    def detect_df_backedges(): #TODO, save the postorder list too #FIXME: as a potential of stack overflow
        print("[static_dep] Detecting dataflow backedges.")
        visited_cf_nodes = set()
        visited_df_nodes = set()
        visited_funcs = set()
        worklist = deque()
        for graph in StaticDepGraph.func_to_graph.values():
            for node in graph.id_to_node.values():
                node.backedge_targets = set()
                node.backedge_sources = set()
        for node in StaticDepGraph.starting_nodes:
            worklist.append(node.function)
        while len(worklist) > 0:
            func = worklist.popleft()
            visited_funcs.add(func)
            if func not in StaticDepGraph.func_to_graph:
                continue
            graph = StaticDepGraph.func_to_graph[func]
            for bb in graph.cfg.postorder_list:
                node_id = graph.bb_id_to_node_id[bb.id]
                node = graph.id_to_node[node_id]
                if node in graph.nodes_in_cf_slice:
                    visited_cf_nodes.add(node)
                    for df_prede in node.df_predes:
                        new_funcs = set()
                        StaticDepGraph.detect_df_backedges_helper(df_prede, visited_cf_nodes, visited_df_nodes, new_funcs)
                        for new_func in new_funcs.difference(visited_funcs):
                            if new_func not in worklist:
                                worklist.append(new_func)
                                for duplicate_name in StaticDepGraph.get_duplicate_names(new_func):
                                    worklist.append(duplicate_name)

        #print("[static_dep] total number of nodes in the postorder list: "
        #      + str(len(StaticDepGraph.postorder_list)))

    @staticmethod
    def sanity_check():
        print("[static_dep] Performing sanity check.")
        bad_count = 0
        for graph in StaticDepGraph.func_to_graph.values():
            assert (len(graph.insn_to_node) == len(graph.id_to_node)), \
                str(len(graph.insn_to_node)) + " " \
                + str(len(graph.id_to_node)) + " " + graph.func
            for node in itertools.chain(graph.nodes_in_cf_slice.keys(), graph.nodes_in_df_slice.keys()):
                for p in node.cf_predes:
                    if node not in p.cf_succes:
                        if node.is_df is True:
                            assert len(node.df_succes) > 0, str(node)
                            continue
                        bad_count += 1
                        print("************ Type 1 ******************")
                        print (" Error: control flow predecessor not not connected to successor")
                        print("**************************************")
                        print(node)
                        print(p)
                    # assert node in p.cf_succes, str(node) + str(p)
                for p in node.df_predes:
                    if node not in p.df_succes:
                        bad_count += 1
                        print("************ Type 2 ******************")
                        print (" Error: dataflow flow predecessor not not connected to successor")
                        print("**************************************")
                        print(node)
                        print(p)
                    # assert node in p.df_succes, str(node) + str(p)
                for s in node.cf_succes:
                    if node not in s.cf_predes:
                        bad_count += 1
                        print("************ Type 3  *****************")
                        print (" Error: control flow successor not not connected to predecessor")
                        print("**************************************")
                        print(node)
                        print(s)
                    # assert node in node.cf_predes, str(node) + str(s)
                for s in node.df_succes:
                    if node not in s.df_predes:
                        bad_count += 1
                        print("************ Type 4  *****************")
                        print (" Error: data flow successor not not connected to predecessor")
                        print("**************************************")
                        print(node)
                        print(s)
                    #assert node in node.df_predes, str(node) + str(s)
                #if node is explained and node.mem_load is not None and len(node.df_predes) == 0:
                #    print("************ Type 5  *****************")
                #    print(" Warn: node loads from memory but has not dataflow predecessors")
                #    print("**************************************")
                #    print(node)
        print("[dyn_dep]Total inconsistent node count: " + str(bad_count))

def json_sanity_check():
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--parallelize_rr', dest='parallelize_rr', action='store_true')
    parser.set_defaults(parallelize_rr=False)
    parser.add_argument('-c', '--use_cached_static_graph', dest='use_cached_static_graph', action='store_true')
    parser.set_defaults(use_cached_static_graph=False)

    parser.add_argument('-i', '--generate_indices', dest='generate_indices', action='store_true')
    parser.set_defaults(generate_indices=False)
    parser.add_argument('-a', '--align_indices', dest='align_indices', action='store_true')
    parser.set_defaults(align_indices=False)
    parser.add_argument('-s_ours', '--our_source_code_dir', dest='our_source_code_dir')
    parser.set_defaults(our_source_code_dir=None)
    parser.add_argument('-s_others', '--other_source_code_dir', dest='other_source_code_dir')
    parser.set_defaults(other_source_code_dir=None)
    args = parser.parse_args()

    limit, program, _, _, starting_events, _ = parse_inputs()

    if args.parallelize_rr is True:
        assert args.generate_indices is False
    if args.generate_indices is True:
        assert args.parallelize_rr is False

    if args.generate_indices is True:
        assert args.our_source_code_dir is not None
    if args.align_indices is True:
        assert args.generate_indices is True
        assert args.our_source_code_dir is not None
        assert args.other_source_code_dir is not None

    if args.generate_indices is False:
        StaticDepGraph.build_dependencies(starting_events, program, limit,
                                      use_cached_static_graph=False if args.parallelize_rr is True else args.use_cached_static_graph,
                                      parallelize_rr=args.parallelize_rr)
    else:
        StaticDepGraph.build_indices(starting_events, program, limit,
                                      align_indices=args.align_indices,
                                     our_source_code_dir=args.our_source_code_dir,
                                     other_source_code_dir=args.other_source_code_dir)

if __name__ == "__main__":
    main()
