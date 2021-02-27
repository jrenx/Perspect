import json
import os
curr_dir = os.path.dirname(os.path.realpath(__file__))

class BasicBlock:
    def __init__(self, id):
        self.id = id
        self.start_addr = None
        self.predes = []
        self.succes = []

    def add_start_addr(self, start_addr):
        self.start_addr = start_addr

    def add_predecessors(self, predes):
        self.predes = predes

    def add_successors(self, succes):
        self.succes = succes


class CFG:
    def __init__(self):
        self.all_bbs = {}

    def parse_and_build_partial_cfg(self):
        with open(os.path.join(curr_dir, 'binary_analysis/result')) as f:
            json_bbs = json.load(f)
            print(json_bbs)
            for json_bb in json_bbs:
                bb_id = json_bb['id']
                addr = json_bb['start_addr']
                bb = BasicBlock(bb_id)
                bb.add_start_addr(addr)
                self.all_bbs[bb_id] = bb

            for json_bb in json_bbs:
                bb_id = json_bb['id']
                json_predes = json_bb['predes']
                predes = []
                for json_prede in json_predes:
                    prede_id = json_prede['id']
                    predes.append(self.all_bbs[prede_id])
                self.all_bbs[bb_id].add_predecessors(predes)

                json_succes = json_bb['succes']
                succes = []
                for json_succe in json_succes:
                    succe_id = json_succe['id']
                    succes.append(self.all_bbs[succe_id])
                self.all_bbs[bb_id].add_successors(succes)

class StaticNode:
    def __init__(self):
        self.bb = None
        self.defs = None
        self.uses = None

#class StaticDepGraph:


if __name__ == "__main__":
    cfg = CFG()
    cfg.parse_and_build_partial_cfg()

