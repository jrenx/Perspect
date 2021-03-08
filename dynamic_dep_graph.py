import json
import os
from util import *
from collections import deque
from collections import OrderedDict
from static_dep_graph import *

class DynamicNode:
    def __init__(self, instance_number):
        self.instance_number = instance_number


class DynamicDepGraph:
    def __init__(self):
        pass

    def make_node(self, insn, bb):
        #for each bb in the pin output, make a node to use in the dynamic dep grap
        pass

    def convert_insn_to_bb(self, insn):
        pass

    def getDynamicOutput(self):

        pass

    def buildDynamicControlFlowDepGrah(self):
        pass


if __name__ == '__main__':
    dynamic_graph = DynamicDepGraph()
    dynamic_graph.buildDynamicControlFlow()
