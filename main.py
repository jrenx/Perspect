from __future__ import division
import os
import sys
from subprocess import call
from optparse import OptionParser
from collections import deque

class Operator:
    def __init__(self):
        pass

class ADD(Operator):
    def __init__(self):
        pass
    def is_add(self):
        return True

class SUB(Operator):
    def __init__(self):
        pass
    def is_minus(self):
        return True
 
class CAP(Operator):
    def __init__(self):
        pass
    def is_interset(self):
        return True      
#    def add_criteria
 
class MUL(Operator):
    def __init__(self):
        pass
    def is_dot_product(self):
        return True      
    def add_context(self, insn):
        self.insn = insn

class Couple():
    # operator
    # expression or operand
    def __init__(self):
        pass

    def add_operator(self, operator):
        self.operator = operator

    def add_operand(self, operand):
        self.operand = operand

    def add_relation(self, relation):
        self.relation = relation

class Relation():
    def __init__(self):
        self.list = []

    def add_couple(couple):
        self.list.append(couple)

class Symptom():
    #reg //Dataflow
    #insn //Control flow
    #expression relation
    
    def __init__(self, insn, reg):
        self.insn = insn
        self.reg = reg

    def __str__(self):
        return "[Sym insn: " + self.insn + " reg: " + self.reg + "]"

def analyze(sym):
    print "Analyzing " + str(sym)
    #op = ADD()
    #print op.is_add()

def analyze_loop(ssym):
    #https://stackoverflow.com/questions/35206372/understanding-stacks-and-queues-in-python
    q = deque()
    q.append(ssym)
    while len(q) > 0:
        sym = q.popleft()
        analyze(sym)

def main():
    #https://docs.python.org/2/library/optparse.html
    parser = OptionParser()
    parser.add_option("-i", "--insn", type="string", dest="insn")
    parser.add_option("-r", "--reg", type="string", dest="reg")
    (options, args) = parser.parse_args()
    print "Instruction: " +  options.insn
    print "Register: " + options.reg
    analyze_loop(Symptom(options.insn, options.reg))


if __name__ == "__main__":
    main()
