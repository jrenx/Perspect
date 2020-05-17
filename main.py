from __future__ import division
import os
import sys
from subprocess import call
from optparse import OptionParser
from collections import deque
from ctypes import *
lib = cdll.LoadLibrary('./binary_analysis/static_analysis.so')
#https://stackoverflow.com/questions/145270/calling-c-c-from-python
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
    def __init__(self, operator, operand=None, relation=None):
        self.operator = operator
        self.operand = operand
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
    
    def __init__(self, func, insn, reg=None):
        self.func = func
        self.insn = insn
        self.reg = reg

    def __str__(self):
        return "[Sym insn: " + str(self.insn) + " reg: " + str(self.reg) \
                + " func: " + str(self.func) + "]"

def analyze_symptom_with_dataflow(sym, prog, q):
    reg_name = c_char_p("[x86_64::" + sym.reg + "]")
    addr = c_ulong(sym.insn)
    func_name = c_char_p(sym.func)
    prog_name = c_char_p(prog)
    print reg_name
    print addr
    print func_name
    print prog_name
    lib.backwardSlice(prog_name, func_name, addr, reg_name)

    # ask pin to watch every variable definition + every symptom + symptom's value change

    # value not equal, then not predictive
    # check for every definition, how many times does the symptom execute?
    # if is multiplicative, use MUL, and need to find the context
    # if is exclusive, use AND, and need to find the citeria
 

def analyze(sym, prog, q):
    print "Analyzing " + str(sym)

    if sym.reg != None: 
        # analyze the dataflow
        analyze_symptom_with_dataflow(sym, prog, q)
    else:
        # analyze the control flow
        addr = c_ulong(sym.insn)
        func_name = c_char_p(sym.func)
        prog_name = c_char_p(prog)
        print "[main] prog: " + str(prog_name)
        print "[main] func: " + str(func_name)
        print "[main] addr: " + str(addr)
        dom = lib.getImmedDom(prog_name, func_name, addr)
        print "[main] immed dom: " + str(dom)
        #op = ADD()
        #print op.is_add()

        # get the control flow dominator

def analyze_loop(ssym, prog):
    #https://stackoverflow.com/questions/35206372/understanding-stacks-and-queues-in-python
    q = deque()
    q.append(ssym)
    while len(q) > 0:
        sym = q.popleft()
        analyze(sym, prog, q)

def main():
    #https://docs.python.org/2/library/optparse.html
    #python main.py -f sweep -i 0x409dc4 -r r8 -p 909_ziptest_exe5
    parser = OptionParser()
    parser.add_option("-f", "--func", type="string", dest="func")
    parser.add_option("-i", "--insn", type="string", dest="insn")
    parser.add_option("-r", "--reg", type="string", dest="reg")
    parser.add_option("-p", "--prog", type="string", dest="prog")
    (options, args) = parser.parse_args()
    print "Program: " + str(options.prog)
    print "Function: " + str(options.func)
    print "Instruction: " +  str(options.insn)
    print "Register: " + str(options.reg)
    analyze_loop(Symptom(options.func, long(options.insn, 16), options.reg), options.prog)


if __name__ == "__main__":
    main()
