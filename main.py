from __future__ import division
import os
import sys
from subprocess import call
from optparse import OptionParser
from collections import deque
from ctypes import *
sys.path.append(os.path.abspath('./rr'))
from sat_def import *
lib = cdll.LoadLibrary('./binary_analysis/static_analysis.so')
#https://stackoverflow.com/questions/145270/calling-c-c-from-python
DEBUG_CTYPE = True

def backslice(sym, prog):
    reg_name = c_char_p(str.encode("[x86_64::" + sym.reg + "]"))
    #https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    #https://bugs.python.org/issue1701409
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] reg: "  + str(reg_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] : " + "Calling C")
    lib.backwardSlice(prog_name, func_name, addr, reg_name)
    if (DEBUG_CTYPE): print( "[main] : Back from C")
    f = open("result", "r")
    ret = f.read().strip()
    if (DEBUG_CTYPE): print( "[main] : returned: " + ret)
    #In the form: |4234758,RSP + 68|4234648,RSP + 68
    segs = ret.split("|")
    data_points = []
    for seg in segs:
        if seg.strip() == "":
            continue
        pc = seg.split(",")[0]
        reg = seg.split(",")[1].split("+")[0].strip()
        off = seg.split(",")[1].split("+")[1].strip()
        data_points.append([pc, reg, off])
    if (DEBUG_CTYPE): print( data_points)
    return data_points

def getImmedDom(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    dom = lib.getImmedDom(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] immed dom: " + str(dom))
    return dom

def getFirstInstrInBB(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    instr = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(instr))
    return instr

def getLastInstrInBB(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    instr = lib.getLastInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(instr))
    return instr


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
    ret_defs = backslice(sym, prog)
    first = getFirstInstrInBB(sym, prog)
    fake_branch = None
    fake_target = None
    if first < sym.insn:
        fake_branch = first
        fake_target = sym.insn
    else:
        last = getLastInstrInBB(sym, prog)
        if sym.insn < last:
            fake_branch = sym.insn
            fake_target = last
        else:
            raise Exception("BB just have one instr")
    for curr_def in ret_defs:
        def_insn = curr_def[0]
        def_reg = curr_def[1]
        def_off = curr_def[2]
        print( "[main]: inputtng to RR: "  \
            + def_insn + " " + def_reg + " " + def_off)
        #get_def(fake_target, fake_branch, def_insn, def_reg, def_off)

    # ask pin to watch
    # ask RR to watch
    # then ask pin to watch again 
    # this should really be a loop

    # ask pin to watch every variable definition + every symptom + symptom's value change

    # value not equal, then not predictive
    # check for every definition, how many times does the symptom execute?
    # if is multiplicative, use MUL, and need to find the context
    # if is exclusive, use AND, and need to find the citeria
 

def analyze(sym, prog, q):
    print( "[main] " + "Analyzing " + str(sym))

    if sym.reg != None: 
        # analyze the dataflow
        analyze_symptom_with_dataflow(sym, prog, q)
    else:
        immedDom = getImmedDom(sym, prog)
        # analyze the control flow
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
    print( "[main] " + "Program: " + str(options.prog))
    print( "[main] " + "Function: " + str(options.func))
    print( "[main] " + "Instruction: " +  str(options.insn))
    print( "[main] " + "Register: " + str(options.reg))
    analyze_loop(Symptom(options.func, int(options.insn, 16), options.reg), options.prog)


if __name__ == "__main__":
    main()
