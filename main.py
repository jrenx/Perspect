from __future__ import division
import os
import os.path
import sys
from subprocess import call
from optparse import OptionParser
from collections import deque
from ctypes import *
sys.path.append(os.path.abspath('./rr'))
from sat_def import *
sys.path.append(os.path.abspath('./function_trace'))
from instruction_reg_trace import *
from instruction_trace import *
lib = cdll.LoadLibrary('./binary_analysis/static_analysis.so')
#https://stackoverflow.com/questions/145270/calling-c-c-from-python
DEBUG_CTYPE = True
rr_result_cache = {}

def static_backslice(reg, insn, func, prog):
    reg_name = c_char_p(str.encode("[x86_64::" + reg + "]"))
    #https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
    #https://bugs.python.org/issue1701409
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
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
        data = seg.split(",")[1]

        def_reg = data.strip()
        off = "0"
        if "+" in data:
            def_reg = data.split("+")[0].strip()
            off = data.split("+")[1].strip()
        data_points.append([pc, def_reg, off])
    if (DEBUG_CTYPE): print( "[main] " + str(data_points))
    return data_points

def dynamic_backslice(reg, off, insn, func, prog): 
    #TODO, can only do this when is in same function?
    fake_branch, fake_target = get_fake_target_and_branch \
                (insn, func, prog)
    insn_str = hex(insn)
    print( "[main] inputtng to RR: "  \
        + str(fake_target) + " " + str(fake_branch) + " " \
        + str(insn_str) + " " + str(reg) + " " + str(off))
    key = str(fake_target) + "_" + str(fake_branch) + "_" \
            + str(insn_str) + "_" + \
            str(reg) + "_" + str(off)
    rr_result_defs = None
    if key in rr_result_cache:
        print("[main] result is cached.")
        rr_result_defs = rr_result_cache[key]
        print("[main] " + str(rr_result_defs))
    else:
        rr_result_defs = get_def(fake_target, fake_branch, \
                                 insn_str, reg, off)
        rr_result_cache[key] = rr_result_defs
    return list(rr_result_defs[0].union(rr_result_defs[1]))


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
    f_insn = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(f_insn))
    return f_insn

def getFirstInstrInBB(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    f_insn = lib.getFirstInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(f_insn))
    return f_insn

def getInstrAfter(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    f_insn = lib.getInstrAfter(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(f_insn))
    return f_insn



def getLastInstrInBB(sym, prog):
    addr = c_ulong(sym.insn)
    func_name = c_char_p(str.encode(sym.func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    l_insn = lib.getLastInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(l_insn))
    return l_insn

def getLastInstrInBB(insn, func, prog):
    addr = c_ulong(insn)
    func_name = c_char_p(str.encode(func))
    prog_name = c_char_p(str.encode(prog))
    if (DEBUG_CTYPE): print( "[main] prog: " + str(prog_name))
    if (DEBUG_CTYPE): print( "[main] func: " + str(func_name))
    if (DEBUG_CTYPE): print( "[main] addr: " + str(addr))
    l_insn = lib.getLastInstrInBB(prog_name, func_name, addr)
    if (DEBUG_CTYPE): print( "[main] first instr: " + str(l_insn))
    return l_insn



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

def get_fake_target_and_branch(insn, func, prog):
    fake_branch = getInstrAfter(insn, func, prog)
    fake_target = getInstrAfter(fake_branch, func, prog)
    #fake_target = getLastInstrInBB(insn, func, prog)
    if fake_branch >= fake_target:
        print("[main] [warn] BB just have one instr? " + str(fake_branch) + " " + str(fake_target))
    fake_branch = hex(fake_branch)
    fake_target = hex(fake_target)
    return fake_branch, fake_target


def dataflow_helper(reg, insn, func, prog, q):
    #basically keep slicing back until basically are forced to make a symptom
    # make a backward slice, does the slice advance from the current symptom?
    # if No,  watch using RR
    # if Yes, are all predictive 
    #         if Yes, keep slicing between RR or static analysis
    #         if No, which individual ones are predictive? 
    # OR, 
    # if Yes, for every individual one, 
    #           check if is predictive, if is keep analyzing until isn't?
    print("[main][df] making a backward static slice")
    static_defs = static_backslice(reg, insn, func, prog)
    for curr_def in static_defs: 
        def_insn = int(curr_def[0])
        def_reg = curr_def[1].lower()
        def_off = "0x" + curr_def[2]
        print("[main][df] analyzing def: " + str(def_reg) \
                + "+" + str(def_off) + "@" + str(def_insn))

        if def_insn == insn: 
            #static slice made no progress
            print("[main] making a backward dynamic slice")
            dynamic_defs = dynamic_backslice\
                    (def_reg, def_off, def_insn, func, prog)
            # TODO dynamically returend are all pure instructions,
            # need to pass to dyninst to look for assignment
        
        # use PIN to watch
        # if predictive, recurse


def analyze_symptom_with_dataflow(sym, prog, q):
    dataflow_helper(sym.reg, sym.insn, sym.func, prog, q)

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

def parse_set(s):
    segs = s.strip("{").strip("}").split(",")
    l = []
    for seg in segs:
        l.append(seg.strip("'"))
    return set(l)

def parse_set(s):
    print("[main] parsing 3 " + str(s))
    s = s.strip()
    s = s.strip("{")
    s = s.strip("}")
    segs = s.split(",")
    print("[main] parsing 4 " + str(segs))
    l = []
    for seg in segs:
        curr = seg.strip("'")
        if curr == "":
            continue
        print("[main] parsing 4 " + str(curr))
        l.append(curr)
    return set(l)

def main():
    #https://docs.python.org/2/library/optparse.html
    #python main.py -f sweep -i 0x409dc4 -r r8 -p 909_ziptest_exe5
    if os.path.exists("rr_result_cache"):
        f = open("rr_result_cache", "r")
        lines = f.readlines()
        for l in lines:
            k = l.split("|")[0].strip()
            v = l.split("|")[1].strip()
            v = v.replace("set())", "{})")
            v = v.replace("(set()", "({}")
            print("[main] parsing 1 " + str(v))
            v = v.strip("(").strip(")")
            print("[main] parsing 2 " + str(v))
            pair = (parse_set(v.split("},")[0]), \
                    parse_set(v.split("},")[1]))
            rr_result_cache[k] = pair

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

    f = open("rr_result_cache", "w")
    for k in rr_result_cache:
        f.write(str(k) + "|" + str(rr_result_cache[k]) + "\n")


if __name__ == "__main__":
    main()
