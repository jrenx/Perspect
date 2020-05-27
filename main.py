from __future__ import division
import os
import os.path
import sys
import subprocess
from subprocess import call
from optparse import OptionParser
from collections import deque
from ctypes import *
#sys.path.append(os.path.abspath('./rr'))
from sat_def import *
#sys.path.append(os.path.abspath('./function_trace'))
from instruction_reg_trace import *
from instruction_trace import *
from bit_trace import *
lib = cdll.LoadLibrary('./binary_analysis/static_analysis.so')
#https://stackoverflow.com/questions/145270/calling-c-c-from-python
working_dir = "/home/anygroup/perf_debug_tool/"
DEBUG_CTYPE = True
rr_result_cache = {}
bitpoints = {}

# C function declarations

def static_backslice(reg, insn, func, prog):
    reg_name = c_char_p(str.encode("[x86_64::" + reg + "]"))
    if reg == "":
        reg_name = c_char_p(str.encode(reg))
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
        if '*' in def_reg:
            print("Is an expression too difficult for RR to handle")
            continue
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
        rr_result_defs = get_def('*' + fake_target, '*' + fake_branch, \
                                 insn_str, reg, off)
        rr_result_cache[key] = rr_result_defs
    return list(rr_result_defs[0].union(rr_result_defs[1]))

def dynamic_backslice2(branch, target, reg, off, insn): 
    #TODO, can only do this when is in same function?
    insn_str = hex(insn)
    target_str = hex(target)
    branch_str = hex(branch)
    if insn_str == '0x409bbc':
        target_str = '0x409bc2'
        branch_str = '0x409bbf'
    print( "[main] inputtng to RR2: "  \
        + str(target_str) + " " + str(branch_str) + " " \
        + str(insn_str) + " " + str(reg) + " " + str(off))
    key = str(target_str) + "_" + str(branch_str) + "_" \
            + str(insn_str) + "_" + \
            str(reg) + "_" + str(off)
    rr_result_defs = None
    ret = []
    #try:
    if key in rr_result_cache:
        print("[main] result is cached.")
        rr_result_defs = rr_result_cache[key]
        print("[main] " + str(rr_result_defs))
    else:
        rr_result_defs = get_sat_def('*' + target_str, '*' + branch_str, \
                                 insn_str, reg, off)
        #rr_result_defs = get_def('*0x409da5', '*0x409d9d', '0x409d98', 'rsp', '0x68')
        rr_result_cache[key] = rr_result_defs
    ret = list(rr_result_defs[0].union(rr_result_defs[1]))
    #except:
    #    print("Unexpected error:", sys.exc_info()[0])
        
    return ret


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

# class definitions

class Operator:
    def __init__(self):
        pass

class ADD(Operator):
    def __init__(self):
        pass
#    def is_add(self):
#        return True

class SUB(Operator):
    def __init__(self):
        pass
#    def is_minus(self):
#        return True
 
class CAP(Operator):
    def __init__(self):
        pass
#    def is_intersect(self):
#        return True      
#    def add_criteria
 
class MUL(Operator):
    def __init__(self):
        pass
#    def is_dot_product(self):
#        return True      
    def add_context(self, insn):
        self.insn = insn

class Couple():
    # operator
    # expression or operand
    def __init__(self, operator, operand=None, relation=None):
        self.operator = operator
        self.operand = operand
        self.relation = relation
        if (self.operand is not None) and (self.relation is not None):
            raise("Operand and relation cannot be set at the same time.")

    def __str__(self):
        s = ""
        op = " "
        if self.operator is not None:
            if isinstance(self.operator, MUL):
                op = "X"
            elif isinstance(self.operator, CAP):
                op = "&"
            elif isinstance(self.operator, SUB):
                op = "-"
            elif isinstance(self.operator, ADD):
                op = "+"
        s += op
        if self.operand is not None:
            s += str(self.operand)
        if self.relation is not None:
            s += str(self.relation)
        s += " "
        return s


class Relation():
    def __init__(self):
        self.list = []

    def add_couple(couple):
        self.list.append(couple)

    def __str__(self):
        s = "("
        for cp in self.list:
            s += str(cp)
        s += ")"
        return s
 
class Symptom():
    #reg //Dataflow
    #insn //Control flow
    #expression relation
    
    def __init__(self, func, insn, reg=None):
        self.func = func
        if isinstance(insn, str):
            self.insn = int(insn, 16)
        else:
            self.insn = insn
        self.reg = reg
        self.isstarting = False
        self.relation = None

    def __str__(self):
        #ss = ""
        #try:
        print(self.insn)
        print(self.reg)
        print(self.func)
        ss = "[Sym insn: " + str(hex(self.insn)) + " reg: " + str(self.reg) \
                + " func: " + str(self.func) + "]"
        #except:
        #    pass
        return ss

class Definition():
    def __init__(self, func, insn, reg=None, off=None):
        self.func = func
        self.insn = insn
        self.reg = reg
        self.off = off
        if reg == None:
            self.isstatic = False
        else:
            self.isstatic = True
        self.isuse = False
    

    def __str__(self):
        return str(self.insn) + "_" + str(self.reg) \
                + "_" + str(self.off) + "_" + str(self.func)

def get_function(insn, prog):
    if not isinstance(insn, str):
        insn = hex(insn)
    cmd = ['addr2line', '-e', prog, '-f', insn]
    print("[main] running command: " + str(cmd))
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    func = result.stdout.decode('ascii').split()[0]
    print("[main] command returned: " + str(func))
    return func

def get_fake_target_and_branch(insn, func, prog):
    fake_branch = getInstrAfter(insn, func, prog)
    fake_target = getInstrAfter(fake_branch, func, prog)
    #fake_target = getLastInstrInBB(insn, func, prog)
    if fake_branch >= fake_target:
        print("[main] [warn] BB just have one instr? " + str(fake_branch) + " " + str(fake_target))
    fake_branch = hex(fake_branch)
    fake_target = hex(fake_target)
    return fake_branch, fake_target


def dataflow_helper(sym, defn, prog, arg, q, def_map):
    #basically keep slicing back until basically are forced to make a symptom
    # make a backward slice, does the slice advance from the current symptom?
    # if No,  watch using RR
    # if Yes, are all predictive 
    #         if Yes, keep slicing between RR or static analysis
    #         if No, which individual ones are predictive? 
    # OR, 
    # if Yes, for every individual one, 
    #           check if is predictive, if is keep analyzing until isn't?
    
    def_map.pop(str(defn)) 
    local_map = {}
    print()
    print("[main][df] current def map: " + str(def_map))
    defs = None
    if defn.isuse or (not defn.isstatic):
        print("[main][df] making a backward static slice for : " + str(defn))
        static_defs = static_backslice(defn.reg, defn.insn, defn.func, prog)
        for curr_def in static_defs: 
            def_insn = int(curr_def[0])
            def_reg = curr_def[1].lower()
            def_off = "0x" + curr_def[2]
            new_def = Definition(defn.func, def_insn, def_reg, def_off)
            print("[main][df] creating new static def: " + str(new_def))
            #if str(new_def) not in def_map:
            local_map[str(new_def)] = new_def
 
    else:
        print("[main] making a backward dynamic slice")
        dynamic_defs = dynamic_backslice(defn.reg, defn.off, \
                                         defn.insn, defn.func, prog)
        # dynamic definitions are just a bunch of instructions
        for curr_def in dynamic_defs:
            # dynamically returend are all pure instructions,
            new_def = Definition(get_function(curr_def, prog), \
                                     int(curr_def, 16))
            print("[main][df] creating new dynamic def: " + str(new_def))
            #if str(new_def) not in def_map:
            local_map[str(new_def)] = new_def

    print("[main][df] local def map: " + str(local_map))

    non_local_def = False
    for k in local_map:
        if local_map[k].func != defn.func:
            print("[main][df] creating a symptom because \
                    dataflow is no longer local.")
            non_local_def = True
            break

    if non_local_def:
        def_map[str(defn)] = defn
        newSym = Symptom(defn.func, defn.insn, defn.reg) 
        q.append(newSym)
        cp = Couple(None, newSym)
        expr = Relation()
        expr.list.add(cp)
        print("[main][df] non_local_def returning expression: " + str(expr))
        return expr

    # use PIN to watch all current definitions #TODO, is there gonna be a problem?
    # for every definition, 
    #   if is not predictive anymore, create a new symptom, create an AND or MUL relation
    #   otherwise, keep analyzing
    # TODO, technically should also check the value being set and used 
    #       to see if there is re-definition
    #       being lazy here just watch instructions.
    local_defs = {}
    defs = set()
    for k in local_map:
        defs.add(local_map[k].insn)
        local_defs[local_map[k].insn] = local_map[k]
    for k in def_map:
        defs.add(def_map[k].insn)
    
    trace = InsTrace(working_dir + prog + " " + arg, pin='~/pin-3.11/pin')
    print("[main][predictive] checking definitions " + str([hex(d) for d in defs]) +\
            " for symptom " + str(sym))
    ret = trace.get_predictive_predecessors(list(defs), sym.insn)
    print("[main][predictive] result: " + str(ret))
    expr = Relation() 
    for k in ret:
        insn = int(k)
        result = ret[insn]
        #print(insn)
        if insn not in local_defs:
            continue

        curr_def = local_defs[insn]
        curr_expr = None
        if result[0] == "same":
            print("[main][df] Keep exploring the definition " \
                    + str(curr_def))

            new_def_map = {}
            for k in def_map:
                new_def_map[k] = def_map[k]
            for k in local_map:
                new_def_map[k] = local_map[k]

            curr_expr = dataflow_helper(sym, curr_def, \
                                        prog, arg, q, new_def_map)
            #TODO, between every expression should be an or operator
        #if result == 
        elif result[0] == "less":
            newDfSym = Symptom(curr_def.func, curr_def.insn, curr_def.reg) 
            q.append(newDfSym)
            newCfSym = Symptom(sym.func, sym.insn)
            q.append(newCfSym)
            cp0 = Couple(None, newCfSym)
            cp1 = Couple(CAP(), newDfSym)
            curr_expr = Relation()
            curr_expr.list.append(cp0)
            curr_expr.list.append(cp1)
        elif result[0] == "more":
            newDfSym = Symptom(curr_def.func, curr_def.insn, curr_def.reg) 
            q.append(newDfSym)
            newCfSym = Symptom(sym.func, sym.insn)
            q.append(newCfSym)
            cp0 = Couple(None, newCfSym)
            cp1 = Couple(MUL(), newDfSym)
            curr_expr = Relation()
            curr_expr.list.append(cp0)
            curr_expr.list.append(cp1)
        else:
            raise("Unexpected result: " + str(result))

        print("[main][df] Got new sub-relation: " + str(curr_expr))

        cp = None
        if len(expr.list) == 0:
            cp = Couple(None, curr_expr)
        else:
            cp = Couple(ADD(), curr_expr)
        expr.list.append(cp)
    return expr

def analyze_symptom_with_dataflow(sym, prog, arg, q):
    defn = Definition(sym.func, sym.insn, sym.reg)
    if sym.istarting: 
        defn.isuse = True
    def_map = {}
    def_map[str(defn)] = defn
    expr = dataflow_helper(sym, defn, prog, arg, q, def_map)
    print("[main][df] Got new relation: " + str(expr))
    print()
    sym.relation = expr

    # ask pin to watch
    # ask RR to watch
    # then ask pin to watch again 
    # this should really be a loop

    # ask pin to watch every variable definition + every symptom + symptom's value change

    # value not equal, then not predictive
    # check for every definition, how many times does the symptom execute?
    # if is multiplicative, use MUL, and need to find the context
    # if is exclusive, use AND, and need to find the citeria
 
def analyze_symptom(sym, prog, arg, q):
    immedDom = getImmedDom(sym, prog)
    print("[main][predictive] checking dom " + str(hex(immedDom)) \
            + " for " + str(hex(sym.insn)))
    trace = InsTrace(working_dir + prog + " " + arg, pin='~/pin-3.11/pin')
    ret = trace.get_predictive_predecessors([immedDom], sym.insn)
    print("[main][predictive] result: " + str(ret))
    if ret[immedDom][0] == "same":
        newSym = Symptom(sym.func, immedDom) 
        q.append(newSym)
    elif ret[immedDom][0] == "less":
        print("[main][analyze symptom] sym happens less often than immed dom")
        branch = immedDom
        static_defs = static_backslice("", branch, sym.func, prog)
        r = Relation()
        for curr_def in static_defs:
            r1 = Relation()
            def_insn = int(curr_def[0])
            def_reg = curr_def[1].lower()
            if not re.search('[a-zA-Z]', def_reg):
                # TODO, a bug to fix later, why is dyninst treating 
                # a using const as a memory read?
                continue
            def_off = "0x" + curr_def[2]
            new_def = Definition(sym.func, def_insn, def_reg, def_off)
            print("[main][df] creating new static def: " + str(new_def))
            #if str(new_def) not in def_map:
            ret = dynamic_backslice2(branch, sym.insn, def_reg, def_off, def_insn)
            #TODO unfortunate hardcode as bit variable recognition not done.
            print("[main][def] result returned by dyanmic slice: " + str(ret))
            if def_insn == 0x409c24:
                print("LOL")
                pos = None 
                neg = None
                if immedDom == 0x409c55:
                    pos, neg = get_rel464()
                elif immedDom == 0x409c84:
                    pos, neg = get_rel467()
                print("[main][def] positive: " + str(pos))
                print("[main][def] negative: " + str(neg))
                for p in pos:
                    if isinstance(p, BitPoint):
                        p = int(p.point, 16)
                    print("[main][def] pos " + str(p))
                    func = get_function(p, prog)
                    ssym = Symptom(func, p, None) 
                    q.append(ssym)
                    c = Couple(ADD(), ssym)
                    r1.list.append(c)
                for n in neg:
                    if isinstance(n, BitPoint):
                        n = int(n.point, 16)
                    print("[main][def] pos " + str(n))
                    func = get_function(n, prog)
                    ssym = Symptom(func, n, None) 
                    q.append(ssym)
                    c = Couple(SUB(), ssym)
                    r1.list.append(c)
        
            r.list.append(Couple(ADD(), r1))
        sym.relation = r
        return r 

def analyze(sym, prog, arg, q, m, mask):
    print()
    print( "[main] " + "Analyzing " + str(sym))
    if sym is None:
        return
    if str(sym) in m:
        print("[main] Symptom already analyzed, " + str(sym) + "returning ...") 
        return
    if sym.insn in mask:
        print("[main] Symptom ignored, " + str(sym) + "returning ...") 
        return
    global count
    count += 1
    print("[stat] analyzed " + str(count) + " symptoms")
    if sym.reg != None: 
        # analyze the dataflow
        analyze_symptom_with_dataflow(sym, prog, arg, q)
    else:
        analyze_symptom(sym, prog, arg, q)

    m[str(sym)] = sym
        # analyze the control flow
        #op = ADD()
        #print op.is_add()

        # get the control flow dominator

def analyze_loop(ssym, prog, arg):
    #https://stackoverflow.com/questions/35206372/understanding-stacks-and-queues-in-python
    # TODO, need to filter symptoms here

    q = deque()
    q.append(ssym)
    m = {}
    mask = [0x409bd3, 0x409e37] #hack for now
    mask = []
    while len(q) > 0:
        print("[main] analysis queue size: " + str(len(q)))
        sym = q.popleft()
        analyze(sym, prog, arg, q, m, mask)

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
    global count
    count = 0
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

    bitpoints[0x409d28] = BitPoint('0x409d28', '0x409d28', 'rbp', '0x409d08', 'cl') #DONE at use site
    bitpoints[0x409c6a] = BitPoint('0x409c6a', '0x409c6a', 'rbp', '0x409c64', 'cl') #DONE at use site
    bitpoints[0x409418] = BitPoint('0x409418', '0x409418', 'r9' , '0x409415', 'cl') #DONE at use site
    bitpoints[0x40a6aa] = BitPoint('0x40a6aa', '0x40a647', 'rsi', '0x40a64e', 'rbp') #DONE
    bitpoints[0x40a7a2] = BitPoint('0x40a7a2', '0x40a75b', 'rbp', '0x40a75f', 'rdx') #DONE 
    bitpoints[0x40a996] = BitPoint('0x40a996', '0x40a962', 'rbx', '0x40a966', 'rdx') #DONE
    #bitpoints[0x40aaad] = BitPoint('0x40aaad', '0x40aaad', 'rax', '0x40a966', 'rdx')
    bitpoints[0x40abcc] = BitPoint('0x40abcc', '0x40abcc', 'rbp', '0x40abb9', 'cl') #DONE at use site

    parser = OptionParser()
    parser.add_option("-f", "--func", type="string", dest="func")
    parser.add_option("-i", "--insn", type="string", dest="insn")
    parser.add_option("-r", "--reg", type="string", dest="reg")
    parser.add_option("-p", "--prog", type="string", dest="prog")
    parser.add_option("-a", "--arg", type="string", dest="arg")
    (options, args) = parser.parse_args()
    print( "[main] " + "Program: " + str(options.prog))
    print( "[main] " + "Argument: " + str(options.arg))
    print( "[main] " + "Function: " + str(options.func))
    print( "[main] " + "Instruction: " +  str(options.insn))
    print( "[main] " + "Register: " + str(options.reg))
    starting_sym = Symptom(options.func, int(options.insn, 16), options.reg)
    starting_sym.istarting = True
    analyze_loop(starting_sym, options.prog, options.arg)

    f = open("rr_result_cache", "w")
    for k in rr_result_cache:
        f.write(str(k) + "|" + str(rr_result_cache[k]) + "\n")


if __name__ == "__main__":
    main()
