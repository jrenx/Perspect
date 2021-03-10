import random
import sys

from get_breakpoints import *
from get_watchpoints import *
#sys.path.append(os.path.abspath('./..'))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sa_util import *

def filter_branch(branch_point, taken_point, trace):
    """
    Find the branches in the trace and distinguish whether it is taken
    :param branch_point: instruction where the branch happens
    :param taken_point: instruction denotes that the branch is taken
    :param trace: the trace that contains list of (addr, value) pairs as
    returned by parse_breakpoint
    :return: two lists of indices into trace that points to taken branch and
    not taken branch
    """
    taken_indices = []
    not_taken_indices = []

    for i, (point, value, _) in enumerate(trace):
        print("point " + str(point))
        print("value " + str(value))
        if point == branch_point and value is None:
            if i + 1 < len(trace) and trace[i + 1][0] == taken_point and trace[i + 1][1] is None:
                taken_indices.append(i)
            else:
                not_taken_indices.append(i)

    return taken_indices, not_taken_indices


def get_reg_from_branch(branch_index, reg_points, trace):
    """
    Get the register values right before the specific branch point
    :param branch_index: index of the branch point in trace
    :param reg_points: register points
    :param trace: the trace that contains list of (addr, value) pairs as
    returned by parse_breakpoint
    :return: dict of instruction -> value mappings
    """
    reg_map = {}

    i = branch_index - 1
    while trace[i][1] is not None:
        print(str(i) + " " + str(trace[i]))
        reg_point, reg_value, reg_deref = trace[i]
        if reg_point in reg_points:
            if reg_point in reg_map:
                raise KeyError("reg point already found")
            reg_map[reg_point] = reg_value
        i -= 1

    return reg_map


def get_num_from_index(index, trace):
    return len([bp for bp in trace[:index] if bp[0] == trace[index][0]]) + 1


def get_watchpoint_trace(watchpoint, branch_num, trace):
    """
    Get the list of instructions that write to watchpoint
    :param watchpoint: watchpoint address
    :param branch_num: the number of branch breakpoint hits, after which
    the trace is ignored
    :param trace: the trace that contains list of (watchpoint, instruction)
    pairs as returned by parse_watchpoints
    :return: list of instructions
    """
    instructions = []

    branch_count, index = 0, 0
    while branch_count < branch_num:
        if trace[index][1] is None:
            branch_count += 1
        elif trace[index][0] == watchpoint:
            instructions.append(trace[index][0])
        index += 1

    return instructions

"""
def offset_reg(reg_str, offset_str):
    reg = int(reg_str, 16)
    offset = int(offset_str, 16)
    return hex(reg + offset)
"""

def analyze_trace(taken_traces, not_taken_traces):
    positive = set()
    negative = set()

    for trace in taken_traces:
        if len(trace) > 0:
            positive.update({trace[-1]})

    for trace in not_taken_traces:
        if len(trace) > 0:
            negative.update({trace[-1]})

    return positive, negative


#def check_writes(reg_point, branch_point, taken_point, trace):
def check_writes(reg_point, trace, watched_addrs):
    """
    Check whether there is unknown writes to address pointed by register
    :param reg_point: instruction address to check the register
    :param branch_point: instruction where the branch happens
    :param taken_point: instruction denotes that the branch is taken
    :param trace: the trace that contains list of (addr, reg_value, value)
    pairs as returned by parse_breakpoint
    :return: two lists of into traces that points to taken branches and not
    taken branches whose register has unknown write
    """
    addr_to_value = {}
    #taken = []
    #not_taken = []
    uknown_writes = []
    unknown_write = False
    equals = 0
    zeros = 0
    for i, (read_insn, var_addr, value) in enumerate(trace):
        print("[tmp] " + str(read_insn) + " " + str(var_addr) + " " + str(value))
        #if reg is None and addr == branch_point:
        #    if unknown_write:
        #        if i + 1 < len(trace) and trace[i + 1][0] == taken_point and trace[i + 1][1] is None:
        #            taken.append(i)
        #        else:
        #            not_taken.append(i)
        #        unknown_write = False
        #    continue
        if read_insn == reg_point: # Is the read point.
            #print("[tmp] Address is being read at: " + str(read_insn))
            if var_addr not in addr_to_value:
                if value == '0x0':
                    zeros += 1
                else:
                    #unknown_write = True
                    uknown_writes.append(i)
                    #print("[tmp] register has not been seen before: " + str(var_addr))
                    #if var_addr in watched_addrs:
                        #print("[tmp] Address already watched: " + str(var_addr))

            elif addr_to_value[var_addr] != value:
                uknown_writes.append(i)
                #print("[tmp] register has been seen before: " + str(var_addr))
                #print("[tmp] but values differ from last written: " + str(addr_to_value[var_addr]) + " " + str(value))
                #if var_addr in watched_addrs:
                    #print("[tmp] Address already watched: " + str(var_addr))
            else:
                #unknown_write = False
                #print("[tmp] register has been seen before: " + str(var_addr))
                #print("[tmp] and values are equal: " + str(addr_to_value[var_addr]) + " " + str(value))
                equals += 1
        else: # Is a write point.
            addr_to_value[var_addr] = value
            #unknown_write = False

    print("[rr] number of reads whose values are zeros: " + str(zeros))
    print("[rr] number of reads whose writes are all seen: " + str(equals))
    print("[rr] number of reads whose writes are not all seen: " + str(len(uknown_writes)))
    #return taken, not_taken
    return uknown_writes


def get_written_reg(instruction):
    raise NotImplementedError

"""
def get_unique_addrs(breakpoint_trace):
    addrs = set()
    for breakpoint in breakpoint_trace:
        addrs.add(breakpoint[1])
        #if len(addrs) == 4:
        #    return addrs
    return addrs
"""

def get_addrs(breakpoint_trace, shift, offset, offset_reg):
    s = int(shift, 16)
    o = int(offset, 16)
    if offset_reg is None:
        return set([hex((int(bp[1], 16) << s) + o) for bp in breakpoint_trace])

    all_addrs = set()
    prev_insn = None
    prev_reg = None
    for bp in breakpoint_trace:
        print("[tmp] breakpoint: " + str(bp))
        curr_insn = bp[0]
        curr_reg = bp[1]
        if prev_insn is not None:
            if curr_insn == prev_insn:
                addr = hex((int(prev_reg, 16) << s) + int(curr_reg, 16) * o)
                print("[tmp] original addr " + prev_reg + " addr calculated " + str(addr))
                all_addrs.add(addr)
                prev_insn = None
                prev_reg = None
                continue
            else:
                all_addrs.add(hex((int(prev_reg, 16) << s) + o))

        prev_insn = curr_insn
        prev_reg = curr_reg
    return all_addrs

#TODO, shift should be shift to the right
def get_def(prog, reg_point, reg, shift='0x0', offset='0x0', offset_reg = None, iter=10):
    print("[rr] In get_def") #, branch: " + branch + " target: " + taken)
    #positive = set()
    #negative = set()

    reg_points = [reg_point]
    regs = [reg]
    off_regs = [offset_reg] if offset_reg is not None else ['']
    offsets = [offset]
    shifts = [shift]
    src_regs = ['']
    loop_insn_flags = ['0']

    # First pass
    print("[rr] Running breakpoints for first step")
    print("[rr] Breakpoints: " + str(reg_points))
    print("[rr] Registers: " + str(regs))
    run_breakpoint([], reg_points, regs, off_regs, offsets, shifts, src_regs, loop_insn_flags, False, False)
    breakpoint_trace = parse_breakpoint([], reg_points, False)
    print("[rr] Parsed " + str(len(breakpoint_trace)) + " breakpoints")

    #taken_indices, not_taken_indices = filter_branch(branch, taken, breakpoint_trace)
    #print("[rr] Parsed " + str(len(taken_indices)) + " taken indices")
    #print("[rr] Parsed " + str(len(not_taken_indices)) + " not taken indices")

    print("[rr] First step finished")
    watched_addrs = set()
    all_addrs = set([breakpoint[1] for breakpoint in breakpoint_trace])
    addrs = set()
    for a in all_addrs:
        addrs.add(a)
        if len(addrs) == 4:
            break
    print("[rr] Total number of unique addresses read: " + str(len(all_addrs)))
    print("[rr] Picking 4 addresses: " + str(addrs))
    #watchpoints = [offset_reg(addr, offset) for addr in addrs]
    watchpoints = [addr for addr in addrs]
    print("[rr] Picked watchpoints: " + str(watchpoints))
    all_addrs = all_addrs.difference(addrs)
    watched_addrs = watched_addrs.union(addrs)

    #branch_indices = random.sample(taken_indices, 4) + random.sample(not_taken_indices, 4)
    #watchpoints = [offset_reg(get_reg_from_branch(index, [reg_point], breakpoint_trace)[reg_point], offset)
    #               for index in branch_indices]
    #watchpoint_taken_indices = range(0, 4)
    #watchpoint_not_taken_indices = range(4, 8)

    all_unique_insns = set()
    results = []

    for i in range(iter):
        # Second pass
        print("[rr] Running second step for {} times".format(i + 1))
        run_watchpoint([], watchpoints)
        watchpoint_trace = parse_watchpoint([], watchpoints)
        print("[rr] Parsed " + str(len(watchpoint_trace)) + " watchpoints")
        #("[tmp] " + str(watchpoint_trace))
        print("[rr] Second step finished")

        #taken_watchpoint_traces = [
        #    get_watchpoint_trace(watchpoints[index], get_num_from_index(index, breakpoint_trace), watchpoint_trace)
        #    for index in watchpoint_taken_indices]
        #not_taken_watchpoint_traces = [
        #    get_watchpoint_trace(watchpoints[index], get_num_from_index(index, breakpoint_trace), watchpoint_trace)
        #    for index in watchpoint_not_taken_indices]

        #watchpoint_result = analyze_trace(taken_watchpoint_traces, not_taken_watchpoint_traces)
        #positive.union(watchpoint_result[0])
        #negative.union(watchpoint_result[1])

        # Third pass
        print("[rr] Running third step for {} times".format(i + 1))
        unique_insns = set()
        for line in watchpoint_trace:
            insn = line[1]
            func = line[2]
            insn_func_str = insn + "@" + func
            if insn_func_str in all_unique_insns:
                continue
            unique_insns.add(insn_func_str)
        print("[rr] Found " + str(len(unique_insns)) + " new unique writes: " + str(unique_insns))
        if len(unique_insns) == 0:
            print("[rr] No additional writes are found, keep watching more addresses.")
        all_unique_insns = all_unique_insns.union(unique_insns)

        if len(unique_insns) > 0:
            insn_to_func = []
            for pair in unique_insns:
                segs = pair.split("@")
                insn = segs[0]
                func = segs[1]
                insn_to_func.append([str(int(insn, 16)), func])

            insn_to_writes = get_mem_writes(insn_to_func, prog)
            print("[rr] returned from get_mem_writes " + str(insn_to_writes))
            for line in insn_to_writes:
                print("[tmp] " + str(line))
                insn = line[0]
                true_insn_addr = line[3]
                func = line[1]
                #TODO, what if have shift and off?

                if len(line[2]) == 0:
                    print("[rr][error] insn " + str(insn) + " writes to no reg! ignoring ...")
                    continue
                elif len(line[2]) > 1:
                    print("[rr][error] insn " + str(insn) + " writes to multiple regs! Not handled ...")
                    raise Exception
                curr_expr = line[2][0]
                print('[tmp] ' + str(curr_expr))
                curr_insn = '*' + hex(true_insn_addr)
                reg_points.append(curr_insn)
                regs.append(curr_expr[1].strip().lower() if curr_expr[1] is not None else '')
                shifts.append(hex(str(curr_expr[2])))
                offsets.append(hex(str(curr_expr[3])))
                off_regs.append(curr_expr[4].strip().lower() if curr_expr[4] is not None else '')
                src_regs.append(line[4].strip().strip('%').lower())
                loop_insn_flags.append(line[5])
                results.append([curr_expr[1:], true_insn_addr, func])
            print("[rr] all insns found " + str(reg_points))
            print("[rr] all registers found " + str(regs))

            #for instruction in positive:
            #    regs.append(get_written_reg(instruction))
            #    reg_points.append(instruction)
            #for instruction in negative:
            #    regs.append(get_written_reg(instruction))
            #    reg_points.append(instruction)

            print("[rr] Running breakpoints for third step")
            print("[rr] Breakpoints: " + str(reg_points))
            print("[rr] Registers: " + str(regs))
            #TODO, how to distinguish diff insn and regs? looks like it's according to order
            run_breakpoint([], reg_points, regs, off_regs, offsets, shifts, src_regs, loop_insn_flags, True, True)
            breakpoint_trace = parse_breakpoint([], reg_points, True)
            print("[rr] Parsed " + str(len(breakpoint_trace)) + " breakpoints")
            print("[rr] Third step finished")

            unknown_writes_indices = check_writes(reg_point, breakpoint_trace, watched_addrs)
            #taken_indices, not_taken_indices = check_writes(reg_point, branch, taken, breakpoint_trace)
            if len(unknown_writes_indices) == 0:
                print("All writes are accounted for, returning now.")
                return results

            partial_breakpoint_trace = [breakpoint_trace[i] for i in unknown_writes_indices]
            all_addrs = set([breakpoint[1] for breakpoint in partial_breakpoint_trace])
            print("[rr] Addresses that might have undergone unknown writes: " + str(len(all_addrs)))

        addrs = set()
        all_addrs = all_addrs.difference(watched_addrs)
        for a in all_addrs:
            addrs.add(a)
            if len(addrs) == 4:
                break
        all_addrs = all_addrs.difference(addrs)
        watched_addrs = watched_addrs.union(addrs)
        print("[rr] Total number of unique addresses read: " + str(len(all_addrs)))
        print("[rr] Picking 4 addresses: " + str(addrs))
        #watchpoints = [offset_reg(addr, offset) for addr in addrs]
        watchpoints = [addr for addr in addrs]
        print("[rr] Picked watchpoints: " + str(watchpoints))
      
        #TODO populate the watchpoints again
        #branch_indices = random.sample(taken_indices, 4) + random.sample(not_taken_indices, 4)

        #watchpoints = [offset_reg(get_reg_from_branch(index, [reg_point], breakpoint_trace)[reg_point], offset)
        #           for index in branch_indices]
        #watchpoint_taken_indices = range(0, 4)
        #watchpoint_not_taken_indices = range(4, 8)

    #return positive, negative
    return results


if __name__ == '__main__':
    branch = '*0x409c84' #472
    taken = '*0x409c55' #467
    reg_point = '*0x409c24'
    regs = 'rbp'
    positive, negative = get_def('909_ziptest_exe9', branch, taken, reg_point, regs)
