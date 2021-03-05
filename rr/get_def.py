import random

from get_breakpoints import *
from get_watchpoints import *


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


def offset_reg(reg_str, offset_str):
    reg = int(reg_str, 16)
    offset = int(offset_str, 16)
    return hex(reg + offset)


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


def check_write(reg_point, branch_point, taken_point, trace):
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
    reg_map = {}
    taken = []
    not_taken = []
    unknown_write = False

    for i, (addr, reg, value) in enumerate(trace):
        if reg is None and addr == branch_point:
            if unknown_write:
                if i + 1 < len(trace) and trace[i + 1][0] == taken_point and trace[i + 1][1] is None:
                    taken.append(i)
                else:
                    not_taken.append(i)
                unknown_write = False
            continue
        if addr == reg_point:
            if reg not in reg_map or reg_map[reg] != value:
                unknown_write = True
            else:
                unknown_write = False
        else:
            reg_map[reg] = value
            unknown_write = False

    return taken, not_taken


def get_written_reg(instruction):
    raise NotImplementedError


def get_def(branch, taken, reg_point, reg, offset='0x0', iter=10):
    print("[rr] In get_def, branch: " + branch + " target: " + taken)
    positive = set()
    negative = set()

    # First pass
    print("[rr] Running breakpoint for first pass")
    run_breakpoint([branch, taken], [reg_point], [reg], False, False)
    breakpoint_trace = parse_breakpoint([branch, taken], [reg_point], False)
    print("[rr] Parsed " + str(len(breakpoint_trace)) + " breakpoints")
    taken_indices, not_taken_indices = filter_branch(branch, taken, breakpoint_trace)
    print("[rr] Parsed " + str(len(taken_indices)) + " taken indices")
    print("[rr] Parsed " + str(len(not_taken_indices)) + " not taken indices")
    print("[rr] First pass finished")

    branch_indices = random.sample(taken_indices, 4) + random.sample(not_taken_indices, 4)

    watchpoints = [offset_reg(get_reg_from_branch(index, [reg_point], breakpoint_trace)[reg_point], offset)
                   for index in branch_indices]
    watchpoint_taken_indices = range(0, 4)
    watchpoint_not_taken_indices = range(4, 8)

    for i in range(iter):
        # Second pass
        print("[rr] Running second pass for {} times".format(i + 1))
        run_watchpoint([branch], watchpoints)
        watchpoint_trace = parse_watchpoint([branch], watchpoints)
        print("[rr] Parsed " + str(len(watchpoint_trace)) + " watchpoints")
        print("[rr] Second pass finished")
        taken_watchpoint_traces = [
            get_watchpoint_trace(watchpoints[index], get_num_from_index(index, breakpoint_trace), watchpoint_trace)
            for index in watchpoint_taken_indices]
        not_taken_watchpoint_traces = [
            get_watchpoint_trace(watchpoints[index], get_num_from_index(index, breakpoint_trace), watchpoint_trace)
            for index in watchpoint_not_taken_indices]

        watchpoint_result = analyze_trace(taken_watchpoint_traces, not_taken_watchpoint_traces)
        positive.union(watchpoint_result[0])
        negative.union(watchpoint_result[1])

        # Third pass
        print("[rr] Running third pass for {} times".format(i + 1))
        reg_points = [reg_point]
        regs = [reg]
        for instruction in positive:
            regs.append(get_written_reg(instruction))
            reg_points.append(instruction)
        for instruction in negative:
            regs.append(get_written_reg(instruction))
            reg_points.append(instruction)
        run_breakpoint([branch, taken], reg_points, regs, True, True)
        breakpoint_trace = parse_breakpoint([branch, taken], reg_points, True)
        taken_indices, not_taken_indices = check_write(reg_point, branch, taken, breakpoint_trace)
        print("[rr] Third pass finished")

        branch_indices = random.sample(taken_indices, 4) + random.sample(not_taken_indices, 4)

        watchpoints = [offset_reg(get_reg_from_branch(index, [reg_point], breakpoint_trace)[reg_point], offset)
                   for index in branch_indices]
        watchpoint_taken_indices = range(0, 4)
        watchpoint_not_taken_indices = range(4, 8)

    return positive, negative


if __name__ == '__main__':
    branch = '*0x409c84' #472
    taken = '*0x409c55' #467
    reg_point = '*0x409c24'
    regs = 'rbp'
    positive, negative = get_def(branch, taken, reg_point, regs)
