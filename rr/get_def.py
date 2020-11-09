import random

from .get_breakpoints import *
from .get_watchpoints import *


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

    for i, (point, value) in enumerate(trace):
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
        reg_point, reg_value = trace[i]
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


def get_def(branch, taken, reg_point, reg, offset='0x0', iter=10):

    positive = set()
    negative = set()

    # First pass
    print("Running breakpoint for first pass")
    run_breakpoint([branch, taken], [reg_point], [reg], False, False)
    breakpoint_trace = parse_breakpoint([branch, taken], [reg_point], False)
    taken_indices, not_taken_indices = filter_branch(branch, taken, breakpoint_trace)
    print("First pass finished")

    branch_indices = random.sample(taken_indices, 4) + random.sample(not_taken_indices, 4)
    watchpoints = [offset_reg(get_reg_from_branch(index, [reg_point], breakpoint_trace)[reg_point], offset)
                   for index in branch_indices]
    watchpoint_taken_indices = range(0, 4)
    watchpoint_not_taken_indices = range(4, 8)

    for i in range(iter):
        # Second pass
        print("Running second pass for {} times".format(i + 1))
        run_watchpoint([branch], watchpoints)
        watchpoint_trace = parse_watchpoint([branch], watchpoints)
        print("Second pass finished")
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
        print("Running third pass for {} times".format(i + 1))
        print("Third pass finished")

    return positive, negative
