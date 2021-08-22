import random
import sys

from get_breakpoints import *
from get_watchpoints import *
#sys.path.append(os.path.abspath('./..'))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sa_util import *
MAX_WP_COUNT = 2
SMALL_READ_POINT_COUNT = 2000
LARGE_READ_POINT_COUNT = 10000
SMALL_ADDR_COUNT = 250
SMALL_IRRELEVANT_WATCH_POINT_RATIO = 10

def count_point_in_bp_trace(target, bp_trace):
    count = 0
    for (insn, addr, _) in bp_trace:
        if insn == target:
            count += 1
    return count

def count_point_in_wp_trace(target, wp_trace):
    count = 0
    for (addr, insn, _) in wp_trace:
        if insn == target:
            count += 1
    return count

def filter_branch(branch_point, target_point, trace):
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
    #print("[tmp] branch " + str(branch_point) + " target " + str(target_point))

    for i, (point, value, _) in enumerate(trace):
        #print("[tmp] point " + str(point) + " value " + str(value))
        if branch_point is None or target_point is None:
            assert branch_point is None and target_point is None
            taken_indices.append(i + 1)
            continue

        if point == branch_point:# and value is None:
            if i + 1 < len(trace) and trace[i + 1][0] == target_point:
                #assert trace[i + 1][1] is None, str(trace[i]) + str(trace[i + 1])
                taken_indices.append(i)
            else:
                not_taken_indices.append(i)

    return taken_indices, not_taken_indices


# TODO, this is the correct way to do it cuz an instruction could read more than one address??? maybe not...
def get_addr_read_by_branch(branch_index, reg_points, trace):
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
        #print("[tmp] " + str(i) + " " + str(trace[i]))
        reg_point, reg_value, reg_deref = trace[i]
        if reg_point in reg_points:
            if reg_point in reg_map:
                raise KeyError("reg point already found")
            reg_map[reg_point] = reg_value
        i -= 1

    return reg_map

def get_def_insn_index_for_branch(branch_index, reg_points, trace):
    """
    Get the register values right before the specific branch point
    :param branch_index: index of the branch point in trace
    :param reg_points: register points
    :param trace: the trace that contains list of (addr, value) pairs as
    returned by parse_breakpoint
    :return: dict of instruction -> value mappings
    """
    i = branch_index - 1
    while i >= 0 and i < len(trace) and trace[i][1] is not None:
        #print("[tmp] " + str(i) + " " + str(trace[i]))
        reg_point, reg_value, reg_deref = trace[i]
        if reg_point in reg_points:
            return i
        i -= 1
    return None


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


def find_unknown_writes(reg_point, trace, filter=None, ignore_default=False):
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
    addr_to_insn = {}
    #taken = []
    #not_taken = []
    unknown_writes = []
    known_writes = []
    unknown_write = False
    equals = 0
    zeros = 0
    read_insns = set()
    for i, (read_insn, var_addr, value) in enumerate(trace):
        #print("[tmp] " + str(read_insn) + " " + str(var_addr) + " " + str(value))
        #if reg is None and addr == branch_point:
        #    if unknown_write:
        #        if i + 1 < len(trace) and trace[i + 1][0] == taken_point and trace[i + 1][1] is None:
        #            taken.append(i)
        #        else:
        #            not_taken.append(i)
        #        unknown_write = False
        #    continue
        if read_insn == reg_point: # Is the read point.
            if filter is not None and i not in filter:
                #print("[tmp] ignoring read point because did not lead to positive branch outcome")
                continue
            #print("[tmp] Address is being read at: " + str(read_insn))
            if not ignore_default and var_addr not in addr_to_value:
                if value == '0x0':
                    zeros += 1
                else:
                    #unknown_write = True
                    unknown_writes.append(i)
                    #print("[tmp] register has not been seen before: " + str(var_addr))
                    #if var_addr in watched_addrs:
                        #print("[tmp] Address already watched: " + str(var_addr))

            elif addr_to_value[var_addr] != value:
                unknown_writes.append(i)
                #print("[tmp] register has been seen before: " + str(var_addr))
                #print("[tmp] but values differ from last written: " + str(addr_to_value[var_addr]) + " " + str(value))
                #if var_addr in watched_addrs:
                    #print("[tmp] Address already watched: " + str(var_addr))
            else:
                #unknown_write = False
                #print("[tmp] register has been seen before: " + str(var_addr))
                #print("[tmp] and values are equal: " + str(addr_to_value[var_addr]) + " " + str(value))
                read_insns.add(int(addr_to_insn[var_addr].strip('*'), 16))
                equals += 1
                known_writes.append(i)
        else: # Is a write point.
            addr_to_value[var_addr] = value
            addr_to_insn[var_addr] = read_insn
            #unknown_write = False

    print("[rr] number of reads whose values are zeros: " + str(zeros))
    print("[rr] number of reads whose writes are all seen: " + str(equals))
    print("[rr] number of reads whose writes are not all seen: " + str(len(unknown_writes)))
    #return taken, not_taken
    return unknown_writes, known_writes, read_insns

"""
def get_unique_addrs(breakpoint_trace):
    addrs = set()
    for breakpoint in breakpoint_trace:
        addrs.add(breakpoint[1])
        #if len(addrs) == 4:
        #    return addrs
    return addrs
"""

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
"""

def update_breakpoints(reg_points, reg_point,
                  regs, reg,
                  shifts, shift,
                  offsets, offset,
                  off_regs, off_reg,
                  src_regs, src_reg,
                  loop_insn_flags,loop_insn_flag):
    reg_points.append(reg_point)
    regs.append(reg)
    shifts.append(shift)
    offsets.append(offset)
    off_regs.append(off_reg)
    src_regs.append(src_reg)
    loop_insn_flags.append(loop_insn_flag)

def parse_mem_write_expr(write):
    reg = write[1].strip().lower() if write[1] is not None else ''
    shift = hex(write[2])
    offset = hex(write[3])
    off_reg = write[4].strip().lower() if write[4] is not None else ''
    return reg, shift, offset, off_reg

def pick_watch_points(pending_addrs):
    watchpoints = set()
    for a in pending_addrs:
        watchpoints.add(a)
        if len(watchpoints) == MAX_WP_COUNT:
            break
    print("[rr] Total number of unknown addresses: " + str(len(pending_addrs)))
    print("[rr] Picking " + str(MAX_WP_COUNT) + " addresses: " + str(watchpoints))
    # watchpoints = [offset_reg(addr, offset) for addr in addrs]
    #print("[rr] Picked watchpoints: " + str(watchpoints))
    return watchpoints

#TODO, shift should be shift to the right
def get_def(prog, branch, target, read, reg, shift='0x0', offset='0x0', offset_reg = None, iter=30):
    print("[rr] In get_def, branch: " + str(branch) + " target: " + str(target))
    #positive = set()
    #negative = set()

    reg_points = [read]
    regs = [reg]
    off_regs = [offset_reg] if offset_reg is not None else ['']
    offsets = [offset]
    shifts = [shift]
    src_regs = ['']
    loop_insn_flags = ['0']

    all_unique_writes = set()
    results = []
    # = False

    all_static_addr_writes, all_nested_static_addr_writes = get_mem_writes_to_static_addrs(prog)

    # First pass
    print("[rr] Running breakpoints for first step")
    print("[rr] Breakpoints: " + str(reg_points))
    print("[rr] Registers: " + str(regs), flush=True)
    if branch is None or target is None:
        assert branch is None and target is None

    branch_target = []
    if branch is not None and target is not None:
        branch_target = [branch, target]
    success, bp_pass_duration = run_breakpoint(branch_target, reg_points, regs, off_regs, offsets, shifts, src_regs, loop_insn_flags, False, False,
                   do_timeout=False)
    breakpoint_trace = parse_breakpoint(branch_target, reg_points, False)
    print("[rr] Parsed " + str(len(breakpoint_trace)) + " breakpoint hits")

    taken_indices, not_taken_indices = filter_branch(branch, target, breakpoint_trace)
    read_point_count = count_point_in_bp_trace(read, breakpoint_trace)
    print("[rr] Parsed " + str(len(taken_indices)) + " taken indices")
    print("[rr] Parsed " + str(len(not_taken_indices)) + " not taken indices")
    print("[rr] COUNT Total number of read points " + str(read_point_count))

    print("[rr] First step finished")
    pending_addrs = set()
    explained_addrs = set()
    for index in taken_indices:
        #print("[tmp] index: " + str(index))
        def_insn_index = get_def_insn_index_for_branch(index, [read], breakpoint_trace)
        if def_insn_index is None:
            print("[rr][warn] No def point found, "
                  "this branch could use a variable that has more than one local definitions,"
                  "ignore for now as we will watch the other one.")
            continue
        #print("[tmp] def_insn_index: " + str(def_insn_index))
        pending_addrs.add(breakpoint_trace[def_insn_index][1])
    #all_addrs = set([breakpoint_trace[get_def_insn_index_for_branch(index, [read], breakpoint_trace)][1]
    #                for index in taken_indices])
    if '0x0' in pending_addrs:
        print("[rr] parsed write to invalid address ...")
        pending_addrs.remove('0x0')
    print("[rr] COUNT Total number of unique addresses read when branch outcome was positive: " + str(len(pending_addrs)))

    if len(pending_addrs) > 1000:
        raise Exception("[warn][rr] Too many unique addresses to investigate... " + str(len(pending_addrs)))

    for static_addr in pending_addrs.intersection(all_static_addr_writes.keys()):
        for insn, func in all_static_addr_writes[static_addr]:
            if insn not in all_unique_writes:
                #append_result(reg_points, '*' + hex(insn), regs, '', shifts, '', offsets, static_addr,
                #              off_regs, '', src_regs, '', loop_insn_flags, '0')
                results.append([['', 0, int(static_addr, 16)], insn, func, ''])
                all_unique_writes.add(insn)
                explained_addrs.add(static_addr)

    print()
    print("[rr] current results count: " + str(len(results)))
    print("[rr] current results: " + str(results))

    print("[rr] Addresses that have unknown writes: " + str(len(pending_addrs)))
    pending_addrs = pending_addrs.difference(explained_addrs)
    print("[rr] Addresses that have unknown writes after removing known addrs: " + str(len(pending_addrs)))
    #if len(pending_addrs) < SMALL_ADDR_COUNT:
    #    print("Very few addresses, watching might be faster")
    #    skip_breakpoints = True


    #branch_indices = random.sample(taken_indices, 4) + random.sample(not_taken_indices, 4)
    #watchpoints = [offset_reg(get_reg_from_branch(index, [reg_point], breakpoint_trace)[reg_point], offset)
    #               for index in branch_indices]
    #watchpoint_taken_indices = range(0, 4)
    #watchpoint_not_taken_indices = range(4, 8)
    addr_to_def_to_ignore = {}
    pos_pass = True
    do_breakpoints = read_point_count < SMALL_READ_POINT_COUNT \
                     or (read_point_count < LARGE_READ_POINT_COUNT and reg.lower() == 'rsp')
    do_thirdpass = True
    print("[rr] Do breakpoints? " + str(do_breakpoints))
    print("[rr] Total iters: " + str(iter))

    watchpoints = pick_watch_points(pending_addrs)
    explained_addrs = explained_addrs.union(watchpoints)
    pending_addrs = pending_addrs.difference(watchpoints)
    watchpoints = list(watchpoints)
    if len(watchpoints) == 0:
        print("[warn] No more watchpoints to watch... Returning now...")
        return results

    for i in range(iter):
        # Second pass
        print("[rr] Running second step for {} times".format(i + 1), flush=True)
        if do_breakpoints is False:
            run_watchpoint(watchpoints)
            watchpoint_trace, watchpoint_count = parse_watchpoint()
        else:
            run_watchpoint(watchpoints,
                           [read], [reg], [offset_reg] if offset_reg is not None else [''], [int(offset, 16)], [int(shift, 16)],
                           additional_timeout = bp_pass_duration)
            watchpoint_trace, watchpoint_count = parse_watchpoint(reads=set([read]), addr_to_def_to_ignore=addr_to_def_to_ignore)
            print("[rr] COUNT Parsed " + str(watchpoint_count) + " raw watchpoint hits")
            watchpoint_count = watchpoint_count -  count_point_in_wp_trace(read, watchpoint_trace)
        print("[rr] COUNT Parsed " + str(len(watchpoint_trace)) + " watchpoint hits")
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
        new_unique_writes = []
        for line in watchpoint_trace:
            addr = line[0]
            insn = int(line[1], 16)
            func = line[2]
            if insn in all_unique_writes:
                continue
            all_unique_writes.add(insn)
            new_unique_writes.append([insn, func, addr])
        print("[rr] Found " + str(len(new_unique_writes)) + " new unique writes: " + str(new_unique_writes))
        if len(new_unique_writes) == 0:
            print("[rr] No additional writes are found, keep watching more addresses.")

        if len(new_unique_writes) > 0:
            insn_to_func = []
            insn_to_addr = {}
            for write in new_unique_writes:
                insn = write[0]
                func = write[1]
                insn_to_func.append([str(insn), func]) #TODO, in the future just pass int ...
                insn_to_addr[insn] = write[2]
            insn_to_writes = get_mem_writes(insn_to_func, prog)
            print("[rr] returned from get_mem_writes " + str(insn_to_writes))

            def_point_count = 0
            for line in insn_to_writes:
                insn = line[0]
                def_point_count = def_point_count + count_point_in_wp_trace(hex(insn), watchpoint_trace)
            print("[rr] COUNT watchpoint count: " + str(watchpoint_count) + " static def point count: " + str(len(insn_to_writes))
                  + " def point count: " + str(def_point_count))
            if do_breakpoints is False:
                if len(insn_to_writes) >= 50 or def_point_count >= 5000:
                    do_breakpoints = True
                    pending_addrs = pending_addrs.union(watchpoints)
                    for write in new_unique_writes:
                        insn = write[0]
                        all_unique_writes.remove(insn)
                    print("[rr] Retrying with read points enabled in watchpoints")
                    continue

            for line in insn_to_writes:
                #print("[tmp] " + str(line))
                insn = line[0]
                true_insn_addr = line[3]
                func = line[1]

                if len(line[2]) == 0:
                    print("[rr][error] insn " + str(insn) + " writes to no reg! ignoring ...")
                    continue
                elif len(line[2]) > 1:
                    print("[rr][error] insn " + str(insn) + " writes to multiple regs! Not handled ...")
                    raise Exception

                curr_expr = line[2][0]
                # print('[tmp] ' + str(curr_expr))
                curr_reg, curr_shift, curr_offset, curr_off_reg = parse_mem_write_expr(curr_expr)
                curr_src_reg = line[4].strip().lower()
                update_breakpoints(reg_points, '*' + hex(true_insn_addr), regs, curr_reg, shifts, curr_shift, offsets, curr_offset,
                              off_regs, curr_off_reg, src_regs, curr_src_reg, loop_insn_flags, line[5])

                results.append([curr_expr[1:], true_insn_addr, func, curr_src_reg])
                curr_src_reg_size = 0
                if curr_src_reg in reg_size_map:
                    curr_src_reg_size = reg_size_map[curr_src_reg]
                if curr_src_reg_size != 8: #TODO, change this for 32 bit
                    print("[warn] write has a partial length: " + hex(insn))
                    curr_addr = insn_to_addr[insn]
                    pending_addrs.add(curr_addr)
                    addr_to_def_to_ignore[curr_addr] = hex(insn)

            #print("[rr] all insns found " + str(reg_points))
            #print("[rr] all registers found " + str(regs))
            print()
            print("[rr] current results count: " + str(len(results)))
            print("[rr] current results: " + str(results))

            if len(pending_addrs) == 0:
                print("[ERROR][rr] No more watchpoints to watch... Returning now...")
                return results

            #for instruction in positive:
            #    regs.append(get_written_reg(instruction))
            #    reg_points.append(instruction)
            #for instruction in negative:
            #    regs.append(get_written_reg(instruction))
            #    reg_points.append(instruction)
            print("[rr] do breakpoint? " + str(do_breakpoints))
            if do_breakpoints is True and do_thirdpass is True:
                print("[rr] Running breakpoints for third step")
                print("[rr] Breakpoints: " + str(reg_points))
                print("[rr] Registers: " + str(regs))
                print("[rr] Offset registers: " + str(off_regs))
                print("[rr] Offsets: " + str(offsets))
                print("[rr] Shifts: " + str(shifts))
                print("[rr] Source registers: " + str(src_regs))
                print("[rr] Is a loop insn: " + str(loop_insn_flags), flush=True)
                #TODO, how to distinguish diff insn and regs? looks like it's according to order
                success, bp_pass_duration2 = run_breakpoint(branch_target, reg_points, regs, off_regs, offsets, shifts, src_regs,
                               loop_insn_flags, True, True)
                breakpoint_trace = parse_breakpoint(branch_target, reg_points, True)
                reg_points = [reg_points[0]]
                regs = [regs[0]]
                off_regs = [off_regs[0]]
                offsets = [offsets[0]]
                shifts = [shifts[0]]
                src_regs = [src_regs[0]]
                loop_insn_flags = [loop_insn_flags[0]]

                print("[rr] Parsed " + str(len(breakpoint_trace)) + " breakpoint hits")
                print("[rr] Third step finished")

                taken_indices, not_taken_indices = filter_branch(branch, target, breakpoint_trace)
                print("[rr] Parsed " + str(len(taken_indices)) + " taken indices")
                print("[rr] Parsed " + str(len(not_taken_indices)) + " not taken indices")
                known_writes_indices = None
                if pos_pass:
                    read_filter = set([get_def_insn_index_for_branch(index, [read], breakpoint_trace) for index in taken_indices])
                    unknown_writes_indices, known_writes_indices, read_insns = find_unknown_writes(read, breakpoint_trace, read_filter)

                    if len(unknown_writes_indices) == 0:
                        print("Only found the writes that lead to positive branch outcome, looking for other writes now...")
                        pos_pass = False
                        return results #TODO remove this

                if not pos_pass:
                    read_filter = set([get_def_insn_index_for_branch(index, [read], breakpoint_trace) for index in not_taken_indices])
                    unknown_writes_indices, known_writes_indices, read_insns = find_unknown_writes(read, breakpoint_trace, read_filter, True)
                    if len(unknown_writes_indices) == 0:
                        print("All writes are accounted for. Returning now...")
                        return results
                # the unknown writes must also have been
                #partial_breakpoint_trace = [breakpoint_trace[i] for i in unknown_writes_indices]
                #pending_addrs = set([breakpoint[1] for breakpoint in partial_breakpoint_trace])

                partial_breakpoint_trace = [breakpoint_trace[i] for i in known_writes_indices]
                current_explained_addrs = set([breakpoint[1] for breakpoint in partial_breakpoint_trace])
                print("[rr] Newly explained addresses: " + str(len(current_explained_addrs)))
                explained_addrs = explained_addrs.union(current_explained_addrs)
                pending_addrs = pending_addrs.difference(explained_addrs)
                print("[rr] Number of explained addresses: " + str(len(explained_addrs)))
                print("[rr] Addresses that might have undergone unknown writes: " + str(len(pending_addrs)))
                # estimate if rewatching the addrs is actually faster than running the breakpoint pass
                # TODO: to optimize for performance, could just only include the latest found definitions
                #       currently will accumulate all of them ... so once this third breakpoint pass gets slow
                #       it only gets slower.
                #TODO: instead of using the static 30s, could track average watchpoint duration too
                #if len(current_explained_addrs)/2*30 < bp_pass_duration2:
                #    print("[rr] Disabling the third breakpoint pass, which took " + str(bp_pass_duration2)
                #          + " seconds in the previous run, but only removed " + str(len(explained_addrs)) + " addrs.")
                #    do_thirdpass = False
        watchpoints = pick_watch_points(pending_addrs)
        explained_addrs = explained_addrs.union(watchpoints)
        pending_addrs = pending_addrs.difference(watchpoints)
        watchpoints = list(watchpoints)
        if len(watchpoints) == 0:
            print("[warn] No more watchpoints to watch... Returning now...")
            return results
        #TODO populate the watchpoints again
        #branch_indices = random.sample(taken_indices, 4) + random.sample(not_taken_indices, 4)

        #watchpoints = [offset_reg(get_reg_from_branch(index, [reg_point], breakpoint_trace)[reg_point], offset)
        #           for index in branch_indices]
        #watchpoint_taken_indices = range(0, 4)
        #watchpoint_not_taken_indices = range(4, 8)
    if len(results) == 0 and len(pending_addrs) > 0:
        raise Exception("[ERROR][rr] No results found because exceeded itertaion, but still has more addresses to watch...")

    #return positive, negative
    return results


if __name__ == '__main__':
    result = get_def('909_ziptest_exe9', '*0x409380', '*0x409418', '*0x409379', 'rdx', '0x0', '0x8', 'r13')
    print(result)
    print(len(result))
