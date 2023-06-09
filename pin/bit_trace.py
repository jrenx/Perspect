from instruction_reg_trace import InsRegTrace
import os

pin_dir = os.path.dirname(os.path.realpath(__file__))

DEBUG2 = False
DEBUG3 = True
class BitPoint:
    def __init__(self, point, addr_point, addr_reg, shift_point, shift_reg):
        self.point = point
        self.addr_point = addr_point
        self.addr_reg = addr_reg
        self.shift_point = shift_point
        self.shift_reg = shift_reg

    def __eq__(self, other):
        if not isinstance(other, BitPoint):
            return False
        return self.point == other.point and self.addr_point == other.addr_point and self.addr_reg == other.addr_reg and self.shift_point == other.shift_point and self.shift_reg == other.shift_reg

    def __hash__(self):
        return ', '.join([self.point, self.addr_point, self.addr_reg, self.shift_point, self.shift_reg]).__hash__()

    def __str__(self):
        return self.point


class BitPointValue:
    def __init__(self, bit_point, addr_value, shift_value):
        self.bit_point = bit_point
        self.addr_value = addr_value
        self.shift_value = shift_value
        self.pc_value = None

    def __eq__(self, other):
        if not isinstance(other, BitPointValue):
            return False
        return self.bit_point == other.bit_point and self.addr_value == other.addr_value and self.shift_value == other.shift_value
    
    def same_value(self, other):
        if not isinstance(other, BitPointValue):
            return False
        return self.addr_value == other.addr_value and self.shift_value == other.shift_value

    def __str__(self):
        return "bit point: insn: " + str(self.bit_point) \
                + " addr: " + str(self.addr_value) \
                + " shift: " + str(self.shift_value) \
                + " pc: " + str(self.pc_value)

class BitTrace(InsRegTrace):

    def __init__(self, program, is_32=False, pin='pin'):
        super(BitTrace, self).__init__(program, is_32, pin)

    def get_trace(self, bit_points, target, branch_point):
        ins_reg_map = dict()
        for bit_point in bit_points:
            ins_reg_map.update({bit_point.point: "pc", bit_point.addr_point: bit_point.addr_reg,
                                bit_point.shift_point: bit_point.shift_reg})
        ins_reg_map.update({branch_point.point: "pc", branch_point.addr_point: branch_point.addr_reg,
                            branch_point.shift_point: branch_point.shift_reg})
        ins_reg_map.update({target: "pc"})
        super(BitTrace, self).run_function_trace(ins_reg_map)

    def parse_bit_trace(self, bit_points, target, branch_point):
        # Creat map from pc to bit_point
        pc_map = dict()
        for bit_point in bit_points:
            pc_map[bit_point.point] = bit_point
            pc_map[bit_point.addr_point] = bit_point
            pc_map[bit_point.shift_point] = bit_point
        pc_map[branch_point.point] = branch_point
        pc_map[branch_point.addr_point] = branch_point
        pc_map[branch_point.shift_point] = branch_point

        traces = []
        curr_bitpoint_value = None
        with open(os.path.join(pin_dir, 'instruction_trace.out')) as trace_file:
            for line in trace_file:
                if 'eof' in line:
                    break
                addr = line.split()[0].strip(':')
                reg = line.split()[1]
                if DEBUG2: print("checking " + line)
                if addr == target:
                    if curr_bitpoint_value is not None:
                        traces.append(curr_bitpoint_value)
                        curr_bitpoint_value = None
                    traces.append(target)
                else:
                    bit_point = pc_map[addr]
                    #print("         Current bit point addr: " + str(bit_point))

                    if curr_bitpoint_value is not None and curr_bitpoint_value.bit_point != bit_point:
                        print("ERROR")
                        curr_bitpoint_value.pc_value = curr_bitpoint_value.bit_point
                        print(" ===> Appending partial bit point: " + str(curr_bitpoint_value))
                        traces.append(curr_bitpoint_value)
                        curr_bitpoint_value = BitPointValue(bit_point, None, None)

                    if curr_bitpoint_value is None:
                        curr_bitpoint_value = BitPointValue(bit_point, None, None)

                    if curr_bitpoint_value is not None and curr_bitpoint_value.bit_point == bit_point:
                        if bit_point.addr_point == addr:
                            curr_bitpoint_value.addr_value = reg
                        elif bit_point.shift_point == addr:
                            curr_bitpoint_value.shift_value = reg
                        elif bit_point.point == addr:
                            curr_bitpoint_value.pc_value = reg
                        else:
                            raise ValueError("wrong address: " + addr)

                        if DEBUG2: print("         Current bit point: " + str(curr_bitpoint_value))
                        if curr_bitpoint_value.addr_value  is not None and \
                                curr_bitpoint_value.shift_value is not None and \
                                curr_bitpoint_value.pc_value is not None:
                            if DEBUG2: print()
                            if DEBUG2: print(" ===> Appending bit point: " + str(curr_bitpoint_value))
                            #print(" ===> Current size of trace: " + str(len(traces)))
                            traces.append(curr_bitpoint_value)
                            curr_bitpoint_value = None

                #print("checked " + line)
                    #else:
                    #    traces.append(curr_bitpoint_value)
                    #    curr_bitpoint_value = BitPointValue(bit_point, None, None)
                    #    if bit_point.addr_point == addr:
                    #        curr_bitpoint_value.addr_value = reg
                    #    elif bit_point.shift_point == addr:
                    #        curr_bitpoint_value.shift_value = reg
                    #    elif bit_point.point == addr:
                    #        pass
                    #    else:
                    #        raise ValueError("wrong address: " + addr)

        return traces

    def split_branch(self, traces, target, branch_point):
        trace_index = 0
        last_branch_index = -1
        taken = []
        not_taken = []
        print("split branch, trace length: " + str(len(traces)))
        for trace in traces:
            print(str(trace_index) + " " + str(trace))
            if not isinstance(trace, BitPointValue) and trace == target:
                if last_branch_index != -1:
                    taken.append(last_branch_index)
                    last_branch_index = -1
            elif trace.bit_point == branch_point:
                if last_branch_index != -1:
                    not_taken.append(last_branch_index)
                    last_branch_index = trace_index
                else:
                    last_branch_index = trace_index
            trace_index += 1
        #print(str(taken))
        #print(str(not_taken))
        return taken, not_taken

    def analyze_trace(self, traces, bit_points, target, branch_point):
        taken_indexes, not_taken_indexes = self.split_branch(traces, target, branch_point)

        positive_bitpoints = set()
        negative_bitpoints = set()

        for taken_index in taken_indexes:
            branch_point_value = traces[taken_index]

            pos = None
            for index in range(taken_index - 1, -1, -1):
                trace = traces[index]
                #print("Positive Checking branch: " + str(index))
                if branch_point_value.same_value(trace) and branch_point_value.bit_point != trace.bit_point:
                    pos = trace.bit_point
                    if DEBUG2: print("Positive   found at: " + str(index) + " " + str(trace))
                    break
            if pos is None:
                if DEBUG2: print("positive WARN: def point not found")
            else:
                positive_bitpoints.add(pos)
                if DEBUG2: print("Positive trace point: " + str(pos))

        for not_taken_index in not_taken_indexes:
            branch_point_value = traces[not_taken_index]

            neg = None
            for index in range(not_taken_index - 1, -1, -1):
                trace = traces[index]
                #print("Negative Checking branch: " + str(index))
                if branch_point_value.same_value(trace) and branch_point_value.bit_point != trace.bit_point:
                    neg = trace.bit_point
                    if DEBUG2: print("Negative   found at: " + str(index) + " " + str(trace))
                    break

            if neg is None:
                if DEBUG2: print("Negative WARN: def point not found")
            else:
                negative_bitpoints.add(trace.bit_point)
                if DEBUG2: print("Negative trace point: " + str(trace.bit_point))

        return positive_bitpoints, negative_bitpoints

    def map_str(self, m):
        s = ""
        for k in m:
            s += str(k)
            s += ":"
            s += str(m[k]) 
            s += ","
        return s

    def filter_positive_and_negative(self, positive, negative, traces, bit_points, target, branch): 
        true_negative_map = {}
        part_negative_map = {}
        doub_negative_map = {}
        for neg in negative:
            true_negative_map[neg] = False
            part_negative_map[neg] = False
            doub_negative_map[neg] = False

        print("init true negative map: " + self.map_str(true_negative_map))
        print("init part negative map: " + self.map_str(part_negative_map))
        print("init doub negative map: " + self.map_str(doub_negative_map))
 

        for index in range(len(traces) - 1, -1, -1):
            trace = traces[index]
            #if DEBUG3: print("Checking " + str(trace))
            if not isinstance(trace, BitPointValue):
                continue
            if trace.bit_point not in negative:
                continue
            neg = trace
            if DEBUG3: print("found negative: " + str(trace))
            overwrites_pos = False
            for index1 in range(index - 1, -1, -1):
                trace = traces[index1]
                if neg.same_value(trace):
                    if DEBUG3: print("     Writing to same var")
                    if trace.bit_point in negative:
                        if DEBUG3: print("     Negative does not directly overwrite positive")
                        #TODO, this counds as double negative
                        if trace.bit_point != neg.bit_point:
                            print("     Negative shadowed by another negative")
                            break

                        if DEBUG3: print("     Current negative has doubles " + str(neg)) #TODO, some frees don't have corresponding allocs, find a bunch called tgt for no reason... is this duplicate freeing? but double free not allowed!!!
                        doub_negative_map[neg.bit_point] = True
                    elif trace.bit_point in positive:
                        if DEBUG3: print("     Negative directly overwrite positive")
                        overwrites_pos = True
                        true_negative_map[neg.bit_point] = True
                        break
            if not overwrites_pos:
                part_negative_map[neg.bit_point] = True
                if DEBUG3: print("     Current negative never overwrites positive " + str(neg))
                if DEBUG3: print("     Current negative never overwrites positive " + str(neg)) #TODO, some frees don't have corresponding allocs, probably those ones we couldn't parse

        doub_positive_map = {}
        common_positives = None
        for pos in positive:
            doub_positive_map[pos] = False
        for index in range(len(traces) - 1, -1, -1):
            trace = traces[index]
            #if DEBUG3: print(str(trace))
            if not isinstance(trace, BitPointValue):
                continue
            if trace.bit_point not in positive:
                continue
            if DEBUG3: print("found positive: " + str(trace))
            pos = trace

            consecutive_positives = []
            consecutive_positives.append(str(trace.bit_point))
            for index1 in range(index - 1, -1, -1):
                trace = traces[index1]
                if not pos.same_value(trace):
                    continue
                #if DEBUG3: print("     Writing to same var")
                if trace.bit_point in positive:
                    if DEBUG3: print("     Positive follows positive")
                    #TODO, this counds as double positive
                    if trace.bit_point != pos.bit_point:
                        if DEBUG3: print("     at " + str(index) + " " + str(index1)\
                                + " Positive shadowed by another positive " + str(trace))
                    else:
                        if DEBUG3: print("     at " + str(index) + " " + str(index1)\
                                + " Current positive has doubles " + str(trace)) #TODO, some frees don't have corresponding allocs, find a bunch called tgt for no reason... is this duplicate freeing? but double free not allowed!!!
                    doub_positive_map[pos.bit_point] = True
                    consecutive_positives.append(str(trace.bit_point))
                    #break
                elif trace.bit_point in negative:
                    break
            if DEBUG3: print(" current common positives: " + str(set(consecutive_positives)))
            if common_positives is None:
                common_positives = set(consecutive_positives)
            else:
                common_positives = common_positives.intersection(set(consecutive_positives))
            if DEBUG3: print(" updated common positives: " + str(common_positives))

        print("doub positive map: " + self.map_str(doub_positive_map))
        print("common positive map: " + str(common_positives))
        if len(common_positives) == 0:
            ret_pos = positive
        else:
            ret_pos = [common_positives]

        ret_neg = []
        print("true negative map: " + self.map_str(true_negative_map))
        print("part negative map: " + self.map_str(part_negative_map))
        print("doub negative map: " + self.map_str(doub_negative_map))
        for k in true_negative_map:
            if true_negative_map[k]:
                ret_neg.append(k)
        return ret_pos, ret_neg

if __name__ == '__main__':
    bitTrace = BitTrace('/home/anygroup/perf_debug_tool/909_ziptest_exe9 /home/anygroup/perf_debug_tool/test.zip', pin='~/pin-3.11/pin')
    #target = '0x409c70'
    
    #target = '0x409c84' #472
    target = '0x409c55' #467

    #branch_point = BitPoint('0x409c41', '0x409c0c', 'rbp', '0x409c13', 'rbx')
    #TODO, in the future, should allow printing the register at the use site or even branch site?

    #branch_point = BitPoint('0x409c55', '0x409c51', 'rbp', '0x409c41', 'cl') #467
    branch_point = BitPoint('0x409c36', '0x409c32', 'rbp', '0x409c2e', 'cl') #464

    bitpoints = []
    bitpoints.append(BitPoint('0x40a6aa', '0x40a658', 'rsi', '0x40a662', 'cl')) #TODO missing the final point
    bitpoints.append(BitPoint('0x40a7a2', '0x40a78b', 'rbp', '0x40a792', 'cl')) #TODO missing the final point

    #TODO, should use proper 
    bitpoints.append(BitPoint('0x40a996', '0x40a989', 'rbx', '0x40a990', 'cl'))

    bitpoints.append(BitPoint('0x409d28', '0x409d25', 'rbp', '0x409d08', 'cl')) #DONE at use site
    bitpoints.append(BitPoint('0x409c6a', '0x409c67', 'rbp', '0x409c64', 'cl')) #DONE at use site
    bitpoints.append(BitPoint('0x409418', '0x409415', 'r9' , '0x40940b', 'cl')) #DONE at use site
    bitpoints.append(BitPoint('0x40abcc', '0x40abbf', 'rbp', '0x40abb9', 'cl')) #DONE at use site #TODO missing the final point
    #bitpoints[0x40aaad] = BitPoint('0x40aaad', '0x40aaad', 'rax', '0x40a966', 'rdx')



    bitTrace.get_trace(bitpoints, target, branch_point)
    traces = bitTrace.parse_bit_trace(bitpoints, target, branch_point)
    print("Got traces:")
    for t in traces:
        print(str(t))
    positive, negative = bitTrace.analyze_trace(traces, bitpoints, target, branch_point)
    #positive = [0x409418, 0x409c6a, 0x40a6aa]
    #negative = [0x409d28, 0x40a7a2, 0x40a996]
    print("positive:", [str(p) for p in positive])
    print("positive:" + str(positive))
    print("negative: ", [str(p) for p in negative])
    print("negative: " + str(negative))
    positive, negative = bitTrace.filter_positive_and_negative(positive, negative, traces, bitpoints, target, branch_point)
    print("positive:", [str(p) for p in positive])
    print("negative: ", [str(p) for p in negative])
