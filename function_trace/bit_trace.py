import instruction_reg_trace


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


class BitPointValue:
    def __init__(self, bit_point, addr_value, shift_value):
        self.bit_point = bit_point
        self.addr_value = addr_value
        self.shift_value = shift_value

    def __eq__(self, other):
        if not isinstance(other, BitPointValue):
            return False
        return self.bit_point == other.bit_point and self.addr_value == other.addr_value and self.shift_value == other.shift_value


class BitTrace(InsRegTrace):

    def __init__(self, program, is_32=False, pin='pin'):
        super(BitTrace, self).__init__(program, is_32, pin)

    def get_trace(self, bit_points, target, branch):
        ins_reg_map = dict()
        for bit_point in bit_points:
            ins_reg_map.update({bit_point.point: "pc", bit_point.addr_point: bit_point.addr_reg,
                                bit_point.shift_point: bit_point.shift_reg})
        ins_reg_map.update({target: "pc"})
        ins_reg_map.update({branch: "pc"})
        super(BitTrace, self).run_function_trace(ins_reg_map)

    def parse_bit_trace(self, bit_points, target, branch):
        # Creat map from pc to bit_point
        pc_map = dict()
        for bit_point in bit_points:
            pc_map[bit_point.point] = bit_point
            pc_map[bit_point.addr_point] = bit_point
            pc_map[bit_point.shift_point] = bit_point

        traces = []
        curr_bitpoint_value = None
        with open('instruction_trace.out') as trace_file:
            for line in trace_file:
                addr = line.split()[0].strip(':')
                reg = line.split()[1]
                if addr == target:
                    if curr_bitpoint_value is not None:
                        traces.append(curr_bitpoint_value)
                        curr_bitpoint_value = None
                    traces.append(target)
                elif addr == branch:
                    traces.append(curr_bitpoint_value)
                    curr_bitpoint_value = None
                    traces.append(branch)
                else:
                    bit_point = pc_map[addr]
                    if curr_bitpoint_value is not None and curr_bitpoint_value.bit_point == bit_point:
                        if bit_point.addr_point == addr:
                            curr_bitpoint_value.addr_value = reg
                        elif bit_point.shift_point == addr:
                            curr_bitpoint_value.shift_value = reg
                        else:
                            raise ValueError("wrong address")
                    elif curr_bitpoint_value is None:
                        curr_bitpoint_value = BitPointValue(bit_point, None, None)
                    else:
                        traces.append(curr_bitpoint_value)
                        curr_bitpoint_value = BitPointValue(bit_point, None, None)
                        if bit_point.addr_point == addr:
                            curr_bitpoint_value.addr_value = reg
                        elif bit_point.shift_point == addr:
                            curr_bitpoint_value.shift_value = reg
                        else:
                            raise ValueError("wrong address")

        return traces


if __name__ == '__main__':
    trace = BitTrace('~/go-repro/909_ziptest_exe2 ~/go-repro/909_ziptest/test.zip', pin='~/pin-3.11/pin')
