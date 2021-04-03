import subprocess
import os

pin_dir = os.path.dirname(os.path.realpath(__file__))

class InsRegTrace:

    def __init__(self, program, is_32=False, pin='pin', out='instruction_trace.out'):
        self.program = program.split()
        self.is_32 = is_32
        self.pin = pin
        self.out = out

    def run_function_trace(self, ins_reg_map):
        if self.is_32:
            obj_file = os.path.join(pin_dir, 'obj-ia32', 'instruction_reg_log.so')
        else:
            obj_file = os.path.join(pin_dir, 'obj-intel64', 'instruction_reg_log.so')
        pin_program_list = [self.pin, '-t', obj_file, '-o', os.path.join(pin_dir, self.out)]

        for ins, reg in ins_reg_map.items():
            pin_program_list.extend(['-i', ins, '-r', reg])

        pin_program_list.append('--')
        pin_program_list.extend(self.program)
        pin_cmd = ' '.join(pin_program_list)
        print(pin_cmd)
        subprocess.call(pin_cmd, shell=True)

    def parse_break_points(self, branch, target):
        count = -1
        last_break = ""
        taken = []
        not_taken = []
        with open(os.path.join(pin_dir, self.out)) as log:
            for line in log:
                if branch in line:
                    if last_break == branch:
                        not_taken.append(count)
                    last_break = branch
                    count += 1
                elif target in line:
                    taken.append(count)
                    last_break = target

        return taken, not_taken


if __name__ == '__main__':
    trace = InsRegTrace('/home/anygroup/perf_debug_tool/909_ziptest_exe9 /home/anygroup/perf_debug_tool/test.zip', pin='~/pin-3.11/pin')
    trace.run_function_trace({"0x409c41": "pc", "0x409c70": "pc", "0x409c10": 'rbp'})
    # instruction1 -> register1, instruction2 -> register2

