import subprocess
import os

working_dir = "/home/anygroup/perf_debug_tool/function_trace/"

class InsRegTrace:

    def __init__(self, program, is_32=False, pin='pin'):
        self.program = program.split()
        self.is_32 = is_32
        self.pin = pin

    def run_function_trace(self, ins_reg_map):
        if self.is_32:
            obj_file = os.path.join('obj-ia32', working_dir + 'instruction_reg_log.so')
        else:
            obj_file = os.path.join('obj-intel64', working_dir + 'instruction_reg_log.so')
        pin_program_list = [self.pin, '-t', obj_file, '-o', working_dir + 'instruction_trace.out']

        for ins, reg in ins_reg_map.items():
            pin_program_list.extend(['-i', ins, '-r', reg])

        pin_program_list.append('--')
        pin_program_list.extend(self.program)
        subprocess.call(' '.join(pin_program_list), shell=True)

    def parse_break_points(self, branch, target):
        count = -1
        last_break = ""
        taken = []
        not_taken = []
        with open(working_dir + "instruction_trace.out") as log:
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
    trace = InsRegTrace('~/go-repro/909_ziptest_exe2 ~/go-repro/909_ziptest/test.zip', pin='~/pin-3.11/pin')
    trace.run_function_trace({"0x409c41": "pc", "0x409c70": "pc", "0x409c10": 'rbp'})
