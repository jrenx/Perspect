import subprocess
import os


class InsRegTrace:

    def __init__(self, program, is_32=False, pin='pin'):
        self.program = program.split()
        self.is_32 = is_32
        self.pin = pin

    def run_function_trace(self, ins_reg_map):
        if self.is_32:
            obj_file = os.path.join('obj-ia32', 'instruction_log.so')
        else:
            obj_file = os.path.join('obj-intel64', 'instruction_log.so')
        pin_program_list = [self.pin, '-t', obj_file, '-o', 'instruction_trace.out']

        for ins, reg in ins_reg_map.items():
            pin_program_list.extend(['-i', ins, '-r', reg])

        pin_program_list.append('--')
        pin_program_list.extend(self.program)
        subprocess.call(' '.join(pin_program_list), shell=True)


if __name__ == '__main__':
    trace = InsRegTrace('~/go-repro/909_ziptest_exe2 ~/go-repro/909_ziptest/test.zip', pin='~/pin-3.11/pin')
    trace.run_function_trace({"0x409c41": "pc", "0x409c70": "pc", "0x409c10": 'rbp'})
