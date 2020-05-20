import subprocess
import os

working_dir = "/home/anygroup/perf_debug_tool/function_trace/"

class InsTrace:

    def __init__(self, program, is_32=False, pin='pin'):
        self.program = program.split()
        self.is_32 = is_32
        self.pin = pin

    def run_function_trace(self, predecessors, successor):
        if self.is_32:
            obj_file = os.path.join('obj-ia32', working_dir + 'instruction_log.so')
        else:
            obj_file = os.path.join('obj-intel64', working_dir + 'instruction_log.so')
        pin_program_list = [self.pin, '-t', obj_file, '-o', working_dir + 'instruction_trace.out']
        for pred in predecessors:
            pin_program_list.extend(['-i', pred])
        pin_program_list.extend(['-i', successor])
        pin_program_list.append('--')
        pin_program_list.extend(self.program)
        subprocess.call(' '.join(pin_program_list), shell=True)

    def get_predictive_predecessor(self, predecessor, successor):
        # return 1 for 1-to-1, n for 1-to-n, 0 for others
        ret = 0
        pred_cnt = 0
        succ_cnt = 0
        with open(working_dir + 'instruction_trace.out') as file:
            for line in file:
                if 'start' in line or 'eof' in line:
                    continue
                addr = int(line, 16)
                if addr == predecessor:
                    if pred_cnt > 0:
                        return 0
                    pred_cnt += 1
                    if ret == 0:
                        ret = succ_cnt
                    elif ret != succ_cnt:
                        return 0
                    succ_cnt = 0
                elif addr == successor:
                    succ_cnt += 1
                    pred_cnt = 0
                else:
                    succ_cnt = 0
                    pred_cnt = 0
        return ret

    def get_predictive_predecessors(self, predecessors, successor):
        self.run_function_trace([hex(pred) for pred in predecessors], hex(successor))
        ret = {}
        for pred in predecessors:
            ret[pred] = self.get_predictive_predecessor(pred, successor)
        return ret

if __name__ == '__main__':
    trace = InsTrace('~/go-repro/909_ziptest_exe2 ~/go-repro/909_ziptest/test.zip', pin='~/pin-3.11/pin')
    print(trace.get_predictive_predecessors([0x409deb, 0x409d9d], 0x409da5))
