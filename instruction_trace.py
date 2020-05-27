from __future__ import division
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
            obj_file = os.path.join(working_dir, 'obj-ia32', 'instruction_log.so')
        else:
            obj_file = os.path.join(working_dir, 'obj-intel64', 'instruction_log.so')
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

    def get_predictive_predecessor2(self, predecessor, successor):
        # return 1 for 1-to-1, n for 1-to-n, 0 for others
        same = True
        less = None
        more = None
        p_pred_cnt = -1
        p_succ_cnt = -1
        pred_cnt = 0
        succ_cnt = 0
        last_is_succ = None
        #print("predecessor: " + hex(predecessor))
        #print("successor:   " + hex(successor))
        with open(working_dir + 'instruction_trace.out') as file:
            for line in file:
                if 'start' in line or 'eof' in line:
                    continue
                addr = int(line, 16)

                if addr == successor:
                    if last_is_succ is False:
                        succ_cnt = 0
                    succ_cnt += 1
                    last_is_succ = True
                else:
                    #print("succ: " + str(succ_cnt))
                    #print("pred: " + str(pred_cnt))
                    #print("p succ: " + str(p_succ_cnt))
                    #print("p pred: " + str(p_pred_cnt))
                    if (last_is_succ is True or addr != predecessor) \
                            and pred_cnt != 0:
                        if p_pred_cnt != -1:
                            if pred_cnt != p_pred_cnt or \
                               succ_cnt != p_succ_cnt:
                                same = False
                        p_pred_cnt = pred_cnt
                        p_succ_cnt = succ_cnt
                              
                        # More has priority over less
                        if succ_cnt > pred_cnt:
                            more = True
                        elif succ_cnt < pred_cnt:
                            if more is not True:
                                less = True
                        pred_cnt = 0
                        succ_cnt = 0


                    last_is_succ = False
                    if addr == predecessor:
                        if last_is_succ is True:
                            pred_cnt = 0
                        pred_cnt += 1
                        succ_cnt = 0
                    else:
                        succ_cnt = 0
                        pred_cnt = 0
        ratio = p_succ_cnt/p_pred_cnt

        ret = ""
        if same: 
            ret += "same"
        if not more and less:
            ret += "less"
        if more:
            ret += "more"

        return (ret, ratio)

    def get_predictive_predecessors(self, predecessors, successor):
        self.run_function_trace([hex(pred) for pred in predecessors], hex(successor))
        ret = {}
        for pred in predecessors:
            #print("Analyzing predecessor: " + str(hex(pred)))
            ret[pred] = self.get_predictive_predecessor2(pred, successor)
        return ret

if __name__ == '__main__':
    trace = InsTrace('/home/anygroup/perf_debug_tool/909_ziptest_exe6 /home/anygroup/perf_debug_tool/test.zip', pin='~/pin-3.11/pin')
    #print(trace.get_predictive_predecessors([0x409d98, 0x409e06], 0x409daa))
    #print(trace.get_predictive_predecessors([0x409deb, 0x409d9d], 0x409da5))
    #print(trace.get_predictive_predecessors([0x409d47], 0x409daa)) #488, 500
    print(trace.get_predictive_predecessors([0x409c84], 0x409d47)) #472, 488
    #print(trace.get_predictive_predecessors([0x409c55], 0x409d47)) #467, 472
    #print(trace.get_predictive_predecessors([0x409c55], 0x409c84)) #467, 472
