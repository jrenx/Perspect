from __future__ import division
import subprocess
import os

pin_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG = True

class InsTrace:

    def __init__(self, program, is_32=False, pin='pin', out='instruction_trace.out'):
        self.program = program.split()
        self.is_32 = is_32
        self.pin = pin
        self.out = out

    '''
        Invokes PIN to watch given set of instructions.
        Every time the instruction is executed,
        PIN will print the address(pc) of the instruction in the output file.
    '''
    def run_instruction_trace(self, instructions):
        if self.is_32:
            obj_file = os.path.join(pin_dir, 'obj-ia32', 'instruction_log.so')
        else:
            obj_file = os.path.join(pin_dir, 'obj-intel64', 'instruction_log.so')
        pin_program_list = [self.pin, '-t', obj_file, '-o', os.path.join(pin_dir, self.out)]
        for insn in instructions:
            pin_program_list.extend(['-i', insn])
        pin_program_list.append('--')
        pin_program_list.extend(self.program)
        pin_cmd = ' '.join(pin_program_list)
        if (DEBUG): print("Invoking pin with: " + pin_cmd)
        subprocess.call(pin_cmd, shell=True)

    def cleanup(self):
        out_file = os.path.join(pin_dir, self.out)
        cmd = ' '.join(['rm', out_file])
        subprocess.call(cmd, shell=True)

    def get_predictive_predecessor(self, predecessor, successor):
        # return 1 for 1-to-1, n for 1-to-n, 0 for others
        ret = 0
        pred_cnt = 0
        succ_cnt = 0
        with open(os.path.join(pin_dir, self.out)) as file:
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
        last_is_succ = False
        #print("predecessor: " + hex(predecessor))
        #print("successor:   " + hex(successor))
        with open(os.path.join(pin_dir, self.out)) as file:
            for line in file:
                if 'start' in line or 'eof' in line:
                    continue
                addr = int(line, 16)

                if addr == successor:
                    if last_is_succ is False:
                        if p_pred_cnt > -1:
                            assert p_succ_cnt > -1
                            if pred_cnt != p_pred_cnt or \
                               succ_cnt != p_succ_cnt:
                                same = False

                            # More has priority over less
                            if succ_cnt > pred_cnt:
                                more = True
                            elif succ_cnt < pred_cnt:
                                if more is not True:
                                    less = True
                        p_succ_cnt = succ_cnt
                        p_pred_cnt = pred_cnt
                        succ_cnt = 0
                        pred_cnt = 0
                    succ_cnt += 1
                    last_is_pred = False
                elif addr == predecessor:
                    pred_cnt += 1
                    last_is_succ = False
                else:
                    last_is_succ = False

        # ratio is only meaningful when we get "same"
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
        instructions = [hex(pred) for pred in predecessors]
        instructions.append(hex(successor))
        self.run_instruction_trace(instructions)
        ret = {}
        for pred in predecessors:
            print("Analyzing predecessor: " + str(hex(pred)) + " for successor " + str(successor))
            ret[pred] = self.get_predictive_predecessor2(pred, successor)
        #self.cleanup()
        return ret

if __name__ == '__main__':
    trace = InsTrace('/home/anygroup/perf_debug_tool/909_ziptest_exe9 /home/anygroup/perf_debug_tool/test.zip', pin='~/pin-3.11/pin')
    #print(trace.get_predictive_predecessors([0x409d98, 0x409e06], 0x409daa))
    #print(trace.get_predictive_predecessors([0x409deb, 0x409d9d], 0x409da5))
    #print(trace.get_predictive_predecessors([0x409d47], 0x409daa)) #488, 500
    print(trace.get_predictive_predecessors([0x409c84], 0x409d47)) #472, 488
    #print(trace.get_predictive_predecessors([0x409c55], 0x409d47)) #467, 472
    #print(trace.get_predictive_predecessors([0x409c55], 0x409c84)) #467, 472
