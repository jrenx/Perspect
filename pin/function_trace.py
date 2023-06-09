import sys
import subprocess
import os

pin_dir = os.path.dirname(os.path.realpath(__file__))
DEBUG = True

class TraceCollector:

    def __init__(self, program, is_32=False, pin='pin'):
        # program is a string that can run the test program
        self.program = program.split()
        self.is_32 = is_32
        self.pin = str(pin)  # path to pin binary
        self.traces = {}

    def is_trace_available(self, fucntion_name):
        return fucntion_name in self.traces

    def is_trace_on_disk(self, function_name):
        return os.path.isfile(os.path.join(pin_dir, '{}.out'.format(function_name)))

    def read_trace_from_disk(self, function_name):
        self.traces[function_name] = self.parse_function_trace(os.path.join(pin_dir, '{}.out'.format(function_name)))

    def run_function_trace(self, function_name):
        if self.is_32:
            obj_file = os.path.join(pin_dir, 'obj-ia32', 'function_trace.so')
        else:
            obj_file = os.path.join(pin_dir, 'obj-intel64', 'function_trace.so')
        pin_program_list = [self.pin, '-t', obj_file, '-f', function_name, '-o', os.path.join(pin_dir, '{}.out'.format(function_name)), '--']
        pin_program_list.extend(self.program)
        pin_cmd = ' '.join(pin_program_list)
        if (DEBUG): print("Invoking pin with: " + pin_cmd)
        subprocess.call(pin_cmd, shell=True)

    def cleanup(self, function_name):
        out_file = os.path.join(pin_dir, '{}.out'.format(function_name))
        cmd = ' '.join(['rm', out_file])
        subprocess.call(cmd, shell=True)


    def is_instruction_after(self, function_name, before, after):
        traces = self.traces[function_name]
        if isinstance(before, str):
            before = int(before, 16)
        if isinstance(after, str):
            after = int(after, 16)
        for trace in traces:
            found = False
            for instruction in trace:
                if found and instruction != after:
                    return False
                if instruction == before:
                    found = True
                else:
                    found = False
        return True

    def parse_function_trace(self, filename):
        traces = []

        with open(filename, 'r') as inputFile:
            trace = []
            for line in inputFile:
                if 'start' in line:
                    if len(trace) > 0:
                        traces.append(trace)
                    trace = []
                elif 'eof' in line:
                    if len(trace) > 0:
                        traces.append(trace)
                    break
                elif '0x' in line:
                    trace.append(int(line, 16))
                else:
                    print("Warning: failed to parse line: " + line)

        return traces
