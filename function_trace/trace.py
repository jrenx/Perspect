import sys
import subprocess
import os


class TraceCollector:

    def __init__(self, program, is_32=False, pin='pin'):
        # program is a string that can run the test program
        self.program = program.split()
        self.is_32 = is_32
        self.pin = pin  # path to pin binary
        self.traces = {}

    def is_trace_available(self, fucntion_name):
        return fucntion_name in self.traces

    def is_trace_on_disk(self, function_name):
        return os.path.isfile('{}.out'.format(function_name))

    def read_trace_from_disk(self, function_name):
        self.traces[function_name] = self.parse_function_trace('{}.out'.format(function_name))

    def run_function_trace(self, function_name):
        if self.is_32:
            obj_file = os.path.join('obj-ia32', 'function_trace.so')
        else:
            obj_file = os.path.join('obj-intel64', 'function_trace.so')
        pin_program_list = [self.pin, '-t', obj_file, '-f', function_name, '-o', '{}.out'.format(function_name), '--']
        pin_program_list.extend(self.program)
        subprocess.run(pin_program_list, shell=True, check=True)

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
