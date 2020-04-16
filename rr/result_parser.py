import gdb
import json
import re


class InitArgument(gdb.Function):
    def __init__(self):
        super(InitArgument, self).__init__('init_argument')

    def invoke(self):
        with open('config.json') as configFile:
            config = json.load(configFile)

        filename = config['file']
        line_num = config['line']
        reg = config['reg']

        gdb.set_convenience_variable('br_point', '{}:{}'.format(filename, line_num))
        gdb.set_convenience_variable('reg', reg)

        if 'out' in config:
            output_filename = config['out']
        else:
            output_filename = 'out.log'
        gdb.set_convenience_variable('output_filename', output_filename)
        return 1


InitArgument()


class SetBreakpoint(gdb.Function):
    def __init__(self):
        super(SetBreakpoint, self).__init__('set_breakpoint')

    def invoke(self):
        br_point = gdb.convenience_variable('br_point')
        gdb.execute('br {}'.format(br_point))
        return 1

SetBreakpoint()


class ContinueMulti(gdb.Function):
    def __init__(self):
        super(ContinueMulti, self).__init__('continue_multi')

    def invoke(self):
        continue_count = gdb.convenience_variable('continue_count')
        gdb.execute('c {}'.format(str(continue_count)))
        return 1


ContinueMulti()


class CheckProcessExit(gdb.Function):
    def __init__(self):
        super(CheckProcessExit, self).__init__('is_process_exit')

    def invoke(self):
        outs = open('result.log', 'r').readlines()
        for line in outs:
            if re.search(r'Inferior \d+ \(process \d+\) exited', line):
                gdb.set_convenience_variable('RET', 1)
                return 1
        gdb.set_convenience_variable('RET', 0)
        return 0


CheckProcessExit()


class CheckBreakpointSuccess(gdb.Function):
    def __init__(self):
        super(CheckBreakpointSuccess, self).__init__('is_br_success')

    def invoke(self):
        outs = open('result.log', 'r').readlines()
        for line in outs:
            if re.search(r'Make breakpoint pending on future shared library load', line):
                gdb.set_convenience_variable('RET', 0)
                return 0
        gdb.set_convenience_variable('RET', 1)
        return 1


CheckBreakpointSuccess()


class GetRegValue(gdb.Function):
    def __init__(self):
        super(GetRegValue, self).__init__('get_reg_value')

    def invoke(self):
        outs = open('result.log', 'r').readlines()
        reg = gdb.convenience_variable('reg')
        for line in outs:
            words = line.split()
            if len(words) >= 2 and words[0] == reg:
                gdb.set_convenience_variable('reg_value', words[1])
                gdb.set_convenience_variable('RET', 1)
                return 1
        gdb.set_convenience_variable('RET', 0)
        return 0


GetRegValue()
