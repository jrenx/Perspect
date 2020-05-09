import gdb
import json
import re
import os


class InitArgument(gdb.Function):
    def __init__(self):
        super(InitArgument, self).__init__('init_argument')

    def invoke(self):
        with open('config.json') as configFile:
            config = json.load(configFile)

        gdb.execute('br {}'.format(config['breakpoint']))
        trace_point = config['trace_point']
        reg = config['reg']
        continue_count = config['continue_count']
        log_filename = config['log_filename']

        gdb.set_convenience_variable('trace_point', trace_point)
        gdb.set_convenience_variable('reg', reg)
        gdb.set_convenience_variable('continue_count', continue_count)
        gdb.set_convenience_variable('log_filename', log_filename)

        return 1


InitArgument()


class UpdateFilePosition(gdb.Function):
    def __init__(self):
        super(UpdateFilePosition, self).__init__('update_file')

    def invoke(self):
        log_filename = gdb.convenience_variable('log_filename')
        with open(log_filename, 'r') as f:
            f.seek(0, 2)
            position = f.tell()
        gdb.set_convenience_variable('log_position', position)
        return 1


UpdateFilePosition()


class ContinueMulti(gdb.Function):
    def __init__(self):
        super(ContinueMulti, self).__init__('continue_multi')

    def invoke(self):
        continue_count = gdb.convenience_variable('continue_count')
        gdb.execute('c')
        if continue_count > 1:
            gdb.execute('c {}'.format(str(continue_count - 1)))
        return 1


ContinueMulti()


class SetLogFile(gdb.Function):
    def __init__(self):
        super(SetLogFile, self).__init__('set_log_file')

    def invoke(self):
        log_filename = gdb.convenience_variable('log_filename')
        gdb.execute('set logging file {}'.format(log_filename))
        return 1


SetLogFile()


class GetRegValue(gdb.Function):
    def __init__(self):
        super(GetRegValue, self).__init__('get_reg_value')

    def invoke(self):
        reg = str(gdb.convenience_variable('reg')).strip('"')
        gdb.execute('i reg {}'.format(reg))
        gdb.flush()
        log_filename = gdb.convenience_variable('log_filename')
        with open(log_filename, 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
        for line in outs:
            words = line.split()
            if len(words) >= 2 and words[0] == reg:
                gdb.set_convenience_variable('reg_value', words[1])
                return 1
        return 0


GetRegValue()


class SetTracePoint(gdb.Function):
    def __init__(self):
        super(SetTracePoint, self).__init__('set_trace_point')

    def invoke(self):
        trace_point = gdb.convenience_variable('trace_point').strip('"')
        gdb.execute("br *{}".format(trace_point))
        return 1


class WatchRegValue(gdb.Function):
    def __init__(self):
        super(WatchRegValue, self).__init__('watch_reg_value')

    def invoke(self):
        reg_value = str(gdb.convenience_variable('reg_value')).strip('"')
        gdb.execute('watch -l *(int *){}'.format(reg_value))
        return 1


WatchRegValue()


class CheckProcessExit(gdb.Function):
    def __init__(self):
        super(CheckProcessExit, self).__init__('is_process_exit')

    def invoke(self):
        log_filename = gdb.convenience_variable('log_filename')
        with open(log_filename, 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
        for line in outs:
            if re.search(r'Inferior \d+ \(process \d+\) exited', line):
                return 1
        return 0


CheckProcessExit()


class CheckProgramStop(gdb.Function):
    def __init__(self):
        super(CheckProgramStop, self).__init__('is_program_stop')

    def invoke(self):
        log_filename = gdb.convenience_variable('log_filename')
        with open(log_filename, 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
        for line in outs:
            if re.search(r'Program stopped', line):
                return 1
        return 0


CheckProgramStop()
