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
        bitmask_point = config['bitmask_point']
        bitmask_reg = config['bitmask_reg']
        shift_point = config['shift_point']
        shift_reg = config['shift_reg']
        shift_direction = config['shift_direction']

        gdb.set_convenience_variable('trace_point', trace_point)
        gdb.set_convenience_variable('reg', reg)
        gdb.set_convenience_variable('continue_count', continue_count)
        gdb.set_convenience_variable('log_filename', log_filename)
        gdb.set_convenience_variable('bitmask_point', bitmask_point)
        gdb.set_convenience_variable('bitmask_reg', bitmask_reg)
        gdb.set_convenience_variable('shift_point', shift_point)
        gdb.set_convenience_variable('shift_reg', shift_reg)
        gdb.set_convenience_variable('shift_direction', shift_direction)

        return 1


InitArgument()


class UpdateFilePosition(gdb.Function):
    def __init__(self):
        super(UpdateFilePosition, self).__init__('update_file')

    def invoke(self):
        log_filename = str(gdb.convenience_variable('log_filename')).strip('"')
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
        log_filename = str(gdb.convenience_variable('log_filename')).strip('"')
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
        log_filename = str(gdb.convenience_variable('log_filename')).strip('"')
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
        trace_point = str(gdb.convenience_variable('trace_point')).strip('"')
        gdb.execute("br *{}".format(trace_point))
        return 1


SetTracePoint()


def shift_bitmask(bitmask_str, shift_str, shift_direction):
    bitmask = int(bitmask_str, 16)
    shift = int(shift_str, 16)
    if shift_direction == 'left':
        bitmask = bitmask << shift
    elif shift_direction == 'right':
        bitmask = bitmask >> shift
    return hex(bitmask)


class WatchRegValue(gdb.Function):
    def __init__(self):
        super(WatchRegValue, self).__init__('watch_reg_value')

    def invoke(self):
        reg_value = str(gdb.convenience_variable('reg_value')).strip('"')
        bitmask_value = str(gdb.convenience_variable('bitmask_reg_value')).strip('"')
        shift_value = str(gdb.convenience_variable('shift_reg_value')).strip('"')
        shift_direction = str(gdb.convenience_variable('shift_direction')).strip('"')
        bitmask = shift_bitmask(bitmask_value, shift_value, shift_direction)
        gdb.execute('watch -l *(long *){} mask {}'.format(reg_value, bitmask))
        return 1


WatchRegValue()


class SetBitmaskPoint(gdb.Function):
    def __init__(self):
        super(SetBitmaskPoint, self).__init__('set_bitmask_point')

    def invoke(self):
        bitmask_point = str(gdb.convenience_variable('bitmask_point')).strip('"')
        gdb.execute("br *{}".format(bitmask_point))
        return 1


SetBitmaskPoint()


class SetShiftPoint(gdb.Function):
    def __init__(self):
        super(SetShiftPoint, self).__init__('set_shift_point')

    def invoke(self):
        bitmask_point = str(gdb.convenience_variable('shift_point')).strip('"')
        gdb.execute("br *{}".format(bitmask_point))
        return 1


SetShiftPoint()


class GetBitmaskReg(gdb.Function):
    def __init__(self):
        super(GetBitmaskReg, self).__init__('get_bitmask_reg')

    def invoke(self):
        reg = str(gdb.convenience_variable('bitmask_reg')).strip('"')
        gdb.execute('i reg {}'.format(reg))
        gdb.flush()
        log_filename = str(gdb.convenience_variable('log_filename')).strip('"')
        with open(log_filename, 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
        for line in outs:
            words = line.split()
            if len(words) >= 2 and words[0] == reg:
                gdb.set_convenience_variable('bitmask_reg_value', words[1])
                return 1
        return 0


GetBitmaskReg()


class GetShiftReg(gdb.Function):
    def __init_(self):
        super(GetShiftReg, self).__init__('get_shift_reg')

    def invoke(self):
        reg = str(gdb.convenience_variable('shift_reg')).strip('"')
        gdb.execute('i reg {}'.format(reg))
        gdb.flush()
        log_filename = str(gdb.convenience_variable('log_filename')).strip('"')
        with open(log_filename, 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
        for line in outs:
            words = line.split()
            if len(words) >= 2 and words[0] == reg:
                gdb.set_convenience_variable('shift_reg_value', words[1])
                return 1
        return 0


GetShiftReg()


class CheckProgramStop(gdb.Function):
    def __init__(self):
        super(CheckProgramStop, self).__init__('is_program_stop')

    def invoke(self):
        log_filename = str(gdb.convenience_variable('log_filename')).strip('"')
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
