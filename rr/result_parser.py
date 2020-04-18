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

        break_point = config['break_point']
        reg = config['reg']

        gdb.set_convenience_variable('br_point', break_point)
        gdb.set_convenience_variable('reg', reg)

        if 'out' in config:
            output_filename = config['out']
        else:
            output_filename = 'out.log'
        os.remove(output_filename)
        gdb.set_convenience_variable('output_filename', output_filename)
        return 1


InitArgument()


class UpdateFilePosition(gdb.Function):
    def __init__(self):
        super(UpdateFilePosition, self).__init__('update_file')

    def invoke(self):
        with open('result.log', 'r') as f:
            f.seek(0, 2)
            position = f.tell()
        gdb.set_convenience_variable('log_position', position)
        return 1


UpdateFilePosition()


class SetBreakpoint(gdb.Function):
    def __init__(self):
        super(SetBreakpoint, self).__init__('set_breakpoint')

    def invoke(self):
        br_point = str(gdb.convenience_variable('br_point')).strip('"')
        gdb.execute('br {}'.format(br_point))
        return 1


SetBreakpoint()


class ContinueMulti(gdb.Function):
    def __init__(self):
        super(ContinueMulti, self).__init__('continue_multi')

    def invoke(self):
        continue_count = gdb.convenience_variable('continue_count')
        for _ in range(continue_count):
            gdb.execute('c')
        return 1


ContinueMulti()


class CheckProcessExit(gdb.Function):
    def __init__(self):
        super(CheckProcessExit, self).__init__('is_process_exit')

    def invoke(self):
        with open('result.log', 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
        for line in outs:
            if re.search(r'Inferior \d+ \(process \d+\) exited', line):
                gdb.set_convenience_variable('RET', 1)
                return 1
        gdb.set_convenience_variable('RET', 0)
        return 0


CheckProcessExit()


class CheckProgramStop(gdb.Function):
    def __init__(self):
        super(CheckProgramStop, self).__init__('is_program_stop')

    def invoke(self):
        with open('result.log', 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
        for line in outs:
            if re.search(r'Program stopped', line):
                gdb.set_convenience_variable('RET', 1)
                return 1
        gdb.set_convenience_variable('RET', 0)
        return 0


CheckProgramStop()


class CheckBreakpointSuccess(gdb.Function):
    def __init__(self):
        super(CheckBreakpointSuccess, self).__init__('is_br_success')

    def invoke(self):
        with open('result.log', 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
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
        reg = str(gdb.convenience_variable('reg')).strip('"')
        gdb.execute('i reg {}'.format(reg))
        gdb.flush()
        with open('result.log', 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
        for line in outs:
            words = line.split()
            if len(words) >= 2 and words[0] == reg:
                output_filename = str(gdb.convenience_variable('output_filename')).strip('"')
                with open(output_filename, 'a') as f:
                    f.write('register {} value: {}\n'.format(reg, words[1]))
                gdb.set_convenience_variable('reg_value', words[1])
                gdb.set_convenience_variable('RET', 1)
                return 1
        gdb.set_convenience_variable('RET', 0)
        return 0


GetRegValue()


class WatchRegValue(gdb.Function):
    def __init__(self):
        super(WatchRegValue, self).__init__('watch_reg_value')

    def invoke(self):
        reg_value = str(gdb.convenience_variable('reg_value')).strip('"')
        gdb.execute('watch -l *(int *){}'.format(reg_value))
        return 1


WatchRegValue()


class DeleteWatchPoint(gdb.Function):
    def __init__(self):
        super(DeleteWatchPoint, self).__init__('delete_watch_point')

    def invoke(self):
        gdb.execute('delete br {}'.format(str(gdb.convenience_variable('continue_count') + 1)))
        return 1


DeleteWatchPoint()


class ProcessWatchOutput(gdb.Function):
    def __init__(self):
        super(ProcessWatchOutput, self).__init__('process_watch_output')

    def invoke(self):
        with open('result.log', 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()
        output_filename = str(gdb.convenience_variable('output_filename')).strip('"')
        output_file = open(output_filename, 'a')
        found = False
        for line in outs:
            if re.search(r'(Old)|(New) value =', line):
                found = True
        if found:
            output_file.writelines(outs)
            return 1
        output_file.close()
        return 0


ProcessWatchOutput()


class CleanUp(gdb.Function):
    def __init__(self):
        super(CleanUp, self).__init__('clean_up')

    def invoke(self):
        os.remove('result.log')
        return 1


CleanUp()
