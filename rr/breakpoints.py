import gdb
import json
import re
import os

rr_dir = os.path.dirname(os.path.realpath(__file__))

class InitArgument(gdb.Function):
    def __init__(self):
        super(InitArgument, self).__init__('init_argument')

    def invoke(self):
        with open(os.path.join(rr_dir, 'config.json')) as configFile:
            config = json.load(configFile)

        breakpoints = config['breakpoints']
        reg_points = config['reg_points']

        for br in reg_points:
            gdb.execute("br {}".format(br))
        for br in breakpoints:
            gdb.execute("br {}".format(br))

        return 1


InitArgument()


class RunBreakCommands(gdb.Function):
    def __init__(self):
        super(RunBreakCommands, self).__init__('run_break_commands')

    def invoke(self):
        with open(os.path.join(rr_dir, 'config.json')) as configFile:
            config = json.load(configFile)

        regs = config['regs']
        step = config['step']
        deref = config['deref']

        with open(os.path.join(rr_dir, 'breakpoints.log'), 'r') as f:
            position = gdb.convenience_variable('log_position')
            if position is not None:
                position = int(position)
                f.seek(position)
            outs = f.readlines()

        for line in outs:
            match = re.match(r'Breakpoint (\d+),', line)
            if not match:
                continue
            break_num = int(match.group(0).split()[1][:-1]) - 1
            if break_num < len(regs):
                if step:
                    gdb.execute('si')
                gdb.execute('i reg {}'.format(regs[break_num]))
                if deref:
                    try:
                        gdb.execute('p/x *((long *) ${})'.format(regs[break_num]))
                    except gdb.MemoryError:
                        print("memory error")
                return 1
        return 0


RunBreakCommands()


class CheckProcessExit(gdb.Function):
    def __init__(self):
        super(CheckProcessExit, self).__init__('is_process_exit')

    def invoke(self):
        with open(os.path.join(rr_dir, 'breakpoints.log'), 'r') as f:
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


class UpdateFilePosition(gdb.Function):
    def __init__(self):
        super(UpdateFilePosition, self).__init__('update_file')

    def invoke(self):
        with open(os.path.join(rr_dir, 'breakpoints.log'), 'r') as f:
            f.seek(0, 2)
            position = f.tell()
        gdb.set_convenience_variable('log_position', position)
        return 1


UpdateFilePosition()
