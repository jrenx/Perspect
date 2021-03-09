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
        off_regs = config['off_regs']
        offsets = config['offsets']
        shifts = config['shifts']
        src_regs = config['src_regs']

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
            is_go_file = line.split()[-1].split(':')[0].endswith('.go')
            if break_num < len(regs):
                if step:
                    gdb.execute('si')
                try:
                    arg = ''

                    arg += '(${}'.format(regs[break_num])
                    if shifts[break_num] != '0x0':
                        arg += '<<{}'.format(shifts[break_num]) #TODO test this
                    if off_regs[break_num] != '':
                        arg += '+${}*{}'.format(off_regs[break_num], offsets[break_num])
                    elif offsets[break_num] != '0x0':
                        arg += '+{}'.format(offsets[break_num])
                    arg += ')'

                    cmd = 'p/x ' + arg
                    gdb.execute(cmd)

                    if deref:
                        if not is_go_file:  # TODO, is this right?
                            arg = '(long *) ' + arg
                        cmd = 'p/x *(' + arg + ')'
                        gdb.execute(cmd)
                except gdb.MemoryError:
                    print("memory error")
                except Exception as e:
                    if 'Attempt to dereference a generic pointer.' in str(e):
                        gdb.execute('p/x ${}'.format(src_regs[break_num]))
                    else:
                        raise Exception


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
