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
        watchpoints = config['watchpoints']

        for wp in watchpoints:
            gdb.execute("watch -l *(long *){}".format(wp))

        for br in breakpoints:
            gdb.execute("br {}".format(br))

        return 1


InitArgument()


class CheckProcessExit(gdb.Function):
    def __init__(self):
        super(CheckProcessExit, self).__init__('is_process_exit')

    def invoke(self):
        with open(os.path.join(rr_dir, 'watchpoints.log'), 'r') as f:
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
        with open(os.path.join(rr_dir, 'watchpoints.log'), 'r') as f:
            f.seek(0, 2)
            position = f.tell()
        gdb.set_convenience_variable('log_position', position)
        return 1


UpdateFilePosition()
