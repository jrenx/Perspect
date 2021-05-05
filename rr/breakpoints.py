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
            gdb.execute("commands\nc\nend")

        return 1


InitArgument()


class RunBreakCommands(gdb.Function):
    def __init__(self):
        super(RunBreakCommands, self).__init__('run_break_commands')

    def invoke(self):
        inside_loop = False
        with open(os.path.join(rr_dir, 'config.json')) as configFile:
            config = json.load(configFile)

        while True:
            with open(os.path.join(rr_dir, 'breakpoints.log'), 'r') as f:
                position = gdb.convenience_variable('log_position')
                if position is not None:
                    position = int(position)
                    f.seek(position)
                outs = f.readlines()

            found_break_num = False
            for line in reversed(outs):
                match = re.match(r'Breakpoint (\d+),', line)
                if not match:
                    continue
                break_num = int(match.group(0).split()[1][:-1]) - 1
                is_go_file = line.split()[-1].split(':')[0].endswith('.go')
                found_break_num = True
                break

            if not found_break_num:
                return 0

            if break_num >= len(config['regs']):
                return 0

            reg = config['regs'][break_num]
            shift = config['shifts'][break_num]
            off_reg = config['off_regs'][break_num]
            src_reg = config['src_regs'][break_num]
            offset = config['offsets'][break_num]
            is_loop_insn = int(config['loop_insn_flags'][break_num])

            cmd1 = None
            cmd2 = None
            arg = ''
            if reg != '':
                arg += '${}'.format(reg)
            if shift != '0x0':
                if arg != '':
                    arg += '<<{}'.format(shift)  # TODO test this
            if off_reg != '':
                if arg != '':
                    arg += '+'
                arg += '${}*{}'.format(off_reg, offset)
            elif offset != '0x0':
                if arg != '':
                    arg += '+'
                arg += '{}'.format(offset)
            arg = '(' + arg + ')'

            if config['step'] and not inside_loop:
                gdb.execute('si')

            for i in range(2):
                try:
                    cmd = 'p/x ' + arg
                    cmd1 = cmd
                    gdb.execute(cmd)
                    break
                except Exception as e: #TODO is there a more specific error?
                    cmd1 = None
                    if 'Argument to arithmetic operation not a number or boolean.' in str(e):
                        if reg != '':
                            gdb.execute('i reg ${}'.format(reg))
                        if off_reg != '':
                            gdb.execute('i reg ${}'.format(off_reg))
                        with open(os.path.join(rr_dir, 'breakpoints.log'), 'r') as f:
                            position = gdb.convenience_variable('log_position')
                            if position is not None:
                                position = int(position)
                                f.seek(position)
                            outs = f.readlines()
                        reg_value = 0
                        off_reg_value = 1
                        for line in outs:
                            if reg != '' and line.startswith(reg):
                                reg_value = int(line.split(1), 16)
                            if off_reg != '' and line.startswith(off_reg):
                                off_reg_value = int(line.split(1), 16)
                        addr = hex(reg_value + off_reg_value * int(offset, 16))
                        print('[debug] computed addr is: ' + addr)
                        arg = addr
                    else:
                        print('[debug] GDB command caused error: ' + cmd)
                        raise e

            if config['deref']:
                if not is_go_file:  # TODO, is this right?
                    cmd = 'p/x *((long *) ' + arg + ')'
                else: # long type does not exist for go
                    if '(' in src_reg or ',' in src_reg or '%' in src_reg:  # FIXME: use regex to test for non alphebet and non number
                        cmd = 'p/x *(' + arg + ')'
                    elif src_reg != '':
                        cmd = 'p/x ${}'.format(src_reg)  # TODO: sometimes the src is not a simple reg either
                    else:
                        print("SPECIAL")
                        cmd = 'x/32b ' + arg
                for i in range(3):
                    try:
                        cmd2 = cmd
                        gdb.execute(cmd)
                        break
                    except gdb.MemoryError as me:
                        cmd2 = None
                        print('[debug] memory error: ' + str(me) + ' caused by cmd: ' + cmd)
                        cmd = 'p/x *(' + arg + ')'
                    except Exception as e: #TODO is there a more specific error?
                        cmd2 = None
                        #if 'Attempt to dereference a generic pointer.' in str(e):
                        #    if '(' in src_reg or ',' in src_reg or '%' in src_reg: #FIXME: use regex to test for non alphebet and non number
                        #        print('[debug] Source register format is not accepted: ' + src_reg)
                        #        raise e
                        #    cmd = 'p/x ${}'.format(src_reg) #TODO: sometimes the src is not a simple reg either
                        #else:
                        print("[debug] GDB command caused error: " + cmd)
                        raise e
            if is_loop_insn != 1:
                #if not config['deref']:
                #    if cmd1 is not None and ((config['deref'] and cmd is not None) or not config['deref']):
                #        cmds = 'commands ' + str(break_num + 1)
                #        gdb.execute(cmds + "\n \n end")
                #        if config['step']:
                #            cmds = cmds + "\nsi"
                #        cmds = cmds + "\n" + cmd1
                #        if cmd2 is not None:
                #            cmds = cmds + "\n" + cmd2
                #        cmds = cmds + "\ncontinue\nend"
                #        print(cmds)
                #        gdb.execute(cmds)
                break
            else:
                print("[debug] Is a loop instruction, re-running.")
                with open(os.path.join(rr_dir, 'breakpoints.log'), 'r') as f:
                    f.seek(0, 2)
                    position = f.tell()
                gdb.set_convenience_variable('log_position', position)
                gdb.execute('si')
                inside_loop = True
        return 1


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
