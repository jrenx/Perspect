import gdb
import json
import re


def set_argument():
    with open('config.json') as configFile:
        config = json.load(configFile)

    filename = config['file']
    line_num = config['line']
    reg = config['reg']

    gdb.set_convenience_variable('filename', filename)
    gdb.set_convenience_variable('line_num', line_num)
    gdb.set_convenience_variable('reg', reg)

    if 'out' in config:
        output_filename = config['out']
    else:
        output_filename = 'out.log'

    output_file = open(output_filename, 'w')

def process_exit(outs):
    for line in outs:
        if re.search(r'Inferior \d+ \(process \d+\) exited', line):
            gdb.set_convenience_variable('RET', 1)
            return
    gdb.set_convenience_variable('RET', 0)


def br_success(outs):
    for line in outs:
        if re.search(r'Make breakpoint pending on future shared library load', line):
            gdb.set_convenience_variable('RET', 0)
            return
    gdb.set_convenience_variable('RET', 1)


def get_reg_value(outs):
    reg = gdb.convenience_variable('reg')
    for line in outs:
        words = line.split()
        if len(words) >= 2 and words[0] == reg:
            gdb.set_convenience_variable('reg_value', words[1])
            gdb.set_convenience_variable('RET', 1)
            return
    gdb.set_convenience_variable('RET', 0)
