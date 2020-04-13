import gdb
import json
import re

with open('config.json') as configFile:
    config = json.load(configFile)

filename = config['file']
line = config['line']
reg = config['reg']
if 'out' in config:
    output_filename = config['out']
else:
    output_filename = 'out.log'

def run(cmd):
    return gdb.execute(cmd, to_string=True)

def br_success(outs):
    for line in outs:
        if re.search(r'Make breakpoint pending on future shared library load', line):
            return False
    return True

outs = run('br {}:{}'.format(filename, line))
if not br_success(outs):
    print('Setting breakpoints failed')
    exit(1)
