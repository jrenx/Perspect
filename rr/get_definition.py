import gdb
import json
import re
import os

with open('config.json') as configFile:
    config = json.load(configFile)

filename = config['file']
line_num = config['line']
reg = config['reg']
if 'out' in config:
    output_filename = config['out']
else:
    output_filename = 'out.log'

output_file = open(output_filename, 'w')


def run(cmd):
    return gdb.execute(cmd, to_string=True).split(os.linesep)


def br_success(outs):
    for line in outs:
        if re.search(r'Make breakpoint pending on future shared library load', line):
            return False
    return True


def get_reg_value(outs):
    for line in outs:
        words = line.split()
        if len(words) >= 2 and words[0] == reg:
            return words[1]
    return ''


def clean_up():
    output_file.close()


outs = run('br {}:{}'.format(filename, str(line_num)))
if not br_success(outs):
    print('Setting breakpoints failed')
    exit(1)

run('r')

continue_count = 0
while True:
    continue_count += 1
    try:
        run('c {}'.format(str(continue_count)))
        outs = run('i reg {}'.format(reg))
    except gdb.error:
        clean_up()
        exit()
    reg_value = get_reg_value(outs)
    if reg_value == '':
        clean_up()
        exit()
    run('disable br 1')
    run('watch -l *(int *){}'.format(reg_value))

    while True:
        outs = run('reverse-cont')
        print('\n\nreverse-cont: ' + outs)
        print('\n\n')

    run('delete br {}'.format(str(continue_count + 1)))
