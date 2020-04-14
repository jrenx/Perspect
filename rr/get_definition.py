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
    # /dev/shm - save file in RAM
    ltxname = "/dev/shm/c.log"

    gdb.execute("set logging file " + ltxname)  # lpfname
    gdb.execute("set logging redirect on")
    gdb.execute("set logging overwrite on")
    gdb.execute("set logging on")
    gdb.execute(cmd)
    gdb.execute("set logging off")

    replyContents = open(ltxname, 'r').read()  # read entire file
    return replyContents.split(os.linesep)


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

    output_file.write("{} value: {}".format(reg, reg_value))

    run('disable br 1')
    run('watch -l *(int *){}'.format(reg_value))

    # while True:
    #     try:
    #         outs = run('reverse-cont')
    #     except gdb.error:
    #         break
    #     print('\n\nreverse-cont output: ')
    #     for line in outs:
    #         print(line)
    #     print('\n\n')

    run('delete br {}'.format(str(continue_count + 1)))
