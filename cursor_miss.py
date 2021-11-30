import json

import gdb

gdb.execute("br bt_cursor.c:677")
gdb.execute("br bt_cursor.c:693")

valid = 0
invalid = 0

def br_handler(event):
    stack = gdb.execute("i stack")
    if 'doTTLForIndex' not in stack:
        return
    
    br_num = event.breakpoints[-1]
    if br_num == 1:
        global valid
        valid += 1
    elif br_num ==2:
        global invalid
        invalid += 1

gdb.events.stop.connect(br_handler)

not_exit = True

def exit_handler(event):
    global not_exit
    not_exit = False
    
gdb.events.exited.connect(exit_handler)

gdb.execute('run')

while not_exit:
    try:
        gdb.execute('c')
    except Exception:
        break

with open('cursur_miss.txt', 'w') as f:
    f.write(json.dumps({'valid': valid, 'invalid': invalid}, f))

gdb.execute('quit', False, True)