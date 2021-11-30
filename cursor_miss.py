import json

import gdb

gdb.execute("br bt_cursor.c:677")
gdb.execute("br bt_cursor.c:693")

valid = 0
invalid = 0

def checkCallStack(frame):
    while frame is not None and frame.is_valid():
        try:
            name = frame.name()
            if name != None and 'doTTLForIndex' in name:
                return True
        except Exception:
            pass
        frame = frame.older()
    return False

def br_handler(event):
    frame = gdb.newest_frame()
    if not checkCallStack(frame):
        return
    
    br_num = int(event.breakpoints[-1].number)
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

gdb.execute('set pagination off')
gdb.execute('run')

while not_exit:
    try:
        gdb.execute('c')
    except Exception:
        break

with open('cursor_miss.txt', 'w') as f:
    f.write(json.dumps({'valid': valid, 'invalid': invalid}, f))

gdb.execute('quit', False, True)
