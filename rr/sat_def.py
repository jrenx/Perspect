import json
import subprocess
import os
import re


def run_break_points(breakpoints):
    json.dump({"breakpoints": breakpoints}, open('config.json', 'w'))
    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        rr_process.communicate('source get_breakpoints'.encode(), 60 * 10)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        return False
    return True


def parse_break_points():
    count = 0
    last_break_num = 0
    taken = []
    not_taken = []
    with open("breakpoints.log") as log:
        for line in log:
            if re.search(r'Breakpoint \d+,', line):
                words = line.split()
                break_num = int(words[1].strip(','))
                if break_num == 1:
                    if last_break_num == 1:
                        not_taken.append(count)
                    last_break_num = 1
                    count += 1
                elif break_num == 2:
                    taken.append(count)
                    last_break_num = 2

    return taken, not_taken


if __name__ == '__main__':
    run_break_points(['mgc0.c:144', 'mgc0.c:150'])
    taken, not_taken = parse_break_points()
    print(str(len(taken)), "taken:", taken[:5])
    print(str(len(not_taken)), "not taken:", not_taken[:5])
