import json
import subprocess
import os
import re
import random


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
                        not_taken.append(count + 1)
                    last_break_num = 1
                    count += 1
                elif break_num == 2:
                    taken.append(count + 1)
                    last_break_num = 2

    return taken, not_taken


def run_back_trace(breakpoint, continue_count, trace_point, reg):
    config = {"breakpoint": breakpoint, "continue_count": continue_count, "trace_point": trace_point, "reg": reg,
              "log_filename": "backtrace_{}.log".format(continue_count)}
    json.dump(config, open('config.json', 'w'))
    rr_process = subprocess.Popen('sudo rr replay', stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    try:
        rr_process.communicate('source get_backtrace'.encode(), 60 * 10)
    except subprocess.TimeoutExpired:
        rr_process.kill()
        return False
    return True


def parse_back_trace(log_filename):
    traces = []
    with open(log_filename) as log:
        for line in log:
            if re.search(r'.+ \(.*\) at .*:\d+', line):
                line = line.strip()
                traces.append(line[line.rindex('/') + 1:])
    return traces


def analyze_trace(taken_traces, not_taken_traces):
    positive = set()
    negative = set()

    potential_set = set(taken_traces[0])
    for i in range(1, len(taken_traces)):
        potential_set.intersection_update(set(taken_traces[i]))

    for func in taken_traces[0]:
        if func in potential_set:
            positive.update({func})
            break

    return positive, negative


def get_sat_def(target, branch, trace_point, reg):
    run_break_points([branch, target])
    taken, not_taken = parse_break_points()

    # TODO: better sampling method
    taken_sample = random.sample(taken, 10)
    not_taken_sample = random.sample(not_taken, 10)

    taken_traces = []
    not_taken_traces = []
    for count in taken_sample:
        run_back_trace(branch, count, trace_point, reg)
        taken_traces.append(parse_back_trace('backtrace_{}.log'.format(count)))
    for count in not_taken_sample:
        run_back_trace(branch, count, trace_point, reg)
        not_taken_traces.append(parse_back_trace('backtrace_{}.log'.format(count)))

    return analyze_trace(taken_traces, not_taken_traces)


if __name__ == '__main__':
    # test break points
    # run_break_points(['mgc0.c:144', 'mgc0.c:150'])
    # taken, not_taken = parse_break_points()
    # print(str(len(taken)), "taken:", taken[:5])
    # print(str(len(not_taken)), "not taken:", not_taken[:5])

    # test back trace
    # run_back_trace("mgc0.c:467", 100, "0x409c0c", "rbp")
    # print(parse_back_trace("backtrace_{}.log".format(100)))

    # test sat_def
    print(get_sat_def('mgc0.c:486', 'mgc0.c:468', '0x409c1f', 'rbx'))
