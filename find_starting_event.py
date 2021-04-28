import sys
import json
import os

def parse(lines, trace):
    ordered_trace = []
    for l in lines:
        if l.startswith("#"):
            continue
        if "continuing without symbols" in l:
            continue
        segs = l.split()
        if len(segs) == 0:
            continue
        obj = segs[2]
        if obj == "[unknown]":
            continue
        #print(l)
        perc = float(segs[0].strip("%"))
        #if perc == 0.0:
        #    continue
        func = segs[-1].strip()
        trace[func] = perc
        ordered_trace.append([func,perc])
    ordered_trace = ordered_trace[::-1]
    return ordered_trace

def get_highly_ranked(t, s, w):
    count = 0
    contrib = 0.0
    #print(len(t))
    while len(t) > 0:
        e = t.pop()
        f = e[0]
        p = e[1]
        #print(f + " " + str(p))
        if p*w <= 1:
            break
        count += 1
        contrib += p
        s.add(f)
        if count >= 15:
            break
        if contrib >= 99:
            break


def run():
    file1 = sys.argv[1]
    time1 = float(sys.argv[2])

    file2 = sys.argv[3]
    time2 = float(sys.argv[4])

    w1 = time1/(time1 + time2)
    w2 = time2/(time1 + time2)

    trace1 = {}
    with open(file1, 'r') as f1:
        lines = f1.readlines()
        ordered_trace1 = parse(lines, trace1)
    print(len(trace1))

    trace2 = {}
    with open(file2, 'r') as f2:
        lines = f2.readlines()
        ordered_trace2 = parse(lines, trace2)
    print(len(trace2))
    print("=============")

    highly_ranked = set() 
    get_highly_ranked(ordered_trace1, highly_ranked, w1)
    get_highly_ranked(ordered_trace2, highly_ranked, w2)
    print(highly_ranked)
    print("=============")

    common = set()
    for f in trace1:
        if f in trace2:
            common.add(f)
    for f in common:
        if f in highly_ranked:
            continue
        del trace1[f]
        del trace2[f]
    print(len(trace1))
    print(len(trace2))
    print("=============")

    sorted_trace1 = []
    remove_set = set()
    for f in trace1:
        if f in highly_ranked:
            continue
        if trace1[f] < 0.1:
            remove_set.add(f)
    for f in remove_set:
        del trace1[f]
    for f in trace1:
        sorted_trace1.append([f, trace1[f]])

    sorted_trace2 = []
    remove_set = set()
    for f in trace2:
        if f in highly_ranked:
            continue
        if trace2[f] < 0.1:
            remove_set.add(f)
    for f in remove_set:
        del trace2[f]
    for f in trace2:
        sorted_trace2.append([f, trace2[f]])

    print(len(trace1))
    print(len(trace2))
    print("=============")

    trace1 = {}
    names1 = {}
    sorted_trace1 = sorted(sorted_trace1, key=lambda pair: pair[1])
    #print(sorted_trace1)
    for i in range(0, 20):
        if len(sorted_trace1) == 0:
            break
        pair = sorted_trace1.pop()
        trace1[pair[0]] = pair[1]
        fname = '<' + pair[0] + '>:'
        names1[fname] = pair[0]

    trace2 = {}
    names2 = {}
    sorted_trace2 = sorted(sorted_trace2, key=lambda pair: pair[1])
    for i in range(0, 20):
        if len(sorted_trace2) == 0:
            break
        pair = sorted_trace2.pop()
        trace2[pair[0]] = pair[1]
        fname = '<' + pair[0] + '>:'
        names2[fname] = pair[0]

    print(len(trace1))
    print(len(trace2))
    print("=============")

    print(trace1)
    print(trace2)
    print("=============")


    binary1 = sys.argv[5]
    output1 = []
    with open(binary1, 'r') as f1:
        lines = f1.readlines()
        for l in lines:
            segs = l.split()
            if len(segs) != 2:
                continue
            for f in names1:
                if f == segs[1]:
                    #print(l)
                    addr = int(segs[0], 16)
                    result = hex(addr) + " " + names1[f]
                    print(result)
                    output1.append(result)

    with open("starting_events_good_run", "w") as f:
        for l in output1:
            f.write(l+"\n")

    print()
    binary2 = sys.argv[6]
    output2 = []
    with open(binary2, 'r') as f2:
        lines = f2.readlines()
        for l in lines:
            segs = l.split()
            if len(segs) != 2:
                continue
            for f in names2:
                if f == segs[1]:
                    #print(l)
                    addr = int(segs[0], 16)
                    result = hex(addr) + " " + names2[f]
                    print(result)
                    output2.append(result)

    with open("starting_events_bad_run", "w") as f:
        for l in output2:
            f.write(l+"\n")


if __name__ == "__main__":
    run()
