import sys
import json
import os
CUT_OFF = 3
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
    print("ordered trace:")
    for ot in ordered_trace:
        print(ot)
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
    print("Got highly ranked events")
    print("=============")
    # if is not highly ranked and exist in both repros, delete
    common = set()
    for f in trace1:
        if f in trace2:
            common.add(f)
    for f in common:
        if f in highly_ranked:
            continue
        del trace1[f]
        del trace2[f]
    print("Number events kept from first trace: " + str(len(trace1)))
    print("Number events kept from first trace: " + str(len(trace2)))
    print("=============")
    # remove starting events regardless of its uniqueness if it contributes to less than 0.1
    sorted_trace1 = []
    remove_set1 = set()
    for f in trace1:
        #More aggressive event trimming - begin
        if f in trace2:
            if round((trace1[f] + trace2[f])/2) <= CUT_OFF:
                remove_set1.add(f)
        elif round(trace1[f]) <= CUT_OFF:
            remove_set1.add(f)
        #More aggressive event trimming - end

        if f in highly_ranked:
            continue
        if round(trace1[f]) <= CUT_OFF:
            remove_set1.add(f)

    sorted_trace2 = []
    remove_set2 = set()
    for f in trace2:
        #More aggressive event trimming - begin
        if f in trace1:
            if round((trace1[f] + trace2[f])/2) <= CUT_OFF:
                remove_set2.add(f)
        elif round(trace2[f]) <= CUT_OFF:
            remove_set2.add(f)
        #More aggressive event trimming - end

        if f in highly_ranked:
            continue
        if round(trace2[f]) <= CUT_OFF:
            remove_set2.add(f)


    for f in remove_set1:
        del trace1[f]
    for f in trace1:
        sorted_trace1.append([f, trace1[f]])

    for f in remove_set2:
        del trace2[f]
    for f in trace2:
        sorted_trace2.append([f, trace2[f]])

    print("Number events kept from first trace: " + str(len(trace1)))
    print("Number events kept from first trace: " + str(len(trace2)))
    print("=============")

    trace1 = {}
    names1 = {}
    weights1 = {}
    sorted_trace1 = sorted(sorted_trace1, key=lambda pair: pair[1])
    #print(sorted_trace1)
    for i in range(0, 20):
        if len(sorted_trace1) == 0:
            break
        pair = sorted_trace1.pop()
        trace1[pair[0]] = pair[1]
        fname = '<' + pair[0] + '>:'
        names1[fname] = pair[0]
        weights1[fname] = pair[1]

    trace2 = {}
    names2 = {}
    weights2 = {}
    sorted_trace2 = sorted(sorted_trace2, key=lambda pair: pair[1])
    for i in range(0, 20):
        if len(sorted_trace2) == 0:
            break
        pair = sorted_trace2.pop()
        trace2[pair[0]] = pair[1]
        fname = '<' + pair[0] + '>:'
        names2[fname] = pair[0]
        weights2[fname] = pair[1]

    print("Number events kept from first trace: " + str(len(trace1)))
    print("Number events kept from first trace: " + str(len(trace2)))
    print("=============")

    print("Events kept from first trace: " + str(trace1))
    print("Events kept from first trace: " + str(trace2))
    print("=============")

    
    all_output = {}
    binary1 = sys.argv[5]
    output1 = {}
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
                    result = hex(addr) + " " + names1[f] + " " + str(weights1[f]*w1)
                    #result = hex(addr) + " " + names1[f] + " " + str(weights1[f]*time1/100) + " " + str(weights1[f])
                    print(result)
                    output1[str(addr) + "_" + f] = result
                    if f in all_output:
                        all_output[str(addr) + "_" + f] += weights1[f]*w1
                    else:
                        all_output[str(addr) + "_" + f] = weights1[f]*w1


    print()
    binary2 = sys.argv[6]
    output2 = {}
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
                    result = hex(addr) + " " + names2[f] + " " + str(weights2[f]*w2)
                    #result = hex(addr) + " " + names2[f] + " " + str(weights2[f]*time2/100) + " " + str(weights2[f])
                    print(result)
                    output2[str(addr) + "_" + f] = result
                    if f in all_output:
                        all_output[str(addr) + "_" + f] += weights2[f]*w2
                    else:
                        all_output[str(addr) + "_" + f] = weights2[f]*w2

    all_output_l = []
    for addr_func_pair in all_output:
        all_output_l.append([addr_func_pair, all_output[addr_func_pair]])
    sorted_all_output = reversed(sorted(all_output_l, key=lambda pair:pair[1]))
    with open("starting_events_good_run", "w") as f:
        for (addr_func_pair, weight) in sorted_all_output:
            if addr_func_pair in output1:
                f.write("_ " + output1[addr_func_pair]+"\n")

    sorted_all_output = reversed(sorted(all_output_l, key=lambda pair:pair[1]))
    with open("starting_events_bad_run", "w") as f:
        for (addr_func_pair, weight) in sorted_all_output:
            if addr_func_pair in output2:
                f.write("_ " + output2[addr_func_pair]+"\n")

if __name__ == "__main__":
    print("Usage: perf report (no call graph) of the fast run, duration of the fast run, perf report (no call graph) of the slow run, duration of the slow run, binary of the fast run, binry of the slow run.")
    run()
