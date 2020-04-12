import sys

def parse_function_trace(filename):

    traces = []

    with open(filename, 'r') as inputFile:
        trace = []
        for line in inputFile:
            if 'start' in line:
                if len(trace) > 0:
                    traces.append(trace)
                trace = []
            elif 'eof' in line:
                if len(trace) > 0:
                    traces.append(trace)
                break
            elif '0x' in line:
                trace.append(int(line, 16))
            else:
                print("Warning: failed to parse line: " + line)

    return traces

# main for testing
if __name__ == '__main__':
    if len(sys.argv) >= 2:
        filename = sys.argv[1]
    else:
        filename = 'ftrace.out'
    print(len(parse_function_trace(filename)))