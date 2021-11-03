def parse_inputs():
    limit = None
    program = None
    program_args = None
    program_path = None
    starting_event_file = None
    with open("analysis.config", "r") as f:
        for l in f.readlines():
            segs = l.split("=")
            if segs[0] == "limit":
                limit = int(segs[1].strip())
            elif segs[0] == "program":
                program = segs[1].strip()
            elif segs[0] == "program_args":
                program_args = segs[1].strip()
            elif segs[0] == "program_path":
                program_path = segs[1].strip()
            elif segs[0] == "starting_event_file":
                starting_event_file = segs[1].strip()
    print("Limit is: " + str(limit))
    print("Program is: " + str(program))
    print("Program args are: " + str(program_args))
    print("Program path is: " + str(program_path))
    print("Starting event file is: " + str(starting_event_file))

    starting_events = []
    starting_insn_to_weight = {}
    if starting_event_file is not None:
        with open(starting_event_file, "r") as f:
            for l in f.readlines():
                segs = l.split()
                reg = "" if segs[0] == "_" else regs[0]
                insn = int(segs[1], 16)
                starting_events.append([reg, insn, segs[2]])
                if len(segs) >= 4:
                    starting_insn_to_weight[insn] = float(segs[3])
    print("Starting events are: " + str(starting_events))
    print("Starting events weights are: " + str(starting_insn_to_weight))
    return  limit, program, program_args, program_path, starting_events, starting_insn_to_weight

if __name__ == '__main__':
    parse_inputs()
