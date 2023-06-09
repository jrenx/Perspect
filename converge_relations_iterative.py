import sys
import os
from relations import *
from util import *
import socket
import time
curr_dir = os.path.dirname(os.path.realpath(__file__))

def parse(f):
    with open(f, 'r') as ff:
        simple_relation_groups = SimpleRelationGroups.fromJSON(json.load(ff))
    #print(simple_relation_groups)
    return simple_relation_groups

def compare(f1, f2):
    rs1 = parse(f1)
    #print(rs1)
    rs2 = parse(f2)
    #print(rs2)
    
    diff = []
    for rg in set(rs1.relations_map.values()):
        file, line, index, total_count = Indices.parse_index_quad(rg.index_quad)
        key = rs2.indices.get_indices2(file, line, total_count, index)
        unique = False
        if key is None:
            #print(str(rg.index_quad) + " not found in other set of relations.")
            #continue
            d = rg.group_weight
            unique = True
            key = Indices.build_key_from_index_quad(rg.index_quad)
        else:
            #d = abs(rs1[key][0] - rs2[key][0])
            d = abs(rg.group_weight - rs2.relations_map[key].group_weight)
        d = round(d)
        diff.append((d, key, unique, "left"))
    for rg in set(rs2.relations_map.values()):
        file, line, index, total_count = Indices.parse_index_quad(rg.index_quad)
        key = rs1.indices.get_indices2(file, line, total_count, index)
        if key is None:
            #print(str(rg.index_quad) + " not found in other set of relations.")
            #continue
            d = rg.group_weight
            d = round(d)
            diff.append((d, Indices.build_key_from_index_quad(rg.index_quad), True, "right"))
    #print(diff)
    sorted_diff = sorted(diff, key=lambda pair: (pair[0], pair[1]))
    #print(sorted_diff)
    for p in sorted_diff:
        print(p)
    return sorted_diff

if __name__ == "__main__":
    #f1 = sys.argv[1]
    #f2 = sys.argv[2]
    a = time.time()
    limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()
    other_ip, other_dir, other_program, other_relations_file, _ = parse_relation_analysis_inputs()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    my_ip = s.getsockname()[0]
    s.close()
    
    server1 = my_ip
    server2 = other_ip

    dir1 = curr_dir
    dir2 = other_dir

    cache_dir1 = os.path.join(curr_dir, "cache", program)
    cache_dir2 = os.path.join(curr_dir, "cache", other_program)

    file1 = "rgroups_simple_" + build_key(starting_events) + ".json"
    file11 = "rgroups.json"
    file2 = other_relations_file

    d1 = os.path.join(dir1, cache_dir1)
    d2 = os.path.join(dir2, cache_dir2)

    f1 = os.path.join(dir1, cache_dir1, file1)
    f2 = os.path.join(dir2, cache_dir2, file2)

    f11 = os.path.join(dir1, cache_dir1, file11)
    f12 = os.path.join(dir1, cache_dir1, file2)
    f21 = os.path.join(dir2, cache_dir2, file1)
    """
    cmd = "rm " + os.path.join(dir1, cache_dir1, file1)
    print(cmd)
    os.system(cmd)

    cmd = "rm " + os.path.join(dir1, cache_dir1, file2)
    print(cmd)
    os.system(cmd)

    cmd = "rm " + os.path.join(dir2, cache_dir2, file2)
    print(cmd)
    os.system(cmd)

    cmd = "rm " + os.path.join(dir2, cache_dir2, file1)
    print(cmd)
    os.system(cmd)
    """

    sd_old = None
    for i in range(100):
        print("Iteration: " + str(i))

        # Run the local one
        #os.chdir(dir1)
        #cmd = "python3.7 serial_relation_analysis.py  > rel_" + str(i)+ " 2>&1"
        cmd = "./ra.sh 60 " + str(i) + " " + f12 + " " + d1 + " &"
        print(cmd, flush=True)
        os.system(cmd)

        if i>10 and i%2 == 0:
            #cmd = "cp " + f1 + " " + d2
            time.sleep(10)
            while not os.path.exists(f1):
                time.sleep(10)
                continue
            cmd = "scp " + f1 + " " + server2 + ":" + d2
            print(cmd, flush=True)
            os.system(cmd)

            continue

        # Run the remote one
        #os.chdir(dir2)
        #cmd = "python3.7 serial_relation_analysis.py  > rel_" + str(i)+ " 2>&1"
        cmd = "./ra.sh 60 " + str(i) + " " + f21 + " " + d2
        cmd = "ssh " + server2 + ' "' + "cd " + dir2 + "; " + cmd + '"'
        print(cmd, flush=True)
        os.system(cmd)

        time.sleep(10)
        while not os.path.exists(f11):
            time.sleep(10)
            continue
        #cmd = "cp " + f1 + " " + d2
        cmd = "scp " + f1 + " " + server2 + ":" + d2
        print(cmd, flush=True)
        os.system(cmd)

        #cmd = "cp " + f2 + " " + d1
        cmd = "scp " + server2 + ":" + f2 + " " + d1
        print(cmd)
        os.system(cmd)

        #if i == 0:
        #    cmd = "./merge_dynamic_graphs.sh " + str(d1)
        #    print(cmd, flush=True)
        #    os.system(cmd)

        #    cmd = "./merge_dynamic_graphs.sh " + str(d2)
        #    cmd = "ssh " + server2 + ' "' + "cd " + dir2 + "; " + cmd + '"'
        #    print(cmd, flush=True)
        #    os.system(cmd)

          
        print("===========================================================")
        sd = compare(f1, f12)
        if sd_old is not None and sd_old == sd:
            break
        sd_old = sd

        print("", flush=True)
    b = time.time()
    print("Finished converging, took: " + str(b-a))
