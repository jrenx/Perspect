import sys
import os
from relations import *

def parse(f):
    with open(f, 'r') as ff:
        simple_relation_groups = SimpleRelationGroups.fromJSON(json.load(ff))
    print(simple_relation_groups)
    return simple_relation_groups

def compare(f1, f2):
    rs1 = parse(f1)
    print(rs1)
    rs2 = parse(f2)
    print(rs2)
    
    diff = []
    for rg in set(rs1.relations_map.values()):
        file, line, index, total_count = Indices.parse_index_quad(rg.index_quad)
        key = rs2.indices.get_indices2(file, line, total_count, index)
        unique = False
        if key is None:
            print(str(rg.index_quad) + " not found in other set of relations.")
            #continue
            d = rg.group_weight
            unique = True
            key = rg.index_quad
        else:
            #d = abs(rs1[key][0] - rs2[key][0])
            d = abs(rg.group_weight - rs2.relations_map[key].group_weight)
        d = round(d)
        diff.append((d, key, unique, "left"))
    for rg in set(rs2.relations_map.values()):
        file, line, index, total_count = Indices.parse_index_quad(rg.index_quad)
        key = rs1.indices.get_indices2(file, line, total_count, index)
        if key is None:
            print(str(rg.index_quad) + " not found in other set of relations.")
            #continue
            d = rg.group_weight
            d = round(d)
            diff.append((d, rg.index_quad, True, "right"))
    print(diff)
    sorted_diff = sorted(diff, key=lambda pair: (pair[0], pair[1]))
    print(sorted_diff)
    for p in sorted_diff:
        print(p)
    return sorted_diff

if __name__ == "__main__":
    #f1 = sys.argv[1]
    #f2 = sys.argv[2]
    dir1 = "/home/anygroup/perf_debug_tool_dev_jenny"
    dir2 = "/home/anygroup/eval_909_32bit"

    cache_dir1 = "cache/909_ziptest_exe9"
    cache_dir2 = "cache/909_ziptest_exe9_32"

    file1 = "rgroups_simple_rdi_0x409daa_rbx_0x407240_rdx_0x40742b_rcx_0x40764c.json"
    file2 = "rgroups_simple_esi_0x8050c16_ebx_0x804e41c_eax_0x804e5fb_eax_0x804e804.json"

    d1 = os.path.join(dir1, cache_dir1)
    d2 = os.path.join(dir2, cache_dir2)

    f1 = os.path.join(dir1, cache_dir1, file1)
    f2 = os.path.join(dir2, cache_dir2, file2)

    #cmd = "cp " + f1 + " " + d2
    #print(cmd)
    #os.system(cmd)
    #cmd = "cp " + f2 + " " + d1
    #print(cmd)
    #os.system(cmd)

    sd_old = None
    for i in range(100):
        print("Iteration: " + str(i))
        os.chdir(dir1)
        cmd = "python3 relation_analysis.py  > rel_" + str(i)+ " 2>&1"
        print(cmd)
        os.system(cmd)
        os.chdir(dir2)
        cmd = "python3 relation_analysis.py  > rel_" + str(i)+ " 2>&1"
        print(cmd)
        os.system(cmd)
        sd = compare(f1, f2)
        if sd_old is not None and sd_old == sd:
            break
        sd_old = sd
        cmd = "cp " + f1 + " " + d2
        print(cmd)
        os.system(cmd)
        cmd = "cp " + f2 + " " + d1
        print(cmd)
        os.system(cmd)
