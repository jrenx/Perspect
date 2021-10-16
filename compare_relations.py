import sys
import os
from relations import *

def parse(f):
    with open(f, 'r') as ff:
        simple_relation_groups = SimpleRelationGroups.fromJSON(json.load(ff))
    #print(simple_relation_groups)
    return simple_relation_groups

def compare_relation_groups(f1, f2):
    rs1 = parse(f1)
    #print(rs1)
    rs2 = parse(f2)
    #print(rs2)
    
    diff = []
    for rg in set(rs1.relations_map.values()):
        file, line, index, total_count = Indices.parse_index_quad(rg.index_quad)
        key = rs2.indices.get_indices2(file, line, total_count, index)
        right = None
        if key is None:
            #print(str(rg.index_quad) + " not found in other set of relations.")
            #continue
            d = rg.group_weight
            key = rg.index_quad
        else:
            #d = abs(rs1[key][0] - rs2[key][0])
            right = rs2.relations_map[key]
            d = abs(rg.group_weight - right.group_weight)
        d = round(d)
        diff.append((d, key, rg, right))
    for rg in set(rs2.relations_map.values()):
        file, line, index, total_count = Indices.parse_index_quad(rg.index_quad)
        key = rs1.indices.get_indices2(file, line, total_count, index)
        if key is None:
            #print(str(rg.index_quad) + " not found in other set of relations.")
            #continue
            d = rg.group_weight
            d = round(d)
            diff.append((d, rg.index_quad, None, rg))
    #print(diff)
    sorted_diff = sorted(diff, key=lambda e: (e[0], e[1]))
    #print(sorted_diff)
    print("========================================")
    for p in sorted_diff:
        print()
        print(p)
        print()
        compare_relations(p[0], p[1], p[2], p[3])
        print()
        print(p)
        print()
        print("========================================")
    return sorted_diff

def compare_relations(parent_d, parent_key, left, right):
    diff = []
    for pair in left.relations:
        r = pair[0]
        prede = pair[1]
        file, line, index, total_count = Indices.parse_index_quad(prede)
        key = right.predes.get_indices2(file, line, total_count, index)
        if key is None:
            if r.weight.perc_contrib < 5:
                continue
            diff.append((r.weight.perc_contrib, r.timestamp, r, None))
            continue
        pair = right.relations_map.get(key) #TODO
        r2 = pair[0]
        if r.relaxed_equals(r2):
            continue
        d = abs(r2.weight.perc_contrib - r.weight.perc_contrib) #TODO diff by contribution
        avg_timestamp = (r2.timestamp + r.timestamp)/2
        #if d < 5:
        #    continue
        diff.append((d, avg_timestamp, r, r2))
    for pair in right.relations:
        r = pair[0]
        prede = pair[1]
        file, line, index, total_count = Indices.parse_index_quad(prede)
        key = left.predes.get_indices2(file, line, total_count, index)
        if key is None:
            #if r.weight.perc_contrib < 5:
            #    continue
            diff.append((r.weight.perc_contrib, r.timestamp, None, r))
    sorted_diff = sorted(diff, key=lambda e: (e[1], e[0]))
    for p in sorted_diff:
        print("-----------------------------------------")
        print(str(p[0]) + " " + str(p[1]))
        print(str(p[2]))
        print(str(p[3]))

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

    compare_relation_groups(f1, f2)
