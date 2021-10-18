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
        print(str(p[0]) + " " + str(p[1]) + " " + str(p[2]) + " " + str(p[3]))
        print()
        compare_relations(p[0], p[1], p[2], p[3])
        print()
        print(str(p[0]) + " " + str(p[1]) + " " + str(p[2]) + " " + str(p[3]))
        print()
        print("========================================")
    return sorted_diff

def compare_relations(parent_d, parent_key, left, right):
    if left is None or right is None:
        print("[warn] One relation group is None")
        return
    max_timestamp = 0
    max_weight = 0
    diff = []
    left_over_left = {}
    left_over_right = {}
    for pair in left.relations:
        r = pair[0]
        prede = pair[1]
        file, line, index, total_count = Indices.parse_index_quad(prede)
        key = right.predes.get_indices2(file, line, total_count, index)
        if key is None:
            if r.weight.perc_contrib < 5:
                print("[ra] Contribution is too low, ignore the relations")
                continue
            if r.duplicate is True:
                print("[ra] Relation is too duplicate, ignore...")
                continue
            left_over_left[prede[0] + "_" + str(prede[1])] = (r.weight.perc_contrib, r.timestamp, r, None)
            #diff.append((r.weight.perc_contrib, r.timestamp, r, None))
            continue
        val = right.relations_map.get(key) #TODO
        if isinstance(val, dict):
            our_ratio = (index if index is not None else 0)/ max(total_count, 1)
            min_diff_ratio = 1
            for their_ratio in val:
                ratio_diff = abs(their_ratio-our_ratio)
                if ratio_diff < min_diff_ratio:
                    min_diff_ratio = their_ratio
            if abs(min_diff_ratio-our_ratio) > 0.05:
                left_over_left[prede[0] + "_" + str(prede[1])] = (r.weight.perc_contrib, r.timestamp, r, None)
                # diff.append((r.weight.perc_contrib, r.timestamp, r, None))
                continue

            pair = val[min_diff_ratio]
        else:
            pair = val
        r2 = pair[0]
        if r.relaxed_equals(r2):
            continue
        avg_contrib = (r2.weight.perc_contrib + r.weight.perc_contrib)/2
        if avg_contrib < 5:
            print("[ra] Average contribution is too low, ignore the relations")
            continue
        d = abs(r2.weight.perc_contrib - r.weight.perc_contrib) #TODO diff by contribution
        avg_timestamp = (r2.timestamp + r.timestamp)/2
        #if d < 5:
        #    continue
        diff.append((d, avg_timestamp, r, r2))
        max_timestamp = max(max_timestamp, avg_timestamp)
        max_weight = max(max_weight, d)
    for pair in right.relations:
        r = pair[0]
        prede = pair[1]
        file, line, index, total_count = Indices.parse_index_quad(prede)
        key = left.predes.get_indices2(file, line, total_count, index)
        if key is None:
            if r.weight.perc_contrib < 5:
                print("[ra] Contribution is too low, ignore the relations")
                continue
            if r.duplicate is True:
                print("[ra] Relation is too duplicate, ignore...")
                continue
            left_over_right[prede[0] + "_" + str(prede[1])] = (r.weight.perc_contrib, r.timestamp, None, r)
            #diff.append((r.weight.perc_contrib, r.timestamp, None, r))
    for key_short in left_over_left:
        triple_left = left_over_left[key_short]
        r = triple_left[2]
        if key_short in left_over_right:
            triple_right = left_over_right[key_short]
            r_right = triple_right[3]
            if r.relaxed_equals(r_right):
                del left_over_right[key_short]
                continue
        diff.append((r.weight.perc_contrib, r.timestamp, r, None))
        max_timestamp = max(max_timestamp, r.timestamp)
        max_weight = max(max_weight, r.weight.perc_contrib)
    for triple in left_over_right.values():
        r = triple[3]
        diff.append((r.weight.perc_contrib, r.timestamp, None, r))
        max_timestamp = max(max_timestamp, r.timestamp)
        max_weight = max(max_weight, r.weight.perc_contrib)

    max_timestamp = max(max_timestamp, 1)
    max_weight = max(max_weight, 1)

    weighted_diff = []
    for quad in diff:
        weight = quad[0]
        avg_timestamp = quad[1]
        r_left = quad[2]
        r_right = quad[3]
        weighted_diff.append((weight/max_weight*100, avg_timestamp/max_timestamp*100, weight, avg_timestamp, r_left, r_right))

    sorted_diff = sorted(weighted_diff, key=lambda e: (e[1], e[0]))
    for p in sorted_diff:
        print("-----------------------------------------")
        print(str(p[0]) + " " + str(p[1]))
        print(str(p[2]) + " " + str(p[3]))
        print(str(p[4]))
        print(str(p[5]))

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
