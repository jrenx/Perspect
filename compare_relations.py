import sys
import os
from relations import *
from util import *
curr_dir = os.path.dirname(os.path.realpath(__file__))

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

def sort_relations_complex(diff, max_weight, max_timestamp):
    # assume left is slow, right is fast
    #
    # forward if increased, calculate the increased difference,
    # times the difference with the total wieght of the slow run to get the impact
    # ignore when forward decreased
    #
    # for backward, for now do not consider the magnitued and
    # only consider if the % contrib of the relation decreased
    # (if consider magnitude: backward if decreased, include all those that do not have the same backward count,
    # or those that dont have the backward event at all
    # ignore when backward is increased, should not be a negative event then)
    #
    # then take the union(max for now) of the two
    # then put into 10 buckets, and sort within each
    weighted_diff = []
    for quad in diff:
        weight = quad[0]
        avg_timestamp = quad[1]

        r_left = quad[2]
        r_right = quad[3]

        corr = 0

        if r_left is not None and r_right is not None:
            forward_impact = r_left.forward.difference(r_right.forward)
            if forward_impact > 0:
                forward_impact = forward_impact/r_left.forward.magnitude() * r_left.weight.perc_contrib
            else:
                forward_impact = 0

            backward_impact = r_left.weight.perc_contrib - r_right.weight.perc_contrib
            if backward_impact < 0:
                backward_impact = abs(backward_impact)
            else:
                backward_impact = 0
            impact = max(forward_impact, backward_impact)
            corr = (r_left.forward.corr() + r_right.forward.corr())/2
        else:
            impact = weight / max_weight * 100
            corr = r_left.forward.corr() if r_left is not None else r_right.forward.corr()

        corr = corr + (abs(1-corr) - abs(1-corr) * abs(1-corr))

        weighted_diff.append(
            (impact, avg_timestamp / max_timestamp * 100, weight, avg_timestamp, r_left, r_right, corr * 100))

    sorted_diff = sorted(weighted_diff, key=lambda e: ((e[2] + (e[1] + e[6])/2) / 2))
    return sorted_diff

def sort_relations_simple(diff, max_weight, max_timestamp):
    weighted_diff = []
    for quad in diff:
        weight = quad[0]
        avg_timestamp = quad[1]
        r_left = quad[2]
        r_right = quad[3]
        weighted_diff.append(
            (weight / max_weight * 100, avg_timestamp / max_timestamp * 100, weight, avg_timestamp, r_left, r_right))

    sorted_diff = sorted(weighted_diff, key=lambda e: ((e[1] + e[0]) / 2))
    return sorted_diff

def compare_relations(parent_d, parent_key, left, right, left_counts, right_counts, d1, mrs_left=None, mrs_right=None):
    if left is None or right is None:
        print("[warn] One relation group is None")
        return
    max_timestamp = 0
    max_weight = 0
    diff = []
    left_over_left = {}
    left_over_right = {}
    extra_weight = None
    for pair in left.relations:
        r = pair[0]
        if r.insn == 0x40744b:
            extra_weight = r.weight.perc_contrib
            print("Extra weight is " + str(extra_weight))
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
            our_ratio = (index if index is not None else 0)/ max(total_count if total_count is not None else 1, 1)
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
        if r.insn == 0x4072e5 and extra_weight is not None:
            d = abs(r2.weight.perc_contrib - extra_weight - r.weight.perc_contrib)
        else:
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

    sorted_diff = sorted(weighted_diff, key=lambda e: ((e[1] + e[0])/2))
    for p in sorted_diff:
        print("-----------------------------------------")
        print("weight: " + str(p[0]) + " timestamp: " + str(p[1]) + " correlation:" + str(p[6]))
        print(str(p[2]) + " " + str(p[3]))
        print(str(p[4]))
        print(str(p[5]))
    
        r_left = p[4]
        r_right = p[5]
        include = True
        if r_left is not None and r_right is not None:
            include = compare_absolute_count(left, right, r_left, r_right, left_summary, right_summary, left_counts, right_counts, insn_to_insn)
        elif r_left is not None:
            print("only has r left: " + str(len(left_seen)))
            for seen in left_seen:
                if r_left.relaxed_equals(seen):
                    include = False
                    break
            if include is True:
                left_seen.append(r_left)
        elif r_right is not None:
            print("only has r right: " + str(len(right_seen)))
            for seen in right_seen:
                if r_right.relaxed_equals(seen):
                    include = False
                    break
            if include is True:
                right_seen.append(r_right)
        if not include:
            print("NO RANK")
            continue
        print("HAS RANK")
        #print("rank: " + str(rank))
        included_diff.append(p)

    print("===============================================")
    print("===============================================")
    insns_left = []
    insns_right = []
    rank = len(included_diff) + 1
    for p in included_diff:
        rank = rank - 1
        print("-----------------------------------------")
        print("rank: " + str(rank))
        print("weight: " + str(p[0]) + " timestamp: " + str(p[1]) + " correlation:" + str(p[6]))
        print(str(p[2]) + " " + str(p[3]))
        print(str(p[4]))
        print(str(p[5]))
        r_left = p[4]
        r_right = p[5]
        if r_left is not None:
            insns_left.append(r_left.insn)
        if r_right is not None:
            insns_right.append(r_right.insn)
    
    with open('insns_left', 'a') as out:
        for i in insns_left:
            out.write(str(i) + "\n")

    with open('insns_right', 'a') as out:
        for i in insns_right:
            out.write(str(i) + "\n")


if __name__ == "__main__":
    #f1 = sys.argv[1]
    #f2 = sys.argv[2]
    limit, program, program_args, program_path, starting_events, starting_insn_to_weight = parse_inputs()
    _, other_dir, other_program, other_relations_file, _ = parse_relation_analysis_inputs()

    dir1 = curr_dir
    dir2 = other_dir

    cache_dir1 = os.path.join(curr_dir, "cache", program)
    cache_dir2 = os.path.join(curr_dir, "cache", other_program)
    #cache_dir2 = "cache/mongod_4.0.13"

    file1 = "rgroups_simple_" + build_key(starting_events) + ".json"
    file2 = other_relations_file

    d1 = os.path.join(dir1, cache_dir1)
    d2 = os.path.join(dir2, cache_dir2)

    f1 = os.path.join(dir1, cache_dir1, file1)
    f2 = os.path.join(dir2, cache_dir2, file2)
    f12 = os.path.join(dir2, cache_dir1, file2)

    compare_relation_groups(f1, f12)
