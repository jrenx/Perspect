import sys
import os
from relations import *
from util import *
from ra_util import *
curr_dir = os.path.dirname(os.path.realpath(__file__))

def parse(f):
    with open(f, 'r') as ff:
        simple_relation_groups = SimpleRelationGroups.fromJSON(json.load(ff))
    #print(simple_relation_groups)
    return simple_relation_groups

def build_insn_to_relation_group_map(rs):
    m = {}
    for rg in rs.relations_map.values():
        m[rg.insn] = rg
    return m

def build_insn_to_reverse_relation_group_map(rs):
    m = {}
    for rg in rs.relations_map.values():
        for pair in rg.relations:
            r = pair[0]
            prede = pair[1]
            if r.insn not in m:
                m[r.insn] = ([], prede)
            m[r.insn][0].append((r, rg.index_quad))
    m1 = {}
    for insn in m:
        relations, group_index_quad = m[insn]
        predes = []
        relations_map = {}
        for relation, index_quad in relations:
            predes.append(index_quad)
            file, line, index, total_count = Indices.parse_index_quad(index_quad)
            child_key = Indices.build_key_from_index_quad(index_quad)
            relations_map[child_key] = (relation, index_quad)
            if total_count == 0 or total_count is None or index is None:
                child_key_short = file + "_" + str(line)
                relations_map[child_key_short] = (relation, index_quad)
            else:
                child_key_short = file + "_" + str(line)
                inner_map = relations_map.get(child_key_short, {})
                if len(inner_map) == 0:
                    relations_map[child_key_short] = inner_map
                elif isinstance(inner_map, tuple):
                    pair = inner_map
                    inner_map = {}
                    inner_map[0] = pair
                ratio = index/max(total_count,1)
                inner_map[ratio] = (relation, index_quad)
        predes = Indices.build_indices(predes)
        file, line, index, total_count = Indices.parse_index_quad(group_index_quad)
        key = file + "_" + str(line) + "_" + str(total_count) + "_" + str(index)
        key_short = file + "_" + str(line)
        simple_relation_group = SimpleRelationGroup(group_index_quad, key, key_short, \
                                                    None, predes, None, relations, relations_map, None)
        m1[insn] = simple_relation_group
    return m1


''' TODO, need to handle when binaries are different '''
def compare_prede_rel(insn1, insn2, mrs1, mrs2):
    if insn1 not in mrs1 or insn2 not in mrs2:
        return True
    left = mrs1[insn1]
    right = mrs2[insn2]
    for pair in left.relations:
        r = pair[0]
        prede = pair[1]
        file, line, index, total_count = Indices.parse_index_quad(prede)
        key = right.predes.get_indices2(file, line, total_count, index)
        if key is None:
            if r.weight.perc_contrib < 5:
                print("[ra] Contribution is too low, ignore the relations")
                continue
            else:
                return True

        ''' Find the matching relation from the right hand side relation group '''
        val = right.relations_map.get(key) #TODO
        if isinstance(val, dict):
            # when cannot find a precise match, match on ratio
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

        ''' If the two relations are roughly equal, ignore '''
        if r.relaxed_equals(r2):
            continue
        else:
            return True

    for pair in right.relations:
        r = pair[0]
        prede = pair[1]
        file, line, index, total_count = Indices.parse_index_quad(prede)
        key = left.predes.get_indices2(file, line, total_count, index)
        if key is None:
            if r.weight.perc_contrib < 5:
                print("[ra] Contribution is too low, ignore the relations")
                continue
            else:
                return True
    return False


''' comparing the absolute count of two relations, this is a heuristic '''
def compare_absolute_count(left, right, r1, r2, \
        summary1, summary2, counts1, counts2, insn_to_insn):
    if len(summary1) == 0 or len(summary2) == 0:
        return True
    print("DEBUG insns: " + hex(r1.insn) + " " + hex(r2.insn))
    c1 = counts1.get(r1.insn, -1)
    c2 = counts2.get(r2.insn, -1)
    print("DEBUG counts: " + str(c1) + " " + str(c2))
    diff = abs(c1/c2-1)*100 
    print("DEBUG diff: " + str(diff))
    ''' if both counts are small, tolerate a higher difference of 50% '''
    ''' otherwise, only tolerate a difference of 25% '''
    if (c1 + c2) <= 10:
        if diff > 50:
            return True
    else:
        if diff > 25:
            return True
    return False
    # rest of the logic is ignored for now
    succes1 = summary1[r1.insn]
    succes2 = summary2[r2.insn]
    ''' check that they have the same set of successors '''
    ''' then for each that match check that the counts are similar '''
    ''' put everything in quad to count then repeat the comparison '''
    print("DEBUG succes: " + str(len(succes1)) + " " + str(len(succes2)))
    #if len(succes1) != len(succes2):
    #    return True

    for succe1 in succes1:
        succe2 = insn_to_insn.get(succe1, None)
        if succe2 is None:
            print(hex(succe1) + " has no matching insn")
            continue
            #return True
        if succe2 not in succes2:
            print(hex(succe2) + " not in the other set")
            #return True
            continue

        c1 = counts1.get(succe1, -1)
        c2 = counts2.get(succe2, -1)
        diff = abs(c1/c2-1)*100 
        print("DEBUG sub diff: " + str(diff))
        if diff > 25:
            return True
    return False
 
def compare_relation_groups(f1, f2, tf1, tf2, d1, mf1, mf12):
    rs1 = parse(f1)
    #print(rs1)
    rs2 = parse(f2)
    #print(rs2)

    mrs1 = None
    if os.path.exists(mf1):
        mrs1 = build_insn_to_reverse_relation_group_map(parse(mf1))
        #mrs1 = build_insn_to_relation_group_map(parse(mf1))
    #print(mrs1)
    mrs2 = None
    if os.path.exists(mf12):
        mrs2 = build_insn_to_reverse_relation_group_map(parse(mf12))
        #mrs2 = build_insn_to_relation_group_map(parse(mf12))
    #print(mrs2)


    nc1 = load_node_info(tf1)
    print("node_count_1: " + str(nc1))
    nc2 = load_node_info(tf2)
    print("node_count_2: " + str(nc2))
    
    diff = []
    ''' find matching relation group from the other execution '''
    for rg in set(rs1.relations_map.values()):
        file, line, index, total_count = Indices.parse_index_quad(rg.index_quad)
        key = rs2.indices.get_indices2(file, line, total_count, index)
        right = None
        if key is None:
            #print(str(rg.index_quad) + " not found in other set of relations.")
            #continue
            d = rg.group_weight
            key = Indices.build_key_from_index_quad(rg.index_quad)
        else:
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
            #diff.append((d, rg.index_quad, None, rg))
            diff.append((d, Indices.build_key_from_index_quad(rg.index_quad), None, rg))

    ''' sort by difference in the base weight of the relation groups '''
    ''' then compare relations within each group '''
    #print(diff)
    sorted_diff = sorted(diff, key=lambda e: (e[0], e[1]))
    #print(sorted_diff)
    print("========================================")
    for p in sorted_diff:
        print()
        print(str(p[0]) + " " + str(p[1]) + " " + str(p[2]) + " " + str(p[3]))
        print()
        compare_relations(p[0], p[1], p[2], p[3], nc1, nc2, d1, mrs1, mrs2)
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
            #corr = (r_left.forward.corr() + r_right.forward.corr())/2
            corr = r_left.forward.corr() 
        else:
            impact = weight / max_weight * 100
            corr = r_left.forward.corr() if r_left is not None else r_right.forward.corr()

        weighted_diff.append(
            (impact, (avg_timestamp / max_timestamp * 100 + corr * 100)/2, weight, avg_timestamp, r_left, r_right))

<<<<<<< HEAD
    sorted_diff = sorted(weighted_diff, key=lambda e: ((e[1] + e[0]) / 2))
=======
    sorted_diff = sorted(weighted_diff, key=lambda e: ((e[0] + (e[1] + e[6])) / 3))
>>>>>>> 4081ae8... [compare_relation] Updated to only use the specificity from the bad run.
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
    left_summary_file = os.path.join(d1, hex(left.insn) + "_summary")
    print(left_summary_file)
    left_summary = {}
    if os.path.exists(left_summary_file):
        with open(left_summary_file, 'r') as f:
            in_result = json.load(f)
            for key in in_result: left_summary[int(key)] = set(in_result[key])
    print("left_summary: " + str(left_summary))

    right_summary_file = os.path.join(d1, "_" + hex(right.insn) + "_summary")
    print(right_summary_file)
    right_summary = {}
    if os.path.exists(right_summary_file):
        with open(right_summary_file, 'r') as f:
            in_result = json.load(f)
            for key in in_result: right_summary[int(key)] = set(in_result[key])
    print("right_summary: " + str(right_summary))

    insn_to_insn = {}

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
                print("[ra] Relation is duplicate, ignore...")
                continue
            left_over_left[prede[0] + "_" + str(prede[1])] = (r.weight.perc_contrib, r.timestamp, r, None)
            #diff.append((r.weight.perc_contrib, r.timestamp, r, None))
            continue

        ''' Find the matching relation from the right hand side relation group '''
        val = right.relations_map.get(key) #TODO
        if isinstance(val, dict):
            # when cannot find a precise match, match on ratio
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
        insn_to_insn[r.insn] = r2.insn

        ''' If the two relations are roughly equal, ignore '''
        if r.relaxed_equals(r2):
            continue

        ''' If average contribution of the pair of relations are small, ignore '''
        avg_contrib = (r2.weight.perc_contrib + r.weight.perc_contrib)/2
        if avg_contrib < 5:
            print("[ra] Average contribution is too low, ignore the relations")
            continue

        ''' If average contribution of the pair of relations are small, ignore '''
        d = abs(r2.weight.perc_contrib - r.weight.perc_contrib) #TODO diff by contribution
        avg_timestamp = (r2.timestamp + r.timestamp)/2
        #if d < 5:
        #    continue
        diff.append((d, avg_timestamp, r, r2))
        max_timestamp = max(max_timestamp, avg_timestamp)
        max_weight = max(max_weight, d)

    ''' Go through relations from the right hand side relation groups '''
    ''' that are not matched to a relation from the left hand side '''
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
                print("[ra] Relation is duplicate, ignore...")
                continue
            left_over_right[prede[0] + "_" + str(prede[1])] = (r.weight.perc_contrib, r.timestamp, None, r)
            #diff.append((r.weight.perc_contrib, r.timestamp, None, r))

    ''' this is just to calculate the max timestamp and weight '''
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

    print("insn_to_insn: " + str(insn_to_insn))

    #sorted_diff = sort_relations_simple(diff, max_weight, max_timestamp)
    sorted_diff = sort_relations_complex(diff, max_weight, max_timestamp)
    included_diff = []
    #rank = len(sorted_diff) + 1
    left_seen = []
    right_seen = []
    for p in sorted_diff:
        #rank = rank - 1
        print("-----------------------------------------")
        print(str(p[0]) + " " + str(p[1]))
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
        if include is True and mrs_left is not None and mrs_right is not None:
            r_insn = r_left.insn if r_left is not None else r_right.insn
            include = compare_prede_rel(r_insn, r_insn, mrs_left, mrs_right)
            print("compare prede rel result: " + str(include))

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
        print(str(p[0]) + " " + str(p[1]))
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

    key = build_key(starting_events)
    file1 = "rgroups_simple_" + key + ".json"
    file2 = other_relations_file
    mfile1 = "multiple_context_" + file1
    mfile2 = "multiple_context_" + file2
    trace_file1 = key + "_instruction_trace.out.count"
    trace_file2 = parse_other_insn_trace() + ".count"

    d1 = os.path.join(dir1, cache_dir1)
    d2 = os.path.join(dir2, cache_dir2)

    f1 = os.path.join(dir1, cache_dir1, file1)
    f2 = os.path.join(dir2, cache_dir2, file2)
    f12 = os.path.join(dir2, cache_dir1, file2)

    mf1 = os.path.join(dir1, cache_dir1, mfile1)
    mf2 = os.path.join(dir2, cache_dir2, mfile2)
    mf12 = os.path.join(dir2, cache_dir1, mfile2)

    tf1 = os.path.join(dir1, "pin", trace_file1)
    tf12 = os.path.join(dir1, "pin", trace_file2)

    print(f1)
    print(f12)

    print(tf1)
    print(tf12)

    compare_relation_groups(f1, f12, tf1, tf12, d1, mf1, mf12)
