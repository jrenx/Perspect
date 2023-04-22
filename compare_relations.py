import sys
import os
from relations import *
from util import *
from ra_util import *
import networkx as nx
import numpy as py
import matplotlib.pyplot as plt
from collections import deque
#import chart_studio.plotly as go
#from plotly.graph_objs import *
import plotly.graph_objects as go

curr_dir = os.path.dirname(os.path.realpath(__file__))

def parse(f):
    with open(f, 'r') as ff:
        simple_relation_groups = SimpleRelationGroups.fromJSON(json.load(ff))
    #print(simple_relation_groups)
    return simple_relation_groups

def build_insn_to_relation_group_map(rs):
    m = {}
    for rg in rs.relations:
        m[rg.insn] = rg
    return m

def build_insn_to_reverse_relation_group_map(rs):
    m = {}
    print(len(rs.relation_groups))
    for rg in rs.relation_groups:
        for pair in rg.relations:
            r = pair[0]
            prede = pair[1]
            if r.insn not in m:
                m[r.insn] = ([], prede)
            else:
                assert prede == m[r.insn][1], str(prede) + " " + str(m[r.insn][1])
            m[r.insn][0].append((r, rg.index_quad, rg.insn))
            #r.insn = rg.insn
    m1 = {}
    for insn in m:
        relations, group_index_quad = m[insn]
        predes = []
        relations_map = {}
        for relation, index_quad, new_insn in relations:
            predes.append(index_quad)
            Indices.insert_to_external_indice_to_item_map(relations_map, index_quad, relation, new_insn)

        predes = Indices.build_indices(predes)
        file, line, index, total_count = Indices.parse_index_quad(group_index_quad)
        key = file + "_" + str(line) + "_" + str(total_count) + "_" + str(index)
        key_short = file + "_" + str(line)
        simple_relation_group = SimpleRelationGroup(group_index_quad, key, key_short, \
                                                    None, predes, None, relations, relations_map, None)
        m1[insn] = simple_relation_group
    return m1

def calculate_dataflow_pass_rates_impact(pass_rates_dataflow1, pass_rates_dataflow2, insn1, insn2, insn_left, insn_right,
        weight_map1, weight_map2, indices1=None, indices2=None):
    if indices1 is None or indices2 is None:
        assert indices1 is None and indices2 is None
        if insn_left is None: insn_left = insn_right
        if insn_right is None: insn_right = insn_left
    pass_rate_dataflow1 = pass_rates_dataflow1.get(insn1, {}).get(insn_left, None)
    pass_rate_dataflow2 = pass_rates_dataflow2.get(insn2, {}).get(insn_right, None)
    print("[compare_relation] Dataflow pass rates are: " + str(pass_rate_dataflow1) + " " + str(pass_rate_dataflow2))
    if pass_rate_dataflow1 is None and pass_rate_dataflow2 is None:
        print("[compare_relation] Returning because both sets of dataflow pass rates are notfound.")
        return None
    succe_weights = []
    if pass_rate_dataflow1 is None or pass_rate_dataflow2 is None:
        print("[compare_relation] Returning because not both sets of dataflow pass rates are found.")
        succe_weights.append([0,100])
        return succe_weights
    for key1 in pass_rate_dataflow1:
        segs = key1.split('_')
        succe = int(segs[1], 16)
        #print("[compare_relation] Succe is: " + hex(succe))
        if succe not in weight_map1:# and succe not in weight_map2:
            print("[compare_relation] Ignore because left succe not in weight map")
            continue
        rate1 = pass_rate_dataflow1[key1]
        if indices1 is None and indices2 is None:
            key2 = key1
        else:
            if IndiceToInsnMap.translate_insn(succe, indices1, indices2) not in weight_map2:
                print("[compare_relation] Ignore because right succe not in weight map")
                continue

            key2 = ""
            for seg in segs:
                s_insn = int(seg, 16)
                matching_s_insn = IndiceToInsnMap.translate_insn(s_insn, indices1, indices2)
                if matching_s_insn is None:
                    print("[compare_relation] fail to matching dataflow key")
                    continue
                key2 += hex(matching_s_insn) + "_"
            key2 = key2[:-1]
            print("[compare_relation] translated key is: " + key2)
        if key2 not in pass_rate_dataflow2:
            rate2 = 0
        else:
            rate2 = pass_rate_dataflow2[key2]
        print("[compare_relation] dataflow pass rates: " + str(rate1) + " " + str(rate2))
        if rate1 == rate2:
            continue
        impact = rate1 - rate2
        if impact * 100 <= 5:
            continue
        if impact < 0:
            continue
        succe_weights.append([impact*100, weight_map1[succe]])
        #return False
    print("[compare_relation] dataflow succe weights are: " + str(succe_weights))
    #FIXME: just so downstream we wouldn't think there is no successors encountered
    if len(succe_weights) == 0:
        succe_weights.append([0,100])
    return succe_weights


def dataflow_pass_rates_equal(pass_rates_dataflow1, pass_rates_dataflow2, insn1, insn2, insn_left, insn_right):
    pass_rate_dataflow1 = pass_rates_dataflow1.get(insn1, {}).get(insn_left, None)
    pass_rate_dataflow2 = pass_rates_dataflow2.get(insn2, {}).get(insn_right, None)
    # print(pass_rates_dataflow1.get(insn1, {}))
    # print(pass_rates_dataflow2.get(insn2, {}))
    print("[compare_relation] Dataflow pass rates are: " + str(pass_rate_dataflow1) + " " + str(pass_rate_dataflow2))
    if pass_rate_dataflow1 is None or pass_rate_dataflow2 is None:
        return False
    if len(pass_rate_dataflow1) != len(pass_rate_dataflow2):
        return False
    for key in pass_rate_dataflow1:
        if key not in pass_rate_dataflow2:
            return False
        if pass_rate_dataflow1[key] == pass_rate_dataflow2[key]:
            continue
        if abs(pass_rate_dataflow1[key] - pass_rate_dataflow2[key]) * 100 <= 5:
            continue
        return False
    return True

''' TODO, need to handle when binaries are different '''
# Returns True if the children relations are not equal, else False.
def compare_children_rels(insn1, insn2, mrs1, mrs2, filter1=None, filter2=None,
                          pass_rates1=None, pass_rates2=None,
                           pass_rates_dataflow1=None, pass_rates_dataflow2=None,
                          counts_left=None, counts_right=None,
                          indices1=None, indices2=None):
    if insn1 is None or insn2 is None:
        return True
    print("[compare_relation] comparing children relations for " + hex(insn1) + " and " + hex(insn2))
    print("[compare_relation] only keeping these instructions on the left  "
          + (str([hex(i) for i in filter1]) if filter1 is not None else ""))
    print("[compare_relation] only keeping these instructions on the right "
          + (str([hex(i) for i in filter2]) if filter2 is not None else ""))
    relation_pairs, succes, insns = get_relation_pairs(insn1, insn2, mrs1, mrs2, indices1, indices2)
    if relation_pairs is None: #no multiple relations provided for either runs, assume not equal.
        return True

    ret = False
    for i in range(len(relation_pairs)):
        p = relation_pairs[i]
        s = succes[i]
        ip = insns[i]

        print("---------------------------------")
        print(str(s[0]) + " " + (hex(ip[0]) if ip[0] is not None else "None"))
        print(p[0])
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        print(str(s[1]) + " " + (hex(ip[1]) if ip[1] is not None else "None"))
        print(p[1])
        print("---------------------------------")

        r_left = p[0]
        r_right = p[1]
        insn_left = ip[0]
        insn_right = ip[1]
        print("[compare_relation] Instruction on the left: " + hex(insn_left) if insn_left is not None else str(insn_left))
        print("[compare_relation] Instruction on the right: " + hex(insn_right) if insn_right is not None else str(insn_right))
        if filter1 is not None:
            if r_left is None or insn_left not in filter1:
                print("[compare_relation] instruction filtered out on the left")
                continue

        if filter2 is not None:
            if r_right is None or insn_right not in filter2:
                print("[compare_relation] instruction filtered out on the right")
                continue

        if r_left is None:
            assert r_right is not None
            if r_right.weight.perc_contrib < 5:
                print("[compare_relation] ignore relation with less than 5% impact")
                continue
            else:
                print("[compare_relation] missing r_right")
                ret = True

        if r_right is None:
            assert r_left is not None
            if r_left.weight.perc_contrib < 5:
                print("[compare_relation] ignore relation with less than 5% impact")
                continue
            else:
                print("[compare_relation] missing r_left")
                ret = True

        print("[compare_relation] Actually comparing...")

        #TODO: Right now the pass rate is the combined result of both ratio and probability of passing.
        #TODO: so we use pass rate to override relation comparison.
        if r_left is not None and r_right is not None:
            if r_left.relaxed_equals(r_right, counts_left.get(r_left.insn, None) if counts_left is not None else None, \
                                      counts_right.get(r_right.insn, None) if counts_right is not None else None):
                print("[compare_relation] Relations considered equal.")
                continue

        #if pass_rates1 is not None and pass_rates2 is not None:
        #    pass_rate1 = pass_rates1.get(insn1, {}).get(insn_left, None)
        #    pass_rate2 = pass_rates2.get(insn2, {}).get(insn_right, None)
        #    print("[compare_relation] Pass rates are: " + str(pass_rate1) + " " + str(pass_rate2))
        #    if pass_rate1 is not None and pass_rate2 is not None:
        #        if pass_rate1 == pass_rate2 or abs(pass_rate1-pass_rate2) * 100 <= 5:
        #            print("[compare_relation] Relations consider equal because pass rates w.r.t successors are equal.")
        #            continue

        if pass_rates_dataflow1 is not None and pass_rates_dataflow2 is not None:
            print("[compare_relation] left  keys for dataflow pass rates are: "
                  + (hex(insn1) if insn1 is not None else "") + " " + (hex(insn_left) if insn_left is not None else ""))
            print("[compare_relation] right keys for dataflow pass rates are: "
                  + (hex(insn2) if insn2 is not None else "") + " " + (hex(insn_right) if insn_right is not None else ""))
            pass_rate_dataflow1 = pass_rates_dataflow1.get(insn1, {}).get(insn_left, None)
            pass_rate_dataflow2 = pass_rates_dataflow2.get(insn2, {}).get(insn_right, None)
            print(pass_rates_dataflow1.get(insn1, {}))
            print(pass_rates_dataflow2.get(insn2, {}))
            print("[compare_relation] Dataflow pass rates are: " + str(pass_rate_dataflow1) + " " + str(pass_rate_dataflow2))
            if pass_rate_dataflow1 is not None and pass_rate_dataflow2 is not None:
                equals = len(pass_rate_dataflow1) == len(pass_rate_dataflow2)
                if equals is True:
                    for key in pass_rate_dataflow1:
                        if key not in pass_rate_dataflow2:
                            equals = False
                            break
                        if pass_rate_dataflow1[key] == pass_rate_dataflow2[key]:
                            continue
                        if abs(pass_rate_dataflow1[key] - pass_rate_dataflow2[key]) * 100 <= 5:
                            continue
                        equals = False
                if equals is True:
                    print("[compare_relation] Relations consider equal because pass rates w.r.t. control flow targets are equal.")
                    continue

        ret = True
    return ret

#TODO, merge this logic and the logic being used in the main comparison loop!!
def get_relation_pairs(insn1, insn2, mrs1, mrs2, indices1=None, indices2=None):
    print("[compare_relation] Looking for relation pairs, insn1: " + hex(insn1) + " insn2: " + hex(insn2))
    if mrs1 is None or mrs2 is None:
        return None, None, None
    left = mrs1[insn1] if insn1 in mrs1 else None
    right = mrs2[insn2] if insn2 in mrs2 else None
    if left is None and right is None:
        return None, None, None
    relation_pairs = []
    index_pairs = []
    insn_pairs = []

    if left is None and right is not None:
        for pair in right.relations:
            relation_pairs.append([None, pair[0]])
            index_pairs.append([None, pair[1]])
            insn_pairs.append([None, pair[2]])
            print("[compare_relation] left is None")
        return relation_pairs, index_pairs, insn_pairs
    if left is not None and right is None:
        for pair in left.relations:
            relation_pairs.append([pair[0], None])
            index_pairs.append([pair[1], None])
            insn_pairs.append([pair[2], None])
            print("[compare_relation] right is None")
        return relation_pairs, index_pairs, insn_pairs
    if left is None and right is None:
        return relation_pairs, index_pairs, insn_pairs

    right_seen = set()
    for pair in left.relations:
        r = pair[0]
        prede = pair[1]
        insn = pair[2]
        pair = Indices.get_item_from_external_indice_map2(right.predes, right.relations_map, prede, indices1, indices2)
        if pair is None:
            relation_pairs.append([r, None])
            index_pairs.append([prede, None])
            insn_pairs.append([insn, None])
            continue
        r2 = pair[0]
        prede2 = pair[1]
        insn2 = pair[2]
        right_seen.add(insn2)
        relation_pairs.append([r, r2])
        index_pairs.append([prede, prede2])
        insn_pairs.append([insn, insn2])

    for pair in right.relations:
        r = pair[0]
        prede = pair[1]
        insn = pair[2]
        pair = Indices.get_item_from_external_indice_map2(left.predes, left.relations_map, prede, indices2, indices1)
        if insn in right_seen:
            assert pair is not None
            continue
        #assert pair is None
        #TODO: Why should left to right match fail but not the other way around?
        # Maybe because multiple from the right match to the same one on the left.
        if pair is not None:
            r1 = pair[0]
            prede1 = pair[1]
            insn1 = pair[2]
            relation_pairs.append([r1, r])
            index_pairs.append([prede1, prede])
            insn_pairs.append([insn1, insn])
            continue
        relation_pairs.append([None, r])
        index_pairs.append([None, prede])
        insn_pairs.append([None, insn])
    return relation_pairs, index_pairs, insn_pairs

''' comparing the absolute count of two relations, this is a heuristic '''
def compare_absolute_count(left, right, r1, r2, \
        summary1, summary2, counts1, counts2, insn_to_insn):
    return True
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

def parse_multiple_relations(f):
    mrs = None
    if os.path.exists(f):
        print("File: " + str(f))
        mrs = build_insn_to_reverse_relation_group_map(parse(f))
        #mrs = build_insn_to_relation_group_map(parse(f))
    #print(mrs)
    return mrs

def parse_pass_rates(fname):
    print(fname)
    if not os.path.exists(fname):
        #raise Exception
        return None
    with open(fname, 'r') as f:
        json_pass_rates_per_succe = json.load(f)
        pass_rates_per_succe = {}
        for json_k in json_pass_rates_per_succe:
            json_pass_rates = json_pass_rates_per_succe[json_k]
            k = int(json_k)
            pass_rates = {}
            for json_k_inner in json_pass_rates:
                k_inner = int(json_k_inner)
                pass_rates[k_inner] = json_pass_rates[json_k_inner]
            pass_rates_per_succe[k] = pass_rates
        return pass_rates_per_succe

def build_indices(idf, inf, isf):
    indices = None
    if os.path.exists(idf) and os.path.exists(inf):
        indices = IndiceToInsnMap()
        indices.build(idf, inf, isf)
    return indices

def compare_relation_groups(f1, f2, tf1, tf2, d1, mcf1, mcf12, mf1, mf12, pf1, pf12, pduf1, pduf12,
                            idf1, idf12,
                            compare_highest_ranking_rg_only=False):
    rs1 = parse(f1)
    #print(rs1)
    rs2 = parse(f2)
    #print(rs2)

    mcrs1 = parse_multiple_relations(mcf1)
    mcrs2 = parse_multiple_relations(mcf12)
    mrs1 = parse_multiple_relations(mf1)
    mrs2 = parse_multiple_relations(mf12)

    nc1 = load_node_info(tf1)
    print("node_count_1: " + str(nc1))
    nc2 = load_node_info(tf2)
    print("node_count_2: " + str(nc2))

    pr1 = parse_pass_rates(pf1)
    pr2 = parse_pass_rates(pf12)

    prdu1 = parse_pass_rates(pduf1)
    prdu2 = parse_pass_rates(pduf12)

    indices1 = build_indices(idf1, idf1 + "_insns", idf1 + "_insn_strs")
    indices2 = build_indices(idf12, idf12 + "_insns", idf12 + "_insn_strs")

    inner_indices1 = build_indices(idf1 + "_inner", idf1 + "_inner_insns", None)
    inner_indices2 = build_indices(idf12 + "_inner", idf12 + "_inner_insns", None)

    diff = []
    #TODO, this does not include the detailed ratio level match
    ''' find matching relation group from the other execution '''
    for rg in rs1.relation_groups:
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
    for rg in rs2.relation_groups:
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
    if compare_highest_ranking_rg_only is True:
        sorted_diff = [sorted_diff[-1]]
    #print(sorted_diff)
    print("========================================")
    for p in sorted_diff:
        print()
        print(str(p[0]) + " " + str(p[1]) + " " + str(p[2]) + " " + str(p[3]))
        print()
        compare_relations(p[0], p[1], p[2], p[3], nc1, nc2, d1, mcrs1, mcrs2, mrs1, mrs2,
                          pr1, pr2, prdu1, prdu2, indices1, indices2, inner_indices1, inner_indices2)
        print()
        print(str(p[0]) + " " + str(p[1]) + " " + str(p[2]) + " " + str(p[3]))
        print()
        print("========================================")
    return sorted_diff

#Rational: a event is more likely a negative event if its total weight always decreased in bad run,
# otherwise it's more likely that there simple exists another source of the performance impact in the bad run.
#TODO: Should use the weight of each starting event too, for now, just use the count
def test_if_likely_true_negative_event(r_left, r_right, left_full_weight, right_full_weight):
    left_weight = r_left.weight.perc_contrib * left_full_weight / 100
    right_weight = r_right.weight.perc_contrib * right_full_weight / 100
    print("[compare_relation] Checking if is likely a true negative event, "
          "full weight from the left: " + str(left_weight) + " full weight from the right: " + str(right_weight))
    if left_weight >= right_weight:
        return False
    if abs(left_weight - right_weight)/right_weight * 100 < 20:
        return False
    if r_left.weight.actual_weight > r_right.weight.actual_weight:
        return False
    return True

def sort_relations_precise(diff, max_weight, max_timestamp, left, right,
                           mcrs_left, mcrs_right, mrs_left, mrs_right, summ_left, summ_right,
                           counts_left, counts_right, pass_rates_left=None, pass_rates_right=None,
                           pass_rates_dataflow_left=None, pass_rates_dataflow_right=None,
                           indices_left=None, indices_right=None):
    #assert pass_rates_left is not None
    #assert pass_rates_right is not None
    #assert pass_rates_dataflow_left is not None
    #assert pass_rates_dataflow_right is not None
    weighted_diff = []
    weight_map_left = {}
    weight_map_right = {}
    matched_diff = []
    max_weight = 100

    insns_left = []
    insns_right = []

    # TODO: Should use the weight of each starting event too, for now, just use the count
    left_full_weight = counts_left[left.insn]
    right_full_weight = counts_right[right.insn]

    for quad in diff:
        weight = quad[0]
        avg_timestamp = quad[1]
        r_left = quad[2]
        r_right = quad[3]
        if r_left is None:
            print("======================================================================")
            print("[compare_relation] Examining node1: " + hex(r_right.insn))

            # Candidate for contextless multiple rels
            # TODO, if good and bad run code differ, need reverse lookup to find the matching instruction
            if indices_left is not None and indices_right is not None:
                matching_insn = IndiceToInsnMap.translate_insn(r_right.insn, indices_right, indices_left)
                print("[compare_relation] " + hex(r_right.insn) + " matching instruction is: "
                      + (hex(matching_insn) if matching_insn is not None else "None"))
            else:
                matching_insn = r_right.insn

            if matching_insn is not None:
                insns_right.append(r_right.insn)
                insns_left.append(matching_insn)
            print([hex(s) for s in summ_right[r_right.insn]])

            #TODO, handle when instructions are not the same
            #TODO, get the corresponding insn on the left...
            equals = not compare_children_rels(matching_insn, r_right.insn, mrs_left, mrs_right,
                                               filter1=None, filter2=set(summ_right[r_right.insn]),
                                               pass_rates1=pass_rates_left, pass_rates2=pass_rates_right,
                                               pass_rates_dataflow1=pass_rates_dataflow_left,
                                               pass_rates_dataflow2=pass_rates_dataflow_right,
                                               counts_left=counts_left, counts_right=counts_right,
                                               indices1=indices_left, indices2=indices_right)
            print("[compare_relation] Children relations are equal? " + str(equals))
            assert weight == r_right.weight.perc_contrib
            corr = r_right.forward.corr()
            if equals is True: #TODO, for debugging for now
                corr = "EQUAL!"
                continue
            OK = False
            for succe in summ_right[r_right.insn]:
                print("SUCCE is " + hex(succe))
                oin = IndiceToInsnMap.translate_insn(succe, indices_right, indices_left)
                if oin is not None:
                    print(" is in other slice " + hex(oin))
                    OK = True
                    break
            if OK is False:
                print("HERE")
                continue
        else:
            print("[compare_relation] Adding node to weight map on the left: " + hex(r_left.insn))
            weight_map_left[r_left.insn] = r_left.weight.perc_contrib

        if r_right is None:
            print("======================================================================")
            print("[compare_relation] Examining node2: " + hex(r_left.insn))

            # Candidate for contextless multiple rels
            # TODO, if good and bad run code differ, need reverse lookup to find the matching instruction
            if indices_left is not None and indices_right is not None:
                matching_insn = IndiceToInsnMap.translate_insn(r_left.insn,indices_left, indices_right)
                print("[compare_relation] " + hex(r_left.insn) + " matching instruction is: "
                      + (hex(matching_insn) if matching_insn is not None else "None"))
            else:
                matching_insn = r_left.insn

            if matching_insn is not None:
                insns_right.append(matching_insn)
                insns_left.append(r_left.insn)
            print([hex(s) for s in summ_left[r_left.insn]])

            equals = not compare_children_rels(r_left.insn, matching_insn, mrs_left, mrs_right,
                                               filter1=set(summ_left[r_left.insn]), filter2=None,
                                               pass_rates1=pass_rates_left, pass_rates2=pass_rates_right,
                                               pass_rates_dataflow1=pass_rates_dataflow_left,
                                               pass_rates_dataflow2=pass_rates_dataflow_right,
                                               counts_left=counts_left, counts_right=counts_right,
                                               indices1=indices_left, indices2=indices_right)
            print("[compare_relation] Children relations are equal? " + str(equals))
            assert weight == r_left.weight.perc_contrib
            corr = r_left.forward.corr()
            if equals is True: #TODO, for debugging for now
                corr = "EQUAL!"
                continue

            OK = False
            for succe in summ_left[r_left.insn]:
                print("SUCCE is " + hex(succe))
                oin = IndiceToInsnMap.translate_insn(succe, indices_left, indices_right) 
                if oin is not None:
                    print(" is in other slice " + hex(oin))
                    OK = True
                    break
            if OK is False:
                print("HERE")
                continue

        else:
            print("[compare_relation] Adding node to weight map on the right: " + hex(r_right.insn))
            weight_map_right[r_right.insn] = r_right.weight.perc_contrib

        if r_left is None or r_right is None:
            print("[compare_relation] One of the relations is None.")
            impact = weight / max_weight * 100
            weighted_diff.append(
                (impact, avg_timestamp / max_timestamp * 100, weight, avg_timestamp, r_left, r_right, corr * 100))
            continue

        if r_left is not None and r_right is not None:
            matched_diff.append(quad)
            #matching_insn = IndiceToInsnMap.translate_insn(r_right.insn, indices_right, indices_left)
            #print("[compare_relation] " + hex(r_right.insn) + " matching instruction2 is: "
            #      + (hex(matching_insn) if matching_insn is not None else "None"))
 

    with open('insns_left', 'w') as out:
        for i in insns_left:
            out.write(str(i) + "\n")

    with open('insns_right', 'w') as out:
        for i in insns_right:
            out.write(str(i) + "\n")

    insns_left = set()
    insns_right = set()
    count = 0
    for quad in matched_diff:
        weight = quad[0]
        avg_timestamp = quad[1]
        r_left = quad[2]
        r_right = quad[3]
        print("======================================================================")
        print("[compare_relation] Examining node: " + hex(r_left.insn) + " number seen: " + str(count))

        print(r_left)
        print(r_right)
        #TODO, should we consider pass rate when deciding if they are equal?
        #if r_left.relaxed_equals(r_right):
        #    print("[compare_relation/warn] parent relations equal, do not re-calculate weight.")
        #    continue

        #Not really handled??
        forward_impact = calculate_forward_impact(r_left, r_right)
        backward_impact = calculate_backward_impact(r_left, r_right)
        if backward_impact > forward_impact:
            likely_true_neg_event = test_if_likely_true_negative_event(r_left, r_right, left_full_weight, right_full_weight)
            if likely_true_neg_event is False:
                print("[compare_relation] Event likely not a negative event, do not use its backward impact.")
                backward_impact = 0
            else:
                print("[compare_relation] Event likely a true negative event.")
        #if backward_impact > forward_impact:
        #    print("[compare_relation/warn] Backward impact " + str(backward_impact) +
        #          " is greater than forward impact " + str(forward_impact))
        #    impact = backward_impact / max_weight * 100
        #    weighted_diff.append(
        #        (impact, avg_timestamp / max_timestamp * 100, weight, avg_timestamp, r_left, r_right, corr * 100))
        #    continue
        # Candidate for in context multiple rels
        succe_insns_right = summ_right[r_right.insn]
        print("[compare_relation] succes on the right " + str([hex(i) for i in succe_insns_right]))
        for succe_insn in succe_insns_right:
            #if succe_insn in weight_map_right:
            insns_right.add(succe_insn)
        succe_insns_left = summ_left[r_left.insn]
        print("[compare_relation] succes on the left " + str([hex(i) for i in succe_insns_left]))
        for succe_insn in succe_insns_left:
            #if succe_insn in weight_map_left:
            insns_left.add(succe_insn)

        # Getting any existing in context multiple rels
        left_succe_to_rels = {}
        rigt_succe_to_rels = {} #TODO, what to do in this case?
        pairs, succes, insns = get_relation_pairs(r_left.insn, r_right.insn, mcrs_left, mcrs_right, indices1=indices_left, indices2=indices_right)
        if pairs is not None:
            for i in range(len(pairs)):
                p = pairs[i]
                s = succes[i]
                ip = insns[i]

                if ip[0] is not None:
                    if ip[0] == r_left.insn:
                        continue
                    left_succe_to_rels[ip[0]] = [p, s, ip]
                else:
                    rigt_succe_to_rels[ip[1]] = [p, s, ip]

                #print("---------------------------------")
                #print(str(s[0]) + " " + (hex(ip[0]) if ip[0] is not None else "None"))
                #print(p[0])
                ##print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                #print(str(s[1]) + " " + (hex(ip[1]) if ip[1] is not None else "None"))
                #print(p[1])
                #print("---------------------------------")

        succe_weights = []
        for succe_insn in succe_insns_left:
            if succe_insn not in weight_map_left:
                print("[compare_relation] Succe: " + hex(succe_insn) + " does not have a relation")
                if succe_insn in left_succe_to_rels:
                    print("[compare_relation/warn] " + hex(succe_insn) + " has a one level relation but not full relation: " +  hex(succe_insn)
                            + " likely because relation was ignored due to low weight...")
                    succe_weight = weight_map_left[r_left.insn]
                    print("[compare_relations] Approximate using the weight of the prede instruction: " + str(succe_weight))
                else:
                    continue
            else:
                succe_weight = weight_map_left[succe_insn]
            print("[compare_relation] " + hex(succe_insn) + " succe weights is: " + str(succe_weight))
            if succe_insn not in left_succe_to_rels:
                print("[compare_relation/warn] " + hex(succe_insn) + " has a full relation but not a one level relation, "
                        + " likely need to re-run the multi-level relation gen again...")
                continue

            p, s, ip = left_succe_to_rels[succe_insn]

            print("---------------------------------")
            print(str(s[0]) + " " + (hex(ip[0]) if ip[0] is not None else "None"))
            print(p[0])
            # print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
            print(str(s[1]) + " " + (hex(ip[1]) if ip[1] is not None else "None"))
            print(p[1])
            print("---------------------------------")

            equals = False
            if p[0] is not None and p[1] is not None:
                equals = p[0].relaxed_equals(p[1])
            print("[compare_relation] Equals? " + str(equals))

            if p[0] is not None and p[1] is not None:
                impact = calculate_forward_impact(p[0], p[1])
            else:
                impact = 100#p[0].weight.perc_contrib
            #impact, corr = calculate_weight_corr(p[0].weight.perc_contrib, p[0], p[1])
            if equals is True and impact != 0:
                print("[compare_relation/warn] relations equal why impact not 0? impact is: " + str(impact))
                impact = 0
            print("[compare_relation] impact: " + str(impact))# + " corr: " + str(corr))
            if p[0] is not None and isinstance(p[0].backward, Invariance) and p[0].backward.is_conditional is True:
                proportion = p[0].backward.conditional_proportion
                succe_weight = succe_weight * proportion
                print("[compare_relation] Updating successor weight with proportion: " + str(proportion)
                      + " new weight is: " + str(succe_weight))

            print("[compare_relation] impact is: " + str(impact))
            #if pass_rates_left is not None and pass_rates_right is not None:
            #    pass_rate1 = pass_rates_left.get(r_left.insn, {}).get(ip[0], None)
            #    pass_rate2 = pass_rates_right.get(r_right.insn, {}).get(ip[1], None)
            #    print("[compare_relation] 2 Pass rates are: " + str(pass_rate1) + " " + str(pass_rate2))
            #    if pass_rate1 is not None and pass_rate2 is not None:
            #        pass_rate_ratio = (pass_rate1 - pass_rate2)/pass_rate1
            #        print("[compare_relation] Pass rates ratio is: " + str(pass_rate_ratio))
            #        if pass_rate_ratio > 0:
            #            old_impact = impact
            #            impact = min((100 - impact)*pass_rate_ratio+impact,100)
            #            print("[compare_relation] updating impact from: " + str(old_impact) + " to: " + str(impact))

            #TODO: Should still include the control flow impacts.
            if impact != 0 and pass_rates_dataflow_left is not None and pass_rates_dataflow_right is not None:
                dataflow_impacts = calculate_dataflow_pass_rates_impact(pass_rates_dataflow_left, pass_rates_dataflow_right,
                                                            r_left.insn, r_right.insn, ip[0], ip[1],
                                                            weight_map_left, weight_map_right, indices_left, indices_right)
                if dataflow_impacts is not None:
                    #print("[compare_relation] setting impact from " + str(impact) + " to 0 because pass rates w.r.t. control flow targets are equal.")
                    succe_weights.extend(dataflow_impacts)
                    continue

            succe_weights.append([impact, succe_weight])
            print("---------------------------------")
        succe_weights = sorted(succe_weights, key=lambda e: e[0])

        old_weight = weight_map_left[r_left.insn]
        assert old_weight == r_left.weight.perc_contrib
        print("[compare_relation] original weights full: " + str(old_weight))
        print("[compare_relation] original weights: " + str(forward_impact))
        print("[compare_relation]   succes weights: " + str(succe_weights))
        old_weight = forward_impact

        new_weight = 0
        total_succe_weights_encountered = 0
        for weight_pair in reversed(succe_weights):
            impact = weight_pair[0]
            succe_weight = weight_pair[1]
            total_succe_weights_encountered += succe_weight
            new_weight += impact * succe_weight / 100
            if new_weight > r_left.weight.perc_contrib: #FIXME
                new_weight = r_left.weight.perc_contrib
                break
        if len(succe_weights) == 0:
            print("[compare_relation] no succes, use original weight. ")
            new_weight = old_weight
        elif total_succe_weights_encountered < old_weight :
            # If original weights of successors do not add up to the original weight of the node,
            # this could be because the predecessor has many successors with small weights,
            # which have been ignored ...
            new_weight += (old_weight - total_succe_weights_encountered)
            assert new_weight <= old_weight, str(new_weight) + " " + str(old_weight)
            print("[compare_relation/warn] Updating the weight to "+ str(new_weight))

        #assert new_weight <= old_weight #TODO, remove
        print("[compare_relation] new weights: " + str(new_weight))
        if backward_impact > forward_impact:
            impact = backward_impact + new_weight
            if impact > 100:
                impact = 100
            print("[compare_relation/warn] Backward impact " + str(backward_impact) +
                  " is greater than forward impact " + str(forward_impact) + " combined new weight is: " + str(impact))
            weighted_diff.append(
                (impact, avg_timestamp / max_timestamp * 100, weight, avg_timestamp, r_left, r_right, corr * 100))
            continue

        #Check that there are no cases where a relation with the successor exists
        # but the successor does not exist in the summary file.
        left_over = set(left_succe_to_rels.keys()).difference(succe_insns_left)
        assert(len(left_over) == 0), str(set(left_succe_to_rels.keys())) + " " + str(succe_insns_left)
        if len(rigt_succe_to_rels) > 0:
            print("[compare_relation/warn] Unhandled case: the right hand side has "
                  + str(len(rigt_succe_to_rels)) + " more successor relations that left")

        corr = r_left.forward.corr()
        weighted_diff.append(
            (new_weight, avg_timestamp / max_timestamp * 100, weight, avg_timestamp, r_left, r_right, corr * 100))
        count += 1
    #sorted_diff = sorted(weighted_diff, key=lambda e: ((e[0] + e[1]) / 2))
    sorted_diff = sorted(weighted_diff, key=lambda e: ((e[0]) / 2))

    with open('insns_left_' + hex(left.insn), 'w') as out:
        for i in insns_left:
            out.write(str(i) + "\n")

    with open('insns_right_' + hex(right.insn), 'w') as out:
        for i in insns_right:
            out.write(str(i) + "\n")

    return sorted_diff

def calculate_forward_impact(r_left, r_right):
    forward_impact = r_left.forward.difference(r_right.forward)
    if forward_impact > 0:
        forward_impact = forward_impact / r_left.forward.magnitude() * r_left.weight.perc_contrib
    else:
        forward_impact = 0
    return forward_impact

def calculate_backward_impact(r_left, r_right):
    backward_impact = r_left.weight.perc_contrib - r_right.weight.perc_contrib
    if backward_impact < 0:
        backward_impact = abs(backward_impact)
    else:
        backward_impact = 0
    return backward_impact

def calculate_weight_corr(weight, r_left, r_right):
    max_weight = 100

    if r_left is not None and r_right is not None:
        forward_impact = calculate_forward_impact(r_left, r_right)
        backward_impact = calculate_backward_impact(r_left, r_right)
        impact = max(forward_impact, backward_impact)

        # corr = (r_left.forward.corr() + r_right.forward.corr())/2
        corr = r_left.forward.corr()
    else:
        impact = weight / max_weight * 100
        corr = r_left.forward.corr() if r_left is not None else r_right.forward.corr()

    corr = corr + (abs(1 - corr) - abs(1 - corr) * abs(1 - corr))
    return impact, corr

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

        corr = corr + (abs(1-corr) - abs(1-corr) * abs(1-corr))

        weighted_diff.append(
            (impact, avg_timestamp / max_timestamp * 100, weight, avg_timestamp, r_left, r_right, corr * 100))

    sorted_diff = sorted(weighted_diff, key=lambda e: ((e[0] + (e[1] + e[6])) / 3))
    return sorted_diff

def sort_relations_simple(diff, max_weight, max_timestamp):
    weighted_diff = []
    for quad in diff:
        weight = quad[0]
        avg_timestamp = quad[1]
        r_left = quad[2]
        r_right = quad[3]
        #weight = r_left.weight.perc_contrib if r_left is not None else 0
        weighted_diff.append(
            (weight / max_weight * 100, avg_timestamp / max_timestamp * 100, weight, avg_timestamp, r_left, r_right, 0))

    #sorted_diff = sorted(weighted_diff, key=lambda e: e[0])
    sorted_diff = sorted(weighted_diff, key=lambda e: ((e[1] + e[0]) / 2))
    return sorted_diff

def compare_relations(parent_d, parent_key, left, right, counts_left, counts_right, d1,
                      mcrs_left=None, mcrs_right=None, mrs_left=None, mrs_right=None,
                      pass_rates_left=None, pass_rates_right=None,
                      pass_rates_dataflow_left=None, pass_rates_dataflow_right=None,
                      indices_left=None, indices_right=None,
                      inner_indices_left=None, inner_indices_right=None):
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

    right_summary_file = os.path.join(d1, hex(right.insn) + "_summary")
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
    right_insns_seen = set()
    insn_to_index = {}
    for pair in left.relations:
        r = pair[0]
        prede = pair[1]
        insn_to_index[r.insn] = prede
        print("[compare_relation] Looking for match relation on the left:")
        print(prede)
        print(r)
        ''' Find the matching relation from the right hand side relation group '''
        pair = Indices.get_item_from_external_indice_map2(right.predes, right.relations_map, prede, indices_left, indices_right)
        if pair is None:
            if r.weight.perc_contrib < 5:
                print("[ra] Contribution is too low, ignore the relations: " + hex(r.insn))
                continue
            if r.duplicate is True:
                print("[ra] Relation is duplicate, ignore... " + hex(r.insn))
                continue
            #left_over_left[prede[0] + "_" + str(prede[1])] = (r.weight.perc_contrib, r.timestamp, r, None)
            diff.append((r.weight.perc_contrib, r.timestamp, r, None))
            continue

        r2 = pair[0]
        insn_to_insn[r.insn] = r2.insn

        ''' If the two relations are roughly equal, ignore '''
        #if r.relaxed_equals(r2):
        #    print("[ra] Relations roughly equal, ignore the relations: " + hex(r.insn) + " " + hex(r2.insn))
        #    continue

        ''' If average contribution of the pair of relations are small, ignore '''
        avg_contrib = (r2.weight.perc_contrib + r.weight.perc_contrib)/2
        if avg_contrib < 5:
            print("[ra] Average contribution is too low, ignore the relations: " + hex(r.insn) + " " + hex(r2.insn))
            continue

        ''' If average contribution of the pair of relations are small, ignore '''
        d = abs(r2.weight.perc_contrib - r.weight.perc_contrib) #TODO diff by contribution
        avg_timestamp = (r2.timestamp + r.timestamp)/2
        #if d < 5:
        #    continue
        right_insns_seen.add(r2.insn)
        diff.append((d, avg_timestamp, r, r2))
        max_timestamp = max(max_timestamp, avg_timestamp)
        max_weight = max(max_weight, d)

    ''' Go through relations from the right hand side relation groups '''
    ''' that are not matched to a relation from the left hand side '''
    for pair in right.relations:
        r = pair[0]
        prede = pair[1]
        insn_to_index[r.insn] = prede
        print("[compare_relation] Looking for matching relation on the right:")
        print(prede)
        print(r)
        pair = Indices.get_item_from_external_indice_map2(left.predes, left.relations_map, prede, indices_right, indices_left)
        if r.insn in right_insns_seen:
            #assert pair is not None
            continue

        if pair is None:
            #assert pair is None
            if r.weight.perc_contrib < 5:
                print("[ra] Contribution is too low, ignore the relations: " + hex(r.insn))
                continue
            if r.duplicate is True:
                print("[ra] Relation is duplicate, ignore... " + hex(r.insn))
                continue
            #left_over_right[prede[0] + "_" + str(prede[1])] = (r.weight.perc_contrib, r.timestamp, None, r)
            diff.append((r.weight.perc_contrib, r.timestamp, None, r))
            continue

        #TODO: I don't know why an instruction would fail to match in the first check and match here...
        r1 = pair[0]
        insn_to_insn[r1.insn] = r.insn

        #if r1.relaxed_equals(r):
        #    print("[ra] Relations roughly equal, ignore the relations: " + hex(r1.insn) + " " + hex(r.insn))
        #    continue

        ''' If average contribution of the pair of relations are small, ignore '''
        avg_contrib = (r1.weight.perc_contrib + r.weight.perc_contrib) / 2
        if avg_contrib < 5:
            print("[ra] Average contribution is too low, ignore the relations: " + hex(r1.insn) + " " + hex(r.insn))
            continue

        ''' If average contribution of the pair of relations are small, ignore '''
        d = abs(r1.weight.perc_contrib - r.weight.perc_contrib)  # TODO diff by contribution
        avg_timestamp = (r1.timestamp + r.timestamp) / 2
        # if d < 5:
        #    continue
        diff.append((d, avg_timestamp, r1, r))
        max_timestamp = max(max_timestamp, avg_timestamp)
        max_weight = max(max_weight, d)

    ''' this is just to calculate the max timestamp and weight '''
    #for key_short in left_over_left:
    #    triple_left = left_over_left[key_short]
    #    r = triple_left[2]
    #    if key_short in left_over_right:
    #        triple_right = left_over_right[key_short]
    #        r_right = triple_right[3]
    #        if r.relaxed_equals(r_right):
    #            del left_over_right[key_short]
    #            continue
    #    diff.append((r.weight.perc_contrib, r.timestamp, r, None))
    #    max_timestamp = max(max_timestamp, r.timestamp)
    #    max_weight = max(max_weight, r.weight.perc_contrib)
    #for triple in left_over_right.values():
    #    r = triple[3]
    #    diff.append((r.weight.perc_contrib, r.timestamp, None, r))
    #    max_timestamp = max(max_timestamp, r.timestamp)
    #    max_weight = max(max_weight, r.weight.perc_contrib)

    max_timestamp = max(max_timestamp, 1)
    max_weight = max(max_weight, 1)

    print("insn_to_insn: " + str(insn_to_insn))

    #TODO, weight is the avg of the two relations if both are present
    #sorted_diff = sort_relations_simple(diff, max_weight, max_timestamp)
    #sorted_diff = sort_relations_complex(diff, max_weight, max_timestamp)
    sorted_diff = sort_relations_precise(diff, max_weight, max_timestamp, left, right,
                                         mcrs_left, mcrs_right, mrs_left, mrs_right, left_summary, right_summary,
                                         counts_left, counts_right, pass_rates_left, pass_rates_right,
                                         pass_rates_dataflow_left, pass_rates_dataflow_right, indices_left, indices_right)

    included_diff = []
    #rank = len(sorted_diff) + 1
    left_seen = []
    right_seen = []
    # Reverse the list so if there are multiple equal relations,
    # we will always see the highest ranked ones first, keep them, and exclude the lowest ranked ones.
    for p in reversed(sorted_diff):
        #rank = rank - 1
        print("-----------------------------------------")
        print("weight: " + str(p[0]) + " timestamp: " + str(p[1]) + " correlation:" + str(p[6]))
        print(str(p[2]) + " " + str(p[3]))
        if p[4] is not None: print(insn_to_index[p[4].insn])
        print(str(p[4]))
        if p[5] is not None: print(insn_to_index[p[5].insn])
        print(str(p[5]))
    
        r_left = p[4]
        r_right = p[5]
        include = True
        if r_left is not None and r_right is not None:
            include = compare_absolute_count(left, right, r_left, r_right, left_summary, right_summary,
                                             counts_left, counts_right, insn_to_insn)
            if include is False:
                print("[compare_relation] absolute count of event same in both runs, ignore...")
        elif r_left is not None:
            print("[compare_relation] only has r left: " + str(len(left_seen)))
            #for seen in left_seen:
            #    if r_left.relaxed_equals(seen):
            #        print("[compare_relation] already seen a similar relation, ignore...")
            #        include = False
            #        break
            succe_in_other_slice = True
            for succe in left_summary[r_left.insn]:
                matching_insn = IndiceToInsnMap.translate_insn(succe, indices_left, indices_right)
                if matching_insn is None:
                    succe_in_other_slice = False
                    break
            if not succe_in_other_slice:
                print("[compare_relation/warn] None of the successors are in the other slice1")
                include = False
            #if include is True:
            #    left_seen.append(r_left)
        elif r_right is not None:
            print("[compare_relation] only has r right: " + str(len(right_seen)))
            #for seen in right_seen:
            #    if r_right.relaxed_equals(seen):
            #        print("[compare_relation] already seen a similar relation, ignore...")
            #        include = False
            #        break
            succe_in_other_slice = True
            for succe in right_summary[r_right.insn]:
                matching_insn = IndiceToInsnMap.translate_insn(succe, indices_right, indices_left)
                if matching_insn is None:
                    succe_in_other_slice = False
                    break
            if not succe_in_other_slice:
                print("[compare_relation/warn] None of the successors are in the other slice2")
                include = False

            #if include is True:
            #    right_seen.append(r_right)
        #if include is True and mcrs_left is not None and mcrs_right is not None:
        #    r_insn = r_left.insn if r_left is not None else r_right.insn
        #    #TODO, this wont work if source codes are different
        #    include = compare_children_rels(r_insn, r_insn, mcrs_left, mcrs_right, indices_right, indices_left)
        #    print("[compare_relation] compare immediate successor rel result: " + str(include))

        if not include:
            print("NO RANK, ignore the relations: " + (hex(r_left.insn) if r_left is not None else "")
                  + " " + (hex(r_right.insn) if r_right is not None else ""))
            continue
        print("HAS RANK")
        #print("rank: " + str(rank))
        included_diff.append(p)


    print("===============================================")
    print("===============================================")
    #insns_left = []
    #insns_right = []
    rank = len(included_diff) + 1

    for p in reversed(included_diff):
        rank = rank - 1
        print("-----------------------------------------")
        print("rank: " + str(rank))
        print("weight: " + str(round(p[0],2)) + "%")# + " timestamp: " + str(p[1]) + " correlation:" + str(p[6]))
        #print(str(p[2]) + " " + str(p[3]))
        #if p[4] is not None: print(insn_to_index[p[4].insn])
        print(str(p[4]))
        #if p[5] is not None: print(insn_to_index[p[5].insn])
        print(str(p[5]))
        #if has a node in the graph, add a label...

        #r_left = p[4]
        #r_right = p[5]
        # Candidate for contextless multiple rels
        # TODO, if good and bad run code differ, need reverse lookup to find the matching instruction
        #if r_left is None:
        #    insns_left.append(r_right.insn)
        #    insns_right.append(r_right.insn)
        #if r_right is None:
        #    insns_left.append(r_left.insn)
        #    insns_right.append(r_left.insn)
    
    #with open('insns_left', 'w') as out:
    #    for i in insns_left:
    #        out.write(str(i) + "\n")

    #with open('insns_right', 'w') as out:
    #    for i in insns_right:
    #        out.write(str(i) + "\n")

    #plot(included_diff, rel_map1, rel_map2, left_summary, right_summary, left, right)

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

    d1 = os.path.join(dir1, cache_dir1)
    d2 = os.path.join(dir2, cache_dir2)

    file1 = "rgroups_simple_" + key + ".json"
    file2 = other_relations_file
    f1 = os.path.join(dir1, cache_dir1, file1)
    f2 = os.path.join(dir2, cache_dir2, file2)
    f12 = os.path.join(dir2, cache_dir1, file2)
    print(f1)
    print(f12)

    mcfile1 = "multiple_context_" + file1
    mcfile2 = "multiple_context_" + file2
    mcf1 = os.path.join(dir1, cache_dir1, mcfile1)
    #mcf2 = os.path.join(dir2, cache_dir2, mcfile2)
    mcf12 = os.path.join(dir2, cache_dir1, mcfile2)
    print(mcf1)
    print(mcf12)

    mfile1 = "multiple_" + file1
    mfile2 = "multiple_" + file2
    mf1 = os.path.join(dir1, cache_dir1, mfile1)
    #mf2 = os.path.join(dir2, cache_dir2, mfile2)
    mf12 = os.path.join(dir2, cache_dir1, mfile2)
    print(mf1)
    print(mf12)

    trace_file1 = key + "_instruction_trace.out.count"
    trace_file2 = parse_other_insn_trace() + ".count"
    tf1 = os.path.join(dir1, "pin", trace_file1)
    tf12 = os.path.join(dir1, "pin", trace_file2)
    print(tf1)
    print(tf12)

    other_key = parse_other_key()
    pfile1 = "pass_rates_" + key + ".json"
    pfile2 = "pass_rates" + other_key + ".json"
    pf1 = os.path.join(dir1, cache_dir1, pfile1)
    #pf2 = os.path.join(dir2, cache_dir2, pfile2)
    pf12 = os.path.join(dir2, cache_dir1, pfile2)
    print(pf1)
    print(pf12)

    pdufile1 = "pass_rates_def_to_use_site_" + key + ".json"
    pdufile2 = "pass_rates_def_to_use_site" + other_key + ".json"
    pduf1 = os.path.join(dir1, cache_dir1, pdufile1)
    #pduf2 = os.path.join(dir2, cache_dir2, pdufile2)
    pduf12 = os.path.join(dir2, cache_dir1, pdufile2)
    print(pduf1)
    print(pduf12)

    indices_file1 = "indices_" + key
    indices_file2 = "indices" + other_key
    idf1 = os.path.join(dir1, cache_dir1, indices_file1)
    #idf2 = os.path.join(dir2, cache_dir2, indices_file2)
    idf12 = os.path.join(dir2, cache_dir1, indices_file2)
    print(idf1)
    print(idf12)

    ##FIXME: no need for these...  possibly simplify
    #insns_file1 = "indices_" + key + "_insns"
    #insns_file2 = "indices" + other_key + "_insns"
    #inf1 = os.path.join(dir1, cache_dir1, insns_file1)
    ##inf2 = os.path.join(dir2, cache_dir2, insns_file2)
    #inf12 = os.path.join(dir2, cache_dir1, insns_file2)
    #print(inf1)
    #print(inf12)

    compare_relation_groups(f1, f12, tf1, tf12, d1, mcf1, mcf12, mf1, mf12, pf1, pf12, pduf1, pduf12,
                            idf1, idf12,
                            compare_highest_ranking_rg_only=True)
