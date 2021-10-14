import sys
from relations import *

def parse(f):
    with open(f, 'r') as ff:
        simple_relation_groups = SimpleRelationGroups.fromJSON(json.load(ff))
    print(simple_relation_groups)
    return simple_relation_groups

f1 = sys.argv[1]
rs1 = parse(f1)
print(rs1)
f2 = sys.argv[2]
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
sorted_diff = sorted(diff, key=lambda pair: pair[0])
print(sorted_diff)
for p in sorted_diff:
    print(p)
