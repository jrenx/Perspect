import sys
from relations import *

def parse(f):
    with open(f, 'r') as ff:
        simple_relation_groups = RelationGroup.fromJSON_simple(json.load(ff))
    print(simple_relation_groups)
    return simple_relation_groups

f1 = sys.argv[1]
rs1 = parse(f1)
print(rs1)
f2 = sys.argv[2]
rs2 = parse(f2)
print(rs2)

diff = []
for key in rs1:
    if key not in rs2:
        print(key + " not found in other set of relations.")
        continue
    #d = abs(rs1[key][0] - rs2[key][0])
    d = abs(rs1[key][4] - rs2[key][4])
    diff.append((d, key))
print(diff)
sorted_diff = sorted(diff, key=lambda pair: pair[0])
print(sorted_diff)
for p in sorted_diff:
    print(p)
