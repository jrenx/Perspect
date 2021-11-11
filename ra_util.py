import json
from relations import *
def load_indices(indices_file_path):
    if not os.path.exists(indices_file_path):
        return None
    with open(indices_file_path, 'r') as f:
        index_quads = json.load(f)
        return Indices.build_indices(index_quads)

def load_node_info(count_file_path):
    print("[ra] Loading node info from file: " + str(count_file_path))
    if not os.path.exists(count_file_path):
        return None
    node_counts = {}
    with open(count_file_path, 'r') as f: #TODO
        for l in f.readlines():
            insn = int(l.split()[0], 16)
            count = int(l.split()[1])
            node_counts[insn] = count
    return node_counts
