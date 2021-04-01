import json
import os

from dynamic_dep_graph import *
from static_dep_graph import *

curr_dir = os.path.dirname(os.path.realpath(__file__))
target_dir = os.path.join(curr_dir, 'dynamicGraph')

dynamic_graph_json_file = os.path.join(target_dir, 'dynamic_graph_result')
static_node_json_file = os.path.join(target_dir, 'static_nodes_result')


def convert_static_ndoe_from_json(static_node_json_map):
    id_to_static_nodes = {}
    id_to_basic_blocks = {}

    for node_info in static_node_json_map:
        basicBlock = None
        if 'bb' in node_info:
            bb_info = json.loads(node_info['bb'])
            id = bb_info['id']
            ends_in_branch = bb_info['ends_in_branch']
            is_entry = bb_info['is_entry']
            lines = bb_info['lines']
            basicBlock = BasicBlock(id, ends_in_branch, is_entry, lines)
            basicBlock.start_insn = bb_info['start_insn']
            basicBlock.last_insn = bb_info['last_insn']
            if 'immed_dom' in bb_info:
                basicBlock.immed_dom = bb_info['immed_dom']
            if 'immed_pdom' in bb_info:
                basicBlock.immed_pdom = bb_info['immed_pdom']
            basicBlock.pdoms = bb_info['pdoms']
            basicBlock.backedge_targets = bb_info['backedge_targets']
            basicBlock.predes = bb_info['predes']
            basicBlock.succes = bb_info['succes']

            id_to_basic_blocks[id] = basicBlock

        id = node_info['id']
        insn = node_info['insn']
        function = node_info['function']
        staticNode = StaticNode(insn, basicBlock, function, id)
        staticNode.explained = node_info['explained']
        staticNode.is_cf = node_info['is_cf']
        staticNode.is_df = node_info['is_df']
        staticNode.mem_load = node_info['mem_load']
        staticNode.reg_load = node_info['reg_load']
        staticNode.mem_store = node_info['mem_store']
        staticNode.reg_store = node_info['reg_store']
        staticNode.cf_predes = node_info['cf_predes']
        staticNode.cf_succes = node_info['cf_succes']
        staticNode.df_predes = node_info['df_predes']
        staticNode.df_succes = node_info['df_succes']

        id_to_static_nodes[id] = staticNode

    for bb in id_to_basic_blocks.values():
        if bb.immed_dom is not None:
            if bb.immed_dom in id_to_basic_blocks:
                bb.immed_dom = id_to_basic_blocks[bb.immed_dom]
            else:
                bb.immed_dom = None

        if bb.immed_pdom is not None:
            if bb.immed_pdom in id_to_basic_blocks:
                bb.immed_pdom = id_to_basic_blocks[bb.immed_pdom]
            else:
                bb.immed_pdom = None

        pdoms = []
        for id in bb.pdoms:
            if id in id_to_basic_blocks:
                pdoms.append(id_to_basic_blocks[id])
            bb.pdoms = pdoms

        backedge_targets = []
        for id in bb.backedge_targets:
            if id in id_to_basic_blocks:
                backedge_targets.append(id_to_basic_blocks[id])
            bb.backedge_targets = backedge_targets

        predes = []
        for id in bb.predes:
            if id in id_to_basic_blocks:
                predes.append(id_to_basic_blocks[id])
            bb.predes = predes

        succes = []
        for id in bb.succes:
            if id in id_to_basic_blocks:
                succes.append(id_to_basic_blocks[id])
            bb.succes = succes


    for static_node in id_to_static_nodes.values():

        static_node.bb = id_to_basic_blocks[static_node.bb.id]
        cf_predes = []
        for id in static_node.cf_predes:
            if id in id_to_static_nodes:
                cf_predes.append(id_to_static_nodes[id])
            static_node.cf_predes = cf_predes

        cf_succes = []
        for id in static_node.cf_succes:
            if id in id_to_static_nodes:
                cf_succes.append(id_to_static_nodes[id])
            static_node.cf_succes = cf_succes

        df_predes = []
        for id in static_node.df_predes:
            if id in id_to_static_nodes:
                df_predes.append(id_to_static_nodes[id])
            static_node.df_predes = df_predes

        df_succes = []
        for id in static_node.df_succes:
            if id in id_to_static_nodes:
                df_succes.append(id_to_static_nodes[id])
            static_node.df_succes = df_succes

    return id_to_static_nodes


def load_dynamic_graph():
    dynamic_nodes = []
    id_to_dynamic_node = {}

    with open(static_node_json_file) as infile:
        static_node_json_map = json.load(infile)

    id_to_static_nodes = convert_static_ndoe_from_json(static_node_json_map)

    with open(dynamic_graph_json_file) as infile:
        dyanmic_graph_json_map = json.load(infile)

    for node_info in dyanmic_graph_json_map:
        dynamicNode = DynamicNode.fromJSON(node_info, id_to_static_nodes)
        id_to_dynamic_node[node_info['id']] = dynamicNode

    for dynamicNode in id_to_dynamic_node.values():

        cf_predes = []
        for id in dynamicNode.cf_predes:
            if id in id_to_dynamic_node:
                cf_predes.append(id_to_dynamic_node[id])
            dynamicNode.cf_predes = cf_predes

        cf_succes = []
        for id in dynamicNode.cf_succes:
            if id in id_to_dynamic_node:
                cf_succes.append(id_to_dynamic_node[id])
            dynamicNode.cf_succes = cf_succes

        df_predes = []
        for id in dynamicNode.df_predes:
            if id in id_to_dynamic_node:
                df_predes.append(id_to_dynamic_node[id])
            dynamicNode.df_predes = df_predes

        df_succes = []
        for id in dynamicNode.df_succes:
            if id in id_to_dynamic_node:
                df_succes.append(id_to_dynamic_node[id])
            dynamicNode.df_succes = df_succes

        dynamic_nodes.append(dynamicNode)

    return id_to_static_nodes, id_to_dynamic_node


if __name__ == '__main__':
    id_to_static_nodes, id_to_dynamic_node = load_dynamic_graph()
    print(str(id_to_static_nodes[7]))
    print(str(id_to_dynamic_node[1]))
