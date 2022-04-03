from scipy.stats import norm
from scipy.stats import ks_2samp
from dynamic_dep_graph import *
import sys, traceback

DEBUG = True
Weight_Threshold = 0
PRINT_IGNORE_RATIO = 10
IGNORE_VARIABLE_CHAIN = False

def get_line(insn, prog):
    if not isinstance(insn, str):
        insn = hex(insn)
    cmd = ['addr2line', '-e', prog, insn]
    #print("[main] running command: " + str(cmd))
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    result_seg = result.stdout.decode('ascii').strip().split(":")
    file = result_seg[0].split("/")[-1]
    try:
        line = int(result_seg[1])
        #print("[main] command returned: " + str(line))
    except ValueError:
        line = None
    return file, line

class Invariance:
    def __init__(self, ratio, conditional_proportion=None): #TODO, in the future, replace with actual conditions
        self.ratio = ratio
        self.is_conditional = False
        self.conditional_proportion = None
        if conditional_proportion is not None:
            self.is_conditional = True
            self.conditional_proportion = conditional_proportion

    def __eq__(self, other):
        if not isinstance(other, Invariance):
            return False
        return self.ratio == other.ratio and \
                self.is_conditional == other.is_conditional and \
                self.conditional_proportion == other.conditional_proportion

    def relaxed_equals(self, other):
        if not isinstance(other, Invariance):
            return False
        if self.ratio != other.ratio:
            return False
        if self.is_conditional != other.is_conditional:
            return False
        if self.conditional_proportion == other.conditional_proportion:
            return True
        diff = abs(self.conditional_proportion - other.conditional_proportion)
        if diff/self.conditional_proportion < 0.1 or diff < 0.01:
            return True
        return False

    def difference(self, other):
        if isinstance(other, Invariance):
            return self.ratio - other.ratio
        elif isinstance(other, Proportion):
            return self.ratio - other.mu
        else:
            raise Exception

    def magnitude(self):
        return self.ratio

    def corr(self):
        mag = self.magnitude()
        if mag > 1:
            return 1/mag
        else:
            return mag

    def __str__(self):
        s = "INVARIANT with ratio: " + str(self.ratio)
        if self.is_conditional is True:
            s += " conditional with proportion: {:.2f}%".format(self.conditional_proportion*100)
        s += "\n"
        return s

    def toJSON(self):
        data = {}
        data["is_invariant"] = True
        data["ratio"] = self.ratio
        data["conditional_proportion"] = self.conditional_proportion
        return data

    @staticmethod
    def fromJSON(data):
        ratio = data['ratio']
        conditional_proportion = data['conditional_proportion']
        return Invariance(ratio, conditional_proportion)

    @staticmethod
    def is_irrelevant(counts):
        return len(counts) == 1 and 0 in counts

    @staticmethod
    def is_invariant(counts):
        return len(counts) == 1 and 0 not in counts

    @staticmethod
    def is_conditionally_invariant(counts):
        return len(counts) == 2 and 0 in counts

    @staticmethod
    def get_conditional_proportion(count_list):
        assert(Invariance.is_conditionally_invariant(set(count_list)) == True)
        none_zero_count = 0
        for c in count_list:
            if c != 0:
                none_zero_count += 1
        return none_zero_count/len(count_list)

class Proportion:
    def __init__(self, distribution, weighted_distribution):
        if None in weighted_distribution:
            weighted_distribution = []
        #print(distribution)
        self.distribution = distribution
        self.mu, self.std = norm.fit(distribution)
        #print(weighted_distribution)
        if len(weighted_distribution) > 0:
            self.weighted_distribution = weighted_distribution
            try:
                self.w_mu, self.w_std = norm.fit(weighted_distribution)
            except Exception as e:
                print("Caught exception fitting to distribution: " + str(e))
                print(str(e))
                print("-" * 60)
                traceback.print_exc(file=sys.stdout)
                print("-" * 60)
                print("Distribution is: " + str(weighted_distribution))

        else:
            self.weighted_distribution = weighted_distribution
            self.w_mu = None
            self.w_std = None

    def __eq__(self, other):
        if not isinstance(other, Proportion):
            return False
        return self.mu == other.mu and \
                self.std == other.std and \
                self.w_mu == other.w_mu and \
                self.w_std == other.w_std

    def relaxed_equals(self, other):
        if not isinstance(other, Proportion):
            return False
        result = ks_2samp(self.distribution, other.distribution)
        if result.pvalue > 0.95:
            return True
        if self.weighted_distribution is None or len(self.weighted_distribution) == 0 or\
                other.weighted_distribution is None or len(other.weighted_distribution) == 0:
            return False
        result = ks_2samp(self.weighted_distribution, other.weighted_distribution)
        if result.pvalue > 0.95:
            return True
        return False

    def difference(self, other):
        if isinstance(other, Invariance):
            return self.mu - other.ratio
        elif isinstance(other, Proportion):
            return self.mu - other.mu
        else:
            raise Exception

    def magnitude(self):
        return self.mu

    def corr(self):
        mag = self.magnitude()
        if mag > 1:
            return 1/mag
        else:
            return mag

    def __str__(self):
        s = "VARIABLE "
        s += "with distrib (mean: {:.2f}".format(self.mu) + ", std: {:.2f}".format(self.std) + ") "
        if self.weighted_distribution is not None and len(self.weighted_distribution) > 0:
            s += "and weighted distrib (mean: {:.2f}".format(self.w_mu) + ", std: {:.2f}".format(self.w_std) + ")"
        s += "\n"
        return s

    def toJSON(self):
        data = {}
        data["is_invariant"] = False
        data["distribution"] = self.distribution
        data["weighted_distribution"] = self.weighted_distribution
        return data

    @staticmethod
    def fromJSON(data):
        distribution = data['distribution']
        weighted_distribution = data['weighted_distribution']
        return Proportion(distribution, weighted_distribution)

class Relation:
    def __init__(self, target_node, prede_node, prede_count, weight, prog, lines=None, file=None):
        self.target_node = target_node
        self.prede_node = prede_node
        self.prede_count = prede_count
        self.weight = weight
        self.forward = None
        self.backward = None
        self.timestamp = None
        self.insn = None

        self.lines = lines
        self.file = file
        if self.lines is None or self.file is None:
            self.lines = []
            self.lines.append(prede_node.line)
            self.file = prede_node.file
        if self.lines is None or self.file is None:
            file, line = get_line(prede_node.insn, prog + "_debug")
            self.lines = []
            self.lines.append(line)
            self.file = file

        self.key = str(self.file) + ":" + str(self.lines)
        self.duplicate = False

    def __eq__(self, other):
        if not isinstance(other, Relation):
            return False
        return self.weight == other.weight and \
                self.forward == other.forward and \
                self.backward == other.backward

    def relaxed_equals(self, other):
        if not isinstance(other, Relation):
            return False
        diff = abs(self.weight.perc_contrib - other.weight.perc_contrib)/self.weight.perc_contrib
        return diff < 0.1 and \
               self.weight.corr == other.weight.corr and \
               self.forward.relaxed_equals(other.forward) and \
                self.backward.relaxed_equals(other.backward)

    def __str__(self):
        s = ""
        s += "  >>> " + str(self.key) + " "
        if self.prede_node is not None:
            s += self.prede_node.hex_insn + "@" + self.prede_node.function
        elif self.insn is not None:
            s += hex(self.insn)
        s += " timestamp: " + str(self.timestamp)
        if self.duplicate is True:
            s += " Duplicate "
        s += "<<<\n"
        s += "  " + str(self.weight) + "\n"
        s += "  => forward:  " + str(self.forward)
        s += "  => backward: " + str(self.backward)
        s += "-----------------\n"
        return s

    def toJSON(self):
        data = {}
        data["target_node"] = str(self.target_node.insn) +"@" + self.target_node.function
        data["prede_node"] = str(self.prede_node.insn) +"@" + self.prede_node.function
        data["prede_count"] = self.prede_count
        data["weight"] = self.weight.toJSON()
        data["forward"] = self.forward.toJSON() if self.forward is not None else None
        data["backward"] = self.backward.toJSON() if self.backward is not None else None
        data["lines"] = self.lines
        data["file"] = self.file
        data["timestamp"] = self.timestamp
        data["duplicate"] = self.duplicate
        return data

    @staticmethod
    def fromJSON(data, prog):
        segs = data["target_node"].split("@")
        graph = StaticDepGraph.get_graph(segs[1], int(segs[0]))
        target_node = graph.insn_to_node[int(segs[0])]

        segs = data["prede_node"].split("@")
        graph = StaticDepGraph.get_graph(segs[1], int(segs[0]))
        prede_node = graph.insn_to_node[int(segs[0])]

        prede_count = data["prede_count"]
        weight = Weight.fromJSON(data["weight"])
        lines = [(int(d) if d is not None else None) for d in data["lines"]] if "lines" in data else None
        file = data["file"] if "file" in data else None

        rel = Relation(target_node, prede_node, prede_count, weight, prog, lines=lines, file=file)

        forward = data["forward"]
        if forward is not None:
            rel.forward = Proportion.fromJSON(forward) if forward["is_invariant"] is False else Invariance.fromJSON(forward)

        backward = data["backward"]
        if backward is not None:
            rel.backward = Proportion.fromJSON(backward) if backward["is_invariant"] is False else Invariance.fromJSON(backward)

        if "timestamp" in data:
            rel.timestamp = data["timestamp"]

        if "duplicate" in data:
            rel.duplicate = data["duplicate"]
        return rel

class RelationGroup:
    def __init__(self, starting_node, weight, prog, lines=None, file=None):
        self.starting_node = starting_node
        self.weight = weight
        self.relations = {}
        self.sorted_relations = []

        self.lines = lines
        self.file = file
        if self.lines is None or self.file is None:
            self.lines = []
            self.lines.append(starting_node.line)
            self.file = starting_node.file
        if self.lines is None or self.file is None:
            file, line = get_line(starting_node.insn, prog + "_debug")
            self.lines = []
            self.lines.append(line)
            self.file = file

        #self.invariant_predes = set()
        self.finished = False
        self.use_weight = False
        self.wavefront = None

    def __str__(self):
        assert(self.finished)
        s =  "================ Relation Group =================\n"
        s += "Starting event: " + str(self.file) + ":" + str(self.lines) + " "
        s +=  self.starting_node.hex_insn + "@" + self.starting_node.function
        s += " weight: " + str(self.weight) + "\n"
        s += " Total number of relations: " + str(len(self.sorted_relations)) + "\n"
        for rel in reversed(self.sorted_relations):
            if rel.weight.perc_contrib < PRINT_IGNORE_RATIO:
                continue
            s += str(rel)
        s += "=================================================\n"
        return s

    def toJSON(self):
        data = {}
        data["starting_node"] = str(self.starting_node.insn) +"@" + self.starting_node.function
        data["weight"] = self.weight
        data["finished"] = self.finished
        data['lines'] = self.lines
        data['file'] = self.file
        data["use_weight"] = self.use_weight
        relations = []
        for relation in self.relations.values():
            relations.append(relation.toJSON())
        data["relations"] = relations
        return data

    @staticmethod
    def fromJSON(data, prog):
        segs = data["starting_node"].split("@")
        graph = StaticDepGraph.get_graph(segs[1], int(segs[0]))
        starting_node = graph.insn_to_node[int(segs[0])]
        weight = data["weight"]
        rgroup = RelationGroup(starting_node, weight, prog)
        rgroup.finished = data["finished"]
        if 'lines' in data:
            rgroup.lines = data['lines']
        if 'file' in data:
            rgroup.file = data['file']
        if 'use_weight' in data:
            rgroup.use_weight = data['use_weight']
        json_relations = data["relations"]
        for json_relation in json_relations:
            relation = Relation.fromJSON(json_relation, prog)
            rgroup.relations[relation.prede_node] = relation
        rgroup.sort_relations()
        return rgroup

    def add_base_weight(self, base_weight):
        self.weight = base_weight
        for rel in self.relations.values():
            rel.weight.update_base_weight(base_weight)

    def trim_invariant_group(self, other_wavefront=None):
        to_remove = set()
        for prede in self.relations:
            if other_wavefront is not None:
                key = other_wavefront.get_indices(prede)
                if key is not None:
                    print("[ra] cannot remove node " + prede.hex_insn \
                          + " because it exists in the relations of the other repro")
                    continue
            if not isinstance(self.relations[prede].forward, Proportion):
                continue
            if not isinstance(self.relations[prede].backward, Proportion):
                continue
            has_only_proportion_succe = True
            for n in itertools.chain(prede.cf_succes, prede.df_succes):
                if n == self.starting_node:
                    has_only_proportion_succe = False
                    break
                if n not in self.relations:
                    continue
                if not isinstance(self.relations[n].forward, Proportion):
                    has_only_proportion_succe = False
                    break
                if not isinstance(self.relations[n].backward, Proportion):
                    has_only_proportion_succe = False
                    break
            if has_only_proportion_succe is False:
                continue
            to_remove.add(prede)
        if IGNORE_VARIABLE_CHAIN is True:
            for prede in to_remove:
                print("[ra] Removing a variable relation whose successors all have variable relations: ")
                print(self.relations[prede])
                del self.relations[prede]
        self.finished = True

    def sort_relations(self):
        self.sorted_relations = sorted(list(self.relations.values()), key=lambda relation: (relation.key, relation.weight))

    def get_or_make_relation(self, prede_node, prede_count, weight, prog):
        if prede_node in self.relations:
            return self.relations[prede_node]
        else:
            r = Relation(self.starting_node, prede_node, prede_count, weight, prog)
            self.relations[prede_node] = r
            return r
        """
        self.starting_node = starting_node
        self.conditionally_forward_invariant_nodes = set()
        self.forward_invariant_nodes = set()
        self.conditionally_backward_invariant_nodes = set()
        self.backward_invariant_nodes = set()
        self.wave_front = set() #TODO is this really useful?
        #TODO, what if we just include the invariant nodes at the edgraphes
        # and simplify when there is an OR? makes verification easier too
        """

class SimpleRelationGroup:
    def __init__(self, index_quad, key, key_short, \
                 used_weight, predes, wavefront, relations, relations_map, group_weight):
        self.index_quad = index_quad
        self.key = key
        self.key_short = key_short
        self.used_weight = used_weight
        self.predes = predes # are the indices of predes
        self.wavefront = wavefront
        self.relations = relations
        self.relations_map = relations_map
        self.group_weight = group_weight
        self.insn = None

    def __str__(self):
        if self.insn is not None:
            return hex(self.insn)
        return "Relation Group"

    @staticmethod
    def toJSON(relation_group):
        data = {}
        data["starting_node"] = [relation_group.starting_node.file, relation_group.starting_node.line,\
                                 relation_group.starting_node.index, relation_group.starting_node.total_count]
        data["use_weight"] = relation_group.use_weight
        data["weight"] = relation_group.weight
        predes = []
        prede_insns = []
        if relation_group.relations is not None:
            for r in relation_group.relations.values():
                n = r.prede_node
                predes.append([n.file, n.line, n.index, n.total_count])
                prede_insns.append(n.hex_insn)
        data["predes"] = predes
        data["predes_insns"] = prede_insns
        data["insn"] = relation_group.starting_node.insn

        relations = []
        if relation_group.relations is not None:
            for r in relation_group.relations.values():
                relation_data = {}
                relation_data["weight"] = r.weight.toJSON()
                relation_data["forward"] = r.forward.toJSON() if r.forward is not None else None
                relation_data["backward"] = r.backward.toJSON() if r.backward is not None else None
                relation_data["timestamp"] = r.timestamp
                relation_data["insn"] = r.prede_node.insn if r.prede_node is not None else r.insn
                relation_data["duplicate"] = r.duplicate
                relations.append(relation_data)
        data["relations"] = relations

        wavelets = []
        if relation_group.wavefront is not None:
            for n in relation_group.wavefront:
                wavelets.append([n.file, n.line, n.index, n.total_count])
        data["wavefront"] = wavelets
        return data

    @staticmethod
    def fromJSON(json_simple_relation_group):
        use_weight = json_simple_relation_group["use_weight"]
        group_weight = None
        if "weight" in json_simple_relation_group:
            group_weight = json_simple_relation_group["weight"]
        predes = None
        sorted_predes = None
        if "predes" in json_simple_relation_group:
            predes = []
            sorted_predes = []
            for index_quad in json_simple_relation_group["predes"]:
                sorted_predes.append(index_quad)
                predes.append(index_quad)

            predes = Indices.build_indices(predes)
        prede_insns = None
        if "prede_insns" in json_simple_relation_group:
            prede_insns = json_simple_relation_group["prede_insns"]
        relations = None
        relations_map = None
        if "relations" in json_simple_relation_group:
            relations = []
            relations_map = {}
            assert(len(sorted_predes) == len(json_simple_relation_group["relations"]))
            for i in range(len(sorted_predes)):
                index_quad = sorted_predes[i]
                #print(index_quad)
                if "??" in index_quad:
                    print("[ra/warn] no file or linenum found for insn: " + prede_insns[i] if prede_insns is not None else "")
                    continue
                relation_data = json_simple_relation_group["relations"][i]
                file, line, index, total_count = Indices.parse_index_quad(index_quad)

                weight = Weight.fromJSON(relation_data["weight"])
                #print(weight)
                relation = Relation(None, None, None, weight, None, lines=line, file=file)
                if "timestamp" in relation_data: relation.timestamp = relation_data["timestamp"]
                if "insn" in relation_data: relation.insn = relation_data["insn"]
                if "duplicate" in relation_data: relation.duplicate = relation_data["duplicate"]
                forward = relation_data["forward"]
                if forward is not None:
                    relation.forward = Proportion.fromJSON(forward) \
                        if forward["is_invariant"] is False else Invariance.fromJSON(forward)
                backward = relation_data["backward"]
                if backward is not None:
                    relation.backward = Proportion.fromJSON(backward) \
                        if backward["is_invariant"] is False else Invariance.fromJSON(backward)
                relations.append((relation, index_quad))

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
                    #relations_map[child_key_short] = (relation, index_quad)
        wavefront = None
        if "wavefront" in json_simple_relation_group:
            wavefront = []
            for index_quad in json_simple_relation_group["wavefront"]:
                wavefront.append(index_quad)
            wavefront = Indices.build_indices(wavefront)
        file, line, index, total_count = Indices.parse_index_quad(json_simple_relation_group["starting_node"])
        key = file + "_" + str(line) + "_" + str(total_count) + "_" + str(index)
        key_short = file + "_" + str(line)
        simple_relation_group = SimpleRelationGroup(json_simple_relation_group["starting_node"], key, key_short, \
                                                    use_weight, predes, wavefront, relations, relations_map, group_weight)
        if "insn" in json_simple_relation_group:
            simple_relation_group.insn = json_simple_relation_group["insn"]
        return simple_relation_group

class SimpleRelationGroups:

    def __init__(self, relations_map, indices):
        self.relations_map = relations_map
        self.indices = indices

    @staticmethod
    def fromJSON(data):
        relations_map = {}
        index_quads = []
        for json_simple_relation_group in data:
            simple_relation = SimpleRelationGroup.fromJSON(json_simple_relation_group)
            relations_map[simple_relation.key] = simple_relation
            relations_map[simple_relation.key_short] = simple_relation
            index_quads.append(simple_relation.index_quad)
        indices_map = Indices.build_indices(index_quads)
        return SimpleRelationGroups(relations_map, indices_map)

class Indices:
    def __init__(self, indices_map):
        self.indices_map = indices_map

    @staticmethod
    def parse_index_quad(index_quad):
        return index_quad[0], index_quad[1], index_quad[2], index_quad[3]

    @staticmethod
    def build_key_from_index_quad(index_quad):
        file, line, index, total_count = Indices.parse_index_quad(index_quad)
        key = file + "_" + str(line) + "_" + str(total_count) + "_" + str(index)
        return key

    @staticmethod
    def build_indices(index_quads):
        indices_map = {}
        for index_quad in index_quads:
            file, line, index, total_count = Indices.parse_index_quad(index_quad)
            lines = indices_map.get(file, None)
            if lines is None:
                lines = {}
                indices_map[file] = lines
            existing_total_count, indices = lines.get(line, (None, None))
            if indices is None:
                indices = set()
                lines[line] = (total_count, indices)
            else:
                pass
                #assert existing_total_count == total_count
            indices.add(index)
            if total_count is not None and existing_total_count is not None:
                if total_count > existing_total_count:
                    lines[line] = (total_count, indices)
                
        return Indices(indices_map)

    def get_indices(self, n):
        return self.get_indices2(n.file, n.line, n.total_count, n.index)

    def get_indices2(self, file, line, total_count, index):
        lines = self.indices_map.get(file, None)
        if lines is None:  # file not found
            return None
        (existing_total_count, indices) = lines.get(line, (None, None))
        if indices is None:  # line not found
            return None
        # only check if the index exists if the line maps to the same number of binary instructions
        # so it's highly likely that it makes sense to match on the index of the binaries
        if total_count is None:
            return file + "_" + str(line)
        if total_count == existing_total_count:
            if index not in indices:
                return None
            else:
                return file + "_" + str(line) + "_" + str(total_count) + "_" + str(index)
        else:
            return file + "_" + str(line)

    def indices_not_found(self, prede_node):
        lines = self.indices_map.get(prede_node.file, None)
        if lines is None:  # file not found
            return True
        (total_count, indices) = lines.get(prede_node.line, (None, None))
        if indices is None:  # line not found
            return True
        # only check if the index exists if the line maps to the same number of binary instructions
        # so it's highly likely that it makes sense to match on the index of the binaries
        if prede_node.total_count is None:
            return False
        if prede_node.total_count == total_count:
            if prede_node.index not in indices:
                return True
        return False


class Weight:
    def __init__(self, actual_weight, base_weight, perc_contrib, corr, order):
        self.actual_weight = actual_weight
        self.base_weight = base_weight

        self.perc_contrib = perc_contrib

        assert (perc_contrib <= 100)
        if actual_weight is None:
                self.total_weight = base_weight * perc_contrib/100
        else:
            self.total_weight = actual_weight
            assert round(actual_weight) == round(base_weight * perc_contrib/100), \
                str(round(actual_weight)) + " " + str(round(base_weight * perc_contrib/100))

        self.corr = corr
        self.order = order

    def update_base_weight(self, base_weight):
        self.base_weight = base_weight
        if self.actual_weight is None:
            self.total_weight = self.perc_contrib * base_weight / 100
        else:
            self.total_weight = self.actual_weight
            self.perc_contrib = self.actual_weight / base_weight * 100

    def __str__(self):
        s = ""
        s += "Total weight:{:20.2f} ".format(self.total_weight)
        s += "%Contrib:{:6.2f}% ".format(self.perc_contrib)
        s += "Corr:{:6.2f}% ".format(self.corr * 100)
        #s += "Round:{:.2f} ".format(self.round_contrib)
        s += "order:{:6d} ".format(self.order)
        return s

    def toJSON(self):
        data = {}
        data["actual_weight"] = self.actual_weight
        data["base_weight"] = self.base_weight
        data["perc_contrib"] = self.perc_contrib
        data["corr"] = self.corr
        data["order"] = self.order
        return data

    @staticmethod
    def fromJSON(data):
        actual_weight = data["actual_weight"]
        base_weight = data["base_weight"]
        perc_contrib = data["perc_contrib"]
        corr = data["corr"]
        order = data["order"]
        return Weight(actual_weight, base_weight, perc_contrib, corr, order)

    def __eq__(self, other):
        return (round(self.total_weight, 2) == round(other.total_weight, 2)
                and self.corr == other.corr)
        #and self.order == other.order)

    def __gt__(self, other):
        if round(self.total_weight, 2) > round(other.total_weight, 2):
            return True
        if round(self.total_weight, 2) < round(other.total_weight, 2):
            return False
        if self.corr > other.corr:
            return True
        if self.corr < other.corr:
            return False
        #if self.order > other.order:
        #    return True
        return False

    def __lt__(self, other):
        if round(self.total_weight, 2) < round(other.total_weight, 2):
            return True
        if round(self.total_weight, 2) > round(other.total_weight, 2):
            return False
        if self.corr < other.corr:
            return True
        if self.corr > other.corr:
            return False
        #if self.order < other.order:
        #    return True
        return False
