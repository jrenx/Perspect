from scipy.stats import norm
from dynamic_dep_graph import *
import sys, traceback

DEBUG = True
Weight_Threshold = 0

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

        if lines is not None:
            self.lines = lines
        else:
            self.lines = []
            file, line = get_line(prede_node.insn, prog)
            if line is not None:
                self.lines.append(line)
            elif isinstance(prede_node.bb, BasicBlock):
                self.lines = list(prede_node.bb.lines)

        if file is None:
            file, line = get_line(prede_node.insn, prog)
        self.file = file
        self.key = str(self.file) + ":" + str(self.lines)

    def __eq__(self, other):
        if not isinstance(other, Relation):
            return False
        return self.weight == other.weight and \
                self.forward == other.forward and \
                self.backward == other.backward

    def __str__(self):
        s = ""
        s += "  >>> " + str(self.key) + " "
        s += self.prede_node.hex_insn + "@" + self.prede_node.function + " <<<\n"
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
        return data

    @staticmethod
    def fromJSON(data, prog):
        segs = data["target_node"].split("@")
        target_node = StaticDepGraph.func_to_graph[segs[1]].insn_to_node[int(segs[0])]

        segs = data["prede_node"].split("@")
        prede_node = StaticDepGraph.func_to_graph[segs[1]].insn_to_node[int(segs[0])]

        prede_count = data["prede_count"]
        weight = Weight.fromJSON(data["weight"])
        lines = [int(d) for d in data["lines"]] if "lines" in data else None
        file = data["file"] if "file" in data else None

        rel = Relation(target_node, prede_node, prede_count, weight, prog, lines=lines, file=file)

        forward = data["forward"]
        if forward is not None:
            rel.forward = Proportion.fromJSON(forward) if forward["is_invariant"] is False else Invariance.fromJSON(forward)

        backward = data["backward"]
        if backward is not None:
            rel.backward = Proportion.fromJSON(backward) if backward["is_invariant"] is False else Invariance.fromJSON(backward)
        return rel

class RelationGroup:
    def __init__(self, starting_node, weight, prog, lines=None, file=None):
        self.starting_node = starting_node
        self.weight = weight
        self.relations = {}
        self.sorted_relations = []
        if lines is not None:
            self.lines = lines
        else:
            self.lines = []
            file, line = get_line(starting_node.insn, prog)
            if line is not None:
                self.lines.append(line)
            elif isinstance(starting_node.bb, BasicBlock):
                self.lines = starting_node.bb.lines

        if file is None:
            file, line = get_line(starting_node.insn, prog)
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

    def toJSON_simple(self):
        data = {}
        data["starting_node"] = [self.starting_node.file, self.starting_node.line,\
                                 self.starting_node.index, self.starting_node.total_count]
        data["use_weight"] = self.use_weight
        simple_relations = []
        for relation in self.relations.values():
            n = relation.prede_node
            simple_relations.append([n.file, n.line, n.index, n.total_count])
        data["relations"] = simple_relations
        simple_wavefront = []
        for n in self.wavefront:
            simple_wavefront.append([n.file, n.line, n.index, n.total_count])
        data["wavefront"] = simple_wavefront
        return data

    @staticmethod
    def fromJSON(data, prog):
        segs = data["starting_node"].split("@")
        starting_node = StaticDepGraph.func_to_graph[segs[1]].insn_to_node[int(segs[0])]
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
            key = prede.file + "_" + str(prede.line) + "_" + str(prede.total_count) + "_" + str(prede.index)
            if other_wavefront is not None:
                if key in other_wavefront:
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
