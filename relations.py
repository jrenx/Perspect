from scipy.stats import norm
from dynamic_dep_graph import *

DEBUG = True
Weight_Threshold = 0

class Invariance:
    def __init__(self, ratio, conditional_proportion=None): #TODO, in the future, replace with actual conditions
        self.ratio = ratio
        self.is_conditional = False
        self.conditional_proportion = None
        if conditional_proportion is not None:
            self.is_conditional = True
            self.conditional_proportion = conditional_proportion

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
            self.w_mu, self.w_std = norm.fit(weighted_distribution)
        else:
            self.weighted_distribution = weighted_distribution
            self.w_mu = None
            self.w_std = None

    def __str__(self):
        s = "VARIABLE "
        s += "with distrib (mean: {:.2f}".format(self.mu) + ", std: {:.2f}".format(self.std) + ") "
        if self.weighted_distribution is not None:
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
    def __init__(self, target_node, prede_node, prede_count, weight):
        self.target_node = target_node
        self.prede_node = prede_node
        self.prede_count = prede_count
        self.weight = weight
        self.forward = None
        self.backward = None

    def __str__(self):
        s = ""
        s += "  >>> " + self.prede_node.hex_insn + "@" + self.prede_node.function + " <<<\n"
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
        return data

    @staticmethod
    def fromJSON(data):
        segs = data["target_node"].split("@")
        target_node = StaticDepGraph.func_to_graph[segs[1]].insn_to_node[int(segs[0])]

        segs = data["prede_node"].split("@")
        prede_node = StaticDepGraph.func_to_graph[segs[1]].insn_to_node[int(segs[0])]

        prede_count = data["prede_count"]
        weight = Weight.fromJSON(data["weight"])
        rel = Relation(target_node, prede_node, prede_count, weight)

        forward = data["forward"]
        if forward is not None:
            rel.forward = Proportion.fromJSON(forward) if forward["is_invariant"] is False else Invariance.fromJSON(forward)

        backward = data["backward"]
        if backward is not None:
            rel.backward = Proportion.fromJSON(backward) if backward["is_invariant"] is False else Invariance.fromJSON(backward)
        return rel

class RelationGroup:
    def __init__(self, starting_node, weight):
        self.starting_node = starting_node
        self.weight = weight
        self.relations = {}
        self.sorted_relations = []
        #self.invariant_predes = set()
        self.finished = False

    def __str__(self):
        assert(self.finished)
        s =  "================ Relation Group =================\n"
        s += "Starting event: " + self.starting_node.hex_insn + "@" + self.starting_node.function
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
        relations = []
        for relation in self.relations.values():
            relations.append(relation.toJSON())
        data["relations"] = relations
        return data

    @staticmethod
    def fromJSON(data):
        segs = data["starting_node"].split("@")
        starting_node = StaticDepGraph.func_to_graph[segs[1]].insn_to_node[int(segs[0])]
        weight = data["weight"]
        rgroup = RelationGroup(starting_node, weight)
        rgroup.finished = data["finished"]
        json_relations = data["relations"]
        for json_relation in json_relations:
            relation = Relation.fromJSON(json_relation)
            rgroup.relations[relation.prede_node] = relation
        return rgroup

    def add_base_weight(self, base_weight):
        self.weight = base_weight
        for rel in self.relations.values():
            rel.weight.update_base_weight(base_weight)

    def trim_invariant_group(self):
        to_remove = set()
        for prede in self.relations:
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
        self.sorted_relations = sorted(list(self.relations.values()), key=lambda relation: relation.weight)

    def get_or_make_relation(self, prede_node, prede_count, weight):
        if prede_node in self.relations:
            return self.relations[prede_node]
        else:
            r = Relation(self.starting_node, prede_node, prede_count, weight)
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
        self.actual_weight = round(actual_weight)
        self.base_weight = round(base_weight)

        self.perc_contrib = round(perc_contrib)

        assert (perc_contrib <= 100)
        if actual_weight is None:
                self.total_weight = round(base_weight * perc_contrib/100)
        else:
            self.total_weight = round(actual_weight)
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
        return (self.total_weight == other.total_weight
                and self.corr == other.corr
                and self.order == other.order)

    def __gt__(self, other):
        if self.total_weight > other.total_weight:
            return True
        if self.total_weight < other.total_weight:
            return False
        if self.corr > other.corr:
            return True
        if self.corr < other.corr:
            return False
        if self.order > other.order:
            return True
        return False

    def __lt__(self, other):
        if self.total_weight < other.total_weight:
            return True
        if self.total_weight > other.total_weight:
            return False
        if self.corr < other.corr:
            return True
        if self.corr > other.corr:
            return False
        if self.order < other.order:
            return True
        return False