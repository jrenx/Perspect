#include <vector>
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>

#include "Instruction.h"
#include "InstructionDecoder.h"
#include "CodeObject.h"
#include "CFG.h"
#include "Graph.h"
#include "slicing.h"

void locateBitVariables(GraphPtr slice,
                        boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariables,
                        boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariablesToIgnore,
                        boost::unordered_map<Assignment::Ptr, AbsRegion> &bitOperands,
                        boost::unordered_map<Assignment::Ptr, std::vector<Assignment::Ptr>> &bitOperations);

void analyzeKnownBitVariables(GraphPtr slice,
                              Expression::Ptr memWrite,
                              boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariables,
                              boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariablesToIgnore,
                              boost::unordered_map<Assignment::Ptr, AbsRegion> &bitOperands,
                              boost::unordered_map<Assignment::Ptr, std::vector<Assignment::Ptr>> &bitOperations);

void findMemoryLoad(Expression::Ptr memWrite,
                    GraphPtr slice,
                    std::vector<Node::Ptr> *list);

bool findMemoryLoadHelper(Expression::Ptr memWrite,
                          SliceNode::Ptr node,
                          std::vector<Node::Ptr> *list,
                          boost::unordered_set<Assignment::Ptr> &visited);

int getBitMaskDigits(Instruction insn, std::vector<AbsRegion> &regions);
