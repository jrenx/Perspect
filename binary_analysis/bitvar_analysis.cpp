#include "bitvar_analysis.hpp"
#include "util.hpp"

#include <stdio.h>
#include <iostream>
#include <fstream>

#include <vector>
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>
#include <boost/heap/priority_queue.hpp>
#include <boost/algorithm/string.hpp>

#include "Instruction.h"
#include "InstructionDecoder.h"
#include "CodeObject.h"
#include "CFG.h"
#include "Graph.h"
#include "slicing.h"

using namespace std;
using namespace boost;
using namespace Dyninst;
using namespace InstructionAPI;
using namespace ParseAPI;
using namespace DataflowAPI;

void analyzeKnownBitVariables(GraphPtr slice,
                              Expression::Ptr memWrite,
                              boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariables,
                              boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariablesToIgnore,
                              boost::unordered_map<Assignment::Ptr, AbsRegion> &bitOperands,
                              boost::unordered_map<Assignment::Ptr, std::vector<Assignment::Ptr>> &bitOperations) {

  // TODO: to implement this properly:
  /*
   *the proper way to handle the known bit variables:
   *run forward normal bit variable with the flag set,
   * find the read point,
   * from the read point get all the bit operations like already done
   * then, check if the read and write points are the same:
   * first, same expression,
   * second, the registers in the expression have the same set of definition points
   */

  // Enqueue all the root nodes of the dataflow graph.
  // Need to do reverse post order.
  std::vector<Node::Ptr> list;
  //getReversePostOrderList(slice, &list);
  //std::reverse(list.begin(), list.end());
  findMemoryLoad(memWrite, slice, &list);
  if (list.begin() == list.end()) {
    if (INFO) cout << "[bit_var] no memory loads found for bit var, returning ..." << endl;
    return;
  }

  //boost::unordered_set<Assignment::Ptr> visitedVariables;
  AbsRegion source;
  std::vector<Assignment::Ptr> operations;
  for(auto it = list.begin(); it != list.end(); ++it) {
    Node::Ptr node = *it;
    SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(node);
    Assignment::Ptr assign = aNode->assign();
    if (assign == NULL) continue;
    entryID id = assign->insn().getOperation().getID();

    if (DEBUG_BIT) cout << "[bit_var] " << "CHECKING instruction for bit variable: ";
    if (DEBUG_BIT) cout << "[bit_var] " << assign->format() << " ";
    if (DEBUG_BIT) cout << "[bit_var] " << assign->insn().format() << " ";
    if (DEBUG_BIT) cout << "[bit_var] " << id << " ";
    if (DEBUG_BIT) cout << endl;

    if (it == list.begin()) {
      source = assign->out();
      continue;
    }

    bool usesSource = false;
    std::vector<AbsRegion> regions;
    for (auto rit = assign->inputs().begin(); rit != assign->inputs().end(); rit++) {
      if (*rit == source) {
        usesSource = true;
        break;
      }
    }

    if (usesSource) {
      for (auto rit = assign->inputs().begin(); rit != assign->inputs().end(); rit++) {
        if (*rit == source) {
          continue;
        }
        bitOperands.insert({assign, *rit});
      }
      source = assign->out();
    }

    switch (id) {
      case e_and:
      case e_or:
      case e_shr:
      case e_sar:
      case e_shl_sal: {
        if (DEBUG_BIT)
          cout << "[bit_var] encountered shift or and instruction: " << assign->format()
               << " " << assign->insn().format() << endl;
        operations.push_back(assign);
      }
        break;
      default:
        if (DEBUG_BIT)
          cout << "[bit_var][warn] Unhandled case: " << assign->format()
               << " " << assign->insn().format() << endl;
    }
  }

  Node::Ptr node = *list.begin();
  SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(node);
  Assignment::Ptr bitVarAssign = aNode->assign();

  std::vector<AbsRegion> oRegions; // FIXME: this is not even used later ...
  //oRegions.push_back(bitVarAssign->out());
  bitVariables.insert({bitVarAssign, oRegions});

  bitOperations.insert({bitVarAssign, operations});

  NodeIterator begin, end;
  slice->entryNodes(begin, end);
  for(NodeIterator it = begin; it != end; ++it) {
    SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(*it);
    Assignment::Ptr assign = aNode->assign();
    if(DEBUG_BIT) cout << "[bit_var] Should ignore? " << assign->format() << " " << assign->insn().format() << endl;
    if (assign == bitVarAssign) continue;
    if(DEBUG_BIT) cout << "[bit_var] Will ignore. " << endl;
    std::vector<AbsRegion> oRegions;
    bitVariablesToIgnore.insert({assign, oRegions});
  }
}

void locateBitVariables(GraphPtr slice,
                        boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariables,
                        boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariablesToIgnore,
                        boost::unordered_map<Assignment::Ptr, AbsRegion> &bitOperands,
                        boost::unordered_map<Assignment::Ptr, std::vector<Assignment::Ptr>> &bitOperations) {

  // Enqueue all the root nodes of the dataflow graph.
  // Need to do reverse post order.
  std::vector<Node::Ptr> list;
  getReversePostOrderList(slice, &list);
  std::reverse(list.begin(), list.end());

  //boost::unordered_set<Assignment::Ptr> visitedVariables;
  for(auto it = list.begin(); it != list.end(); ++it) {
    Node::Ptr node = *it;
    SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(node);
    Assignment::Ptr assign = aNode->assign();
    if (assign == NULL) continue;
    entryID id = assign->insn().getOperation().getID();

    /*
    if (visitedVariables.find(assign) != visitedVariables.end()) {
      if(DEBUG_SLICE) cout << "[slice] " << "Already visited." << endl;
      continue;
    }
    visitedVariables.insert(assign);
    */

    if(DEBUG_BIT) cout << "[bit_var] " << "CHECKING instruction for bit variable: ";
    if(DEBUG_BIT) cout << "[bit_var] " << assign->format() << " ";
    if(DEBUG_BIT) cout << "[bit_var] " << assign->insn().format() << " ";
    if(DEBUG_BIT) cout << "[bit_var] " << id << " ";
    if(DEBUG_BIT) cout << endl;

    bool predeIsIgnored = false;
    bool predeIsBitVar = false;

    std::vector<Assignment::Ptr> operations;

    NodeIterator oBegin, oEnd;
    node->outs(oBegin, oEnd);
    // Checking through predecessors.
    for (NodeIterator it = oBegin; it != oEnd; ++it) {
      SliceNode::Ptr oNode = boost::static_pointer_cast<SliceNode>(*it);
      Assignment::Ptr oAssign = oNode->assign();
      if(DEBUG_BIT) cout << "[bit_var] " << "Dataflow predecessor: ";
      if(DEBUG_BIT) cout << "[bit_var] " << oAssign->format() << " ";
      if(DEBUG_BIT) cout << "[bit_var] " << oAssign->insn().format() << endl;

      if (bitVariablesToIgnore.find(oAssign) != bitVariables.end()) {
        if(DEBUG_BIT) cout << "[bit_var] " << "Assignment might involve a bit variable that should be ignored." << endl;
        std::vector<AbsRegion> regions = bitVariablesToIgnore[oAssign];
        if (std::find(regions.begin(), regions.end(), assign->out()) != regions.end()) {
          predeIsIgnored = true;
          if(DEBUG_BIT) cout << "[bit_var] " << "Assignment involves a bit variable that should be ignored." << endl;
          break;
        }
      }

      if (predeIsIgnored) {
        break;
      }

      if (bitVariables.find(oAssign) != bitVariables.end()) {
        if(DEBUG_BIT) cout << "[bit_var] " << "Assignment might involve a bit variable." << endl;
        std::vector<AbsRegion> regions = bitVariables[oAssign];
        if(DEBUG_BIT) cout << "[bit_var] " << "Current out " << assign->out() << endl;
        if (std::find(regions.begin(), regions.end(), assign->out()) != regions.end()) {
          predeIsBitVar = true;
          if(DEBUG_BIT) cout << "[bit_var] " << "Assignment involves a bit variable." << endl;
          operations = bitOperations[oAssign];
          break;
        }
      }
    }

    if (predeIsIgnored) {
      std::vector<AbsRegion> regions;
      for(auto iit = assign->inputs().begin(); iit != assign->inputs().end(); ++iit) {
        regions.push_back(*iit);
      }
      bitVariablesToIgnore.insert({assign, regions});
      continue;
    }

    if (predeIsBitVar) {
      switch(id) {
        case e_mov: {
          if(DEBUG_BIT) cout << "[bit_var] encountered mov instruction: " << assign->format() << " " << assign->insn().format() << endl;
          std::vector<AbsRegion> regions;
          for(auto iit = assign->inputs().begin(); iit != assign->inputs().end(); ++iit) {
            regions.push_back(*iit);
          }
          bitVariables.insert({assign, regions});
          bitOperations.insert({assign, operations});
        }
          break;
        case e_and:
        case e_shr:
        case e_sar:
        case e_shl_sal: {
          if(DEBUG_BIT) cout << "[bit_var] encountered shift or and instruction: " << assign->format()
                             << " " << assign->insn().format() << endl;
          AbsRegion operand;
          std::vector<AbsRegion> regions;
          if (assign->inputs().size() == 2) {
            //cout << "HERE" << (assign->out() == assign->inputs()[0]) << endl;
            //cout << "HERE" << (assign->out() == assign->inputs()[1]) << endl;
            std::vector<AbsRegion> regionsToIgnore;
            if (assign->out() == assign->inputs()[0]) {
              regions.push_back(assign->inputs()[0]);
              regionsToIgnore.push_back(assign->inputs()[1]);
            } else {
              regions.push_back(assign->inputs()[1]);
              regionsToIgnore.push_back(assign->inputs()[0]);
            }
            bitVariablesToIgnore.insert({assign, regionsToIgnore});
            operand = *regionsToIgnore.begin();

          } else if (assign->inputs().size() == 1) {
            regions.push_back(assign->inputs()[0]);
          } else {
            if(DEBUG_BIT) cout << "[warn][bit_var] Unhandle number of inputs. " << endl;
          }
          bitVariables.insert({assign, regions});

          operations.push_back(assign);
          bitOperations.insert({assign, operations});

          bitOperands.insert({assign, operand});
        }
          break;
        default:
          if(DEBUG_BIT) cout << "[bit_var][warn] Unhandled case: " << assign->format()
                             << " " << assign->insn().format() << endl;
      }
      continue;
    }

    if (id == e_and) { //TODO: OR is not yet handled, should probably handle, but works for this case
      if (DEBUG_BIT) cout << "[bit_var] " << "FOUND an AND instruction, considered a mask: ";

      if(DEBUG_BIT) cout << "[bit_var] " << assign->format() << " ";
      if(DEBUG_BIT) cout << "[bit_var] " << assign->insn().format() << endl;

      std::vector<AbsRegion> regions; // FIXME, should probably get rid of the vector and just store one AbsRegion?
      std::vector<AbsRegion> regionsToIgnore;
      for(auto iit = assign->inputs().begin(); iit != assign->inputs().end(); ++iit) {
        if (*iit == assign->out())
          regions.push_back(*iit);
        else
          regionsToIgnore.push_back(*iit);
      }
      int bitMaskDigits = getBitMaskDigits(assign->insn(), regions);
      cout << "[bit_var] number of digits in bit mask: " << bitMaskDigits << endl;
      if (bitMaskDigits != 1 && bitMaskDigits != -1) {
        cout << "[bit_var][warn] unhandled bit mask... " << endl;
        continue;
      }
      bitVariables.insert({assign, regions});
      bitVariablesToIgnore.insert({assign, regionsToIgnore});

      std::vector<Assignment::Ptr> operations;
      operations.push_back(assign);
      bitOperations.insert({assign, operations});

      AbsRegion operand;
      if (regionsToIgnore.begin() != regionsToIgnore.end()) {
        operand = *regionsToIgnore.begin();
      }
      bitOperands.insert({assign, operand});

      continue;
    }
  }
  //for (auto it = bitVariables.begin(); it != bitVariables.end(); ++it) {
  //  cout << (*it)->format() << endl;
  //}
}

bool findMemoryLoadHelper(Expression::Ptr memWrite,
                          SliceNode::Ptr node,
                          std::vector<Node::Ptr> *list,
                          boost::unordered_set<Assignment::Ptr> &visited) {

  Assignment::Ptr assign = node->assign();
  if (assign == NULL) return false;
  if (visited.find(assign) != visited.end()) {
    if(DEBUG && DEBUG_BIT) cout << "[bit_var] Node already visited, returning ..." << endl;
    return false;
  }
  visited.insert(assign);

  NodeIterator iBegin, iEnd;
  node->ins(iBegin, iEnd);
  // Checking through successors.
  bool containsMemLoad = false;

  Instruction insn = assign->insn();
  std::set<Expression::Ptr> memReads;
  insn.getMemoryReadOperands(memReads);
  if (memReads.size() > 1) {
    if(DEBUG && DEBUG_BIT) cout << "[bit_var] Instruction has more than one memory read? " << insn.format() << endl;
  }
  if(DEBUG && DEBUG_BIT) cout << "[bit_var] Instruction " << insn.format() << " has " << memReads.size() << endl;
  if (memReads.size() == 1) {
    Expression::Ptr memRead = *memReads.begin();
    std::string readStr = memRead->format();
    std::string writeStr = memWrite->format();
    if(DEBUG && DEBUG_BIT) cout << "[bit_var] Read str: " << readStr << endl;
    if(DEBUG && DEBUG_BIT) cout << "[bit_var] Write str: " << writeStr << endl;
    if (readStr.compare(writeStr) == 0) {
      list->push_back(node);
      return true;
    }
  }

  for (NodeIterator it = iBegin; it != iEnd; ++it) {
    SliceNode::Ptr iNode = boost::static_pointer_cast<SliceNode>(*it);
    containsMemLoad = (containsMemLoad == true) ? true : findMemoryLoadHelper(memWrite, iNode, list, visited);
  }
  if (containsMemLoad == true) {
    list->push_back(node);
  }
  return containsMemLoad;
}

void findMemoryLoad(Expression::Ptr memWrite,
                    GraphPtr slice,
                    std::vector<Node::Ptr> *list) { //TODO, give it a better name???
  NodeIterator begin, end;
  slice->exitNodes(begin, end);//Exit nods are the root nodes.
  for (NodeIterator it = begin; it != end; ++it) {
    SliceNode::Ptr iNode = boost::static_pointer_cast<SliceNode>(*it);
    boost::unordered_set<Assignment::Ptr> visited;
    findMemoryLoadHelper(memWrite, iNode, list, visited);
  }
}

int getBitMaskDigits(Instruction insn, std::vector<AbsRegion> &regions) {
  //cout << insn.format() << endl;
  std::vector<Operand> ops;
  insn.getOperands(ops);
  int digits = 0;
  AbsRegionConverter arc(true, false);
  for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
    //cout << (*oit).getValue()->format() << endl;
    std::set<RegisterAST::Ptr> regsRead;
    (*oit).getReadSet(regsRead);
    bool ignore = false;
    for (auto rrit = regsRead.begin(); rrit != regsRead.end(); ++rrit) {
      AbsRegion curr = arc.convert(*rrit);
      if (std::find(regions.begin(), regions.end(), curr) != regions.end()) {
        ignore = true;
      }
    }
    if (ignore)  continue;
    MachRegister machReg;
    long off = 0;
    getRegAndOff((*oit).getValue(), &machReg, &off);
    // TODO: right way to do this is to recurse exhaustively to find constant definitions
    // for now if we don't find any we just return
    if (off == 0) digits = -1;
    while (off > 0) {
      digits += off*0x1;
      off = off >> 1;
    }
  }
  return digits;
}