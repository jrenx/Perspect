#include "dataflow_analysis.hpp"
#include "stack_analysis.hpp"
#include "bitvar_analysis.hpp"
#include "static_df_analysis.hpp"
#include "util.hpp"

#include <stdio.h>
#include <iostream>
#include <fstream>

#include <vector>
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>
#include <boost/heap/priority_queue.hpp>
#include <boost/algorithm/string.hpp>

#include "cJSON.h"

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

void backwardSliceHelper(vector<Function *> *allFuncs,
                         cJSON *json_reads, boost::unordered_set<Address> &visited,
                         char *funcName,
                         long unsigned int addr, char *regName, bool reversedOnce,
                         bool isKnownBitVar, bool atEndPoint,
                         boost::unordered_map<Assignment::Ptr, AbsRegion>* prevBitOperands,
                         std::vector<std::vector<Assignment::Ptr>>* prevOperationses) {

  if (INFO) cout << endl;
  if (INFO) cout << "[sa] -------------------------------" << endl;
  if (INFO) cout << "[sa] Making a backward slice: " << endl;
  if (INFO) cout << "[sa] func: " << funcName << endl;
  if (INFO) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if (INFO) cout << "[sa] reversed at least once " << reversedOnce << endl;
  if (INFO) cout << "[sa] is known bit var " << isKnownBitVar << endl;
  if (INFO) cout << "[sa] at end point " << atEndPoint << endl;

  if (visited.find(addr) != visited.end()) {
    if (INFO) cout << "[sa] address already visited, returning... " << endl;
    return;
  }
  visited.insert(addr);

  Function *func = getFunction2(allFuncs, funcName, addr);
  Block *bb = getBasicBlock2(func, addr);
  Instruction insn = bb->getInsn(addr);

  if (strcmp(regName, "[x86_64::special]") == 0) {
    bool foundMemRead = false;
    std::set<Expression::Ptr> memReads;
    insn.getMemoryReadOperands(memReads);
    if (memReads.size() > 0) foundMemRead = true;
    if (!foundMemRead) {
      regName = (char *) getLoadRegName(insn).c_str();
    } else {
      const char *empty = "";
      regName = (char*)empty;
    }
  }

  if (INFO) cout << "[sa] insn: " << insn.format() << endl;
  if (INFO) cout << "[sa] reg: " << regName << endl;
  if (INFO) cout << endl;

  bool madeProgress = true;
  GraphPtr slice = buildBackwardSlice(func, bb, insn, addr, regName, &madeProgress, atEndPoint);
  bool inputInsnReadsFromStack = false;
  bool pendingDefInNewFunction = false;
  if (!isKnownBitVar) {
    MachRegister stackReadReg;
    long stackReadOff;
    inputInsnReadsFromStack = readsFromStack(insn, addr, &stackReadReg, &stackReadOff);
    cout << "[sa] input instruction reads from stack? " << inputInsnReadsFromStack << endl;

    // Handle register definitions in other functions.
    if (!inputInsnReadsFromStack) {
      // If 1. a valid register name is passed,
      //    2. we have not been able to find a definition locally
      //    3. and the stop slicing flag has not been set
      if (strcmp(regName, "") != 0 && !madeProgress && !atEndPoint) {
        AssignmentConverter ac(true, false);
        vector <Assignment::Ptr> assignments;
        ac.convert(insn, addr, func, bb, assignments);
        AbsRegion targetRegion;
        bool targetRegionFound = false;
        Assignment::Ptr assign = assignments[0];
        for (auto rit = assign->inputs().begin(); rit != assign->inputs().end(); rit++) {
          if ((*rit).format().compare(regName) == 0) {
            targetRegion = *rit;
            targetRegionFound = true;
            break;
          }
        }
        if (CRASH_ON_ERROR) assert(targetRegionFound);
        else {
          if (!targetRegionFound) {
            cout << "[sa][BUG] target not found, returning...";
            return;
          }
        }
        boost::unordered_map < Address, Function * > ret;
        boost::unordered_set <Address> visitedAddrs;
        handleRegDefInCallees(targetRegion, addr, bb, func, ret, visitedAddrs);
        cout << "[sa]  found " << ret.size() << " defs in callees" << endl;

        int old_ret_size = ret.size();
        if (USE_X86_CALLING_CONVENTION) {
          cout << "[sa] Is using x86 calling convention, checking the definition of the register in caller function." << endl;
          if (strcmp(regName, "[x86_64::rdi]") == 0  ||
              strcmp(regName, "[x86_64::rsi]") == 0 ||
              strcmp(regName, "[x86_64::rdx]") == 0 ||
              strcmp(regName, "[x86_64::rcx]") == 0 ||
              strcmp(regName, "[x86_64::r8]") == 0 ||
              strcmp(regName, "[x86_64::r9]") == 0) {
              visitedAddrs.clear();
              handleRegDefInCallers(targetRegion, addr, bb, func, ret, visitedAddrs, false);
          }
        }
        cout << "[sa]  found " << (ret.size() - old_ret_size) << " defs in callers" << endl;
        if (!reversedOnce) {
          for (auto rit = ret.begin(); rit != ret.end(); rit++) {
            Function *newFunc = (*rit).second;
            char *newFuncName = (char *) newFunc->name().c_str();
            bool atEndPoint = strcmp(newFuncName, funcName) != 0;
            //TODO, in the future just return the instructions as well...
            Address newAddr = (*rit).first;

            bool foundMemRead = false;
            Block *newBB = getBasicBlock2(newFunc, newAddr);
	        if (!CRASH_ON_ERROR) {
	          if (newBB == NULL) {
	            cout << "[sa/warn] BB is not found for addr: " << hex << newAddr << dec << endl;
	            return;
	          }
	        }
            Instruction newInsn = newBB->getInsn(newAddr);
            std::set<Expression::Ptr> memReads;
            newInsn.getMemoryReadOperands(memReads);
            if (memReads.size() > 0) foundMemRead = true;

            std::string newRegStr = getLoadRegName(newInsn);
            if (foundMemRead) atEndPoint = true;
            char *newRegName = (char *) newRegStr.c_str();
            // TODO, in the future even refactor the signature of the backwardSliceHelper function ...
            backwardSliceHelper(allFuncs, json_reads, visited, newFuncName, newAddr, newRegName, true, isKnownBitVar, atEndPoint);
          }
          return;
        } else {
          cout << "[sa]  persisting intermediate results instead of pass by reference defs " << endl;
          atEndPoint = true;
          pendingDefInNewFunction = true;
        }
      }
    }
  }

  boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> bitVariables;
  boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> bitVariablesToIgnore;
  boost::unordered_map<Assignment::Ptr, AbsRegion> bitOperands;
  boost::unordered_map<Assignment::Ptr, std::vector<std::vector<Assignment::Ptr>>> bitOperationses;
  if (!isKnownBitVar) {
    locateBitVariables(slice, bitVariables, bitVariablesToIgnore, bitOperands, bitOperationses);
  } else {
    std::set<Expression::Ptr> memWrites;
    insn.getMemoryWriteOperands(memWrites);
    if (memWrites.size() != 1) {
      cout << "[sa][warn] Instruction does not have exactly one memory write? " << insn.format()
              << " number of writes " << memWrites.size() << endl;
    }
    assert(memWrites.size() == 1);
    analyzeKnownBitVariables(slice, *memWrites.begin(), bitVariables, bitVariablesToIgnore, bitOperands,
                             bitOperationses);
  } // TODO propogate the bit operands.

  // get all the leaf nodes.
  NodeIterator begin, end;
  if (!atEndPoint && !inputInsnReadsFromStack) slice->entryNodes(begin, end);
  else slice->exitNodes(begin, end);

  for(NodeIterator it = begin; it != end; ++it) {
    SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(*it);
    Assignment::Ptr assign = aNode->assign();
    if (assign == NULL) continue;
    cout << assign->format() << " " << assign->insn().format() << " " << assign->insn().getOperation().getID() << " " << endl;
    //if (!atEndPoint && !assign->insn().readsMemory()) continue;

    if(INFO) cout << endl;
    if(INFO) cout << "[sa] In result slice: " << endl;
    if(INFO) cout << "[sa]" << assign->format() << " ";
    if(INFO) cout << "insn: " << assign->insn().format() << " ";
    if(INFO) cout << "addr: " << std::hex << assign->addr() << std::dec << endl;

    bool isBitVar = bitVariables.find(assign) != bitVariables.end();
    if (prevOperationses != NULL) isBitVar = true;
    bool isIgnoredBitVar = bitVariablesToIgnore.find(assign) != bitVariablesToIgnore.end();

    if(INFO) cout << "is bit var: " << isBitVar  << " ";
    if(INFO) cout << "is ignored bit var: " << isIgnoredBitVar  << " ";
    if(INFO) cout << endl;

    if (isIgnoredBitVar) {
      if(INFO) cout << "do not persist read because variable is an ignored bit variable " << endl;
      continue;
    }

    // Handle reads from stack and stack addresses
    // TODO, technically for both below scenarios should verify with RR cuz no guarantee there's no other writes
    //       low prioirty for now.
    if (!atEndPoint) {
      MachRegister readReg;
      long readOff;
      if (readsFromStack(assign->insn(), assign->addr(), &readReg, &readOff)) {
        cout << "[sa] result of slicing is reading from stack, perform stack analysis..." << endl;
        boost::unordered_map<Address, Function *> stackWrites = checkAndGetStackWrites(func, assign->insn(),
                                                                                       assign->addr(), readReg, readOff,
                                                                                       0);
        cout << "[sa]  found " << stackWrites.size() << " stack writes " << endl;
        for (auto stit = stackWrites.begin(); stit != stackWrites.end(); stit++) {
          Function *newFunc = (*stit).second;
          char *newFuncName = (char *) newFunc->name().c_str();
          bool atEndPoint = strcmp(newFuncName, funcName) != 0;

          if (!atEndPoint || !reversedOnce) {
            Address newAddr = (*stit).first;
            bool foundMemRead = false;
            Block *newBB = getBasicBlock2(newFunc, newAddr);
            Instruction newInsn = newBB->getInsn(newAddr);
            std::set <Expression::Ptr> memReads;
            newInsn.getMemoryReadOperands(memReads);
            if (memReads.size() > 0) foundMemRead = true;

            std::string newRegStr = getLoadRegName(newInsn);
            if (foundMemRead) atEndPoint = true;
            char *newRegName = (char *) newRegStr.c_str();
            backwardSliceHelper(allFuncs, json_reads, visited, newFuncName, newAddr, newRegName, true,
                                isKnownBitVar, atEndPoint,
                                isBitVar?(&bitOperands):NULL, isBitVar?(&bitOperationses[assign]):NULL);
          } else {
            pendingDefInNewFunction = true;
          }
        }
        if (stackWrites.size() > 0 && !pendingDefInNewFunction) continue;
      } else if (readsFromStaticAddr(assign->insn(), assign->addr(),
                                     &readOff)) { //FIXME: currently only reads from same function.
        // Assume static writes are always in the same function.... TODO fix this
        cout << "[sa] result of slicing is reading from static addr, looking for writes to static addrs..." << endl;
        boost::unordered_set<Address> writesToStaticAddrs = checkAndGetWritesToStaticAddrs(
            func, assign->insn(), assign->addr(), readOff); //TODO, make this interprocedural too?
        cout << " [sa]  found " << writesToStaticAddrs.size() << " writes to static addresses " << endl;
        const char *empty = "";
        for (auto wit = writesToStaticAddrs.begin(); wit != writesToStaticAddrs.end(); wit++) {
          backwardSliceHelper(allFuncs, json_reads, visited, funcName, *wit, (char *)empty, true, isKnownBitVar);
        }
        continue;
      }
    }
    if (INFO) cout << "[sa] checking result instruction: " << assign->insn().format() << endl;

    bool memReadFound = false, regFound = false;
    std::string readStr = getMemReadStrIfNotRegReadStr(assign->insn(), &memReadFound, &regFound);
    if (!memReadFound && !regFound) {
      if (INFO) cout << "[sa] result is a constant load, ignore" << endl;
      continue;
    }
    if (INFO) cout << "[sa] => Instruction addr: " << std::hex << assign->addr() << std::dec << endl;
    if (INFO) cout << "[sa] => Function: " << funcName << endl;
    if (INFO) cout << "[sa] => Read expr: " << readStr << endl;
    if (INFO) cout << "[sa] => Read same as write: " << (isKnownBitVar ? 1 : 0) << endl; // TODO maybe fix this
    if (INFO) cout << "[sa] => Is bit var: " << isBitVar << endl;
    cJSON *json_read = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_read, "insn_addr", assign->addr());
    cJSON_AddStringToObject(json_read, "expr", readStr.c_str());
    cJSON_AddStringToObject(json_read, "func", funcName);
    cJSON_AddNumberToObject(json_read, "read_same_as_write", isKnownBitVar ? 1 : 0); // TODO, see analyzeKnownBitVariables for proper way to handle this

    std::vector<Operand> ops;
    insn.getOperands(ops);
    MachRegister reg;
    for (auto oit = ops.rbegin(); oit != ops.rend(); oit++) {
      //bool isRegWrittenOnly = !(*oit).isRead() && (*oit).isWritten() && !(*oit).readsMemory() && !(*oit).writesMemory();
      bool isRegWrittenOnly = (*oit).isWritten() && !(*oit).readsMemory() && !(*oit).writesMemory();
      if (!isRegWrittenOnly) continue;
      std::vector<MachRegister> regs;
      long off = 0;
      getRegAndOff((*oit).getValue(), regs, &off);
      if (off != 0) continue;
      if (regs.size() != 1) continue;
      reg = regs[0];
    }
    cJSON_AddStringToObject(json_read, "dst", reg != InvalidReg ? reg.name().c_str() : "");
    if (pendingDefInNewFunction)
      cJSON_AddNumberToObject(json_read, "intermediate_def", 1);
    if (isBitVar) {
      std::vector<std::vector<Assignment::Ptr>> *operationses;
      if (prevOperationses != NULL) {
        operationses = prevOperationses;
        bitOperands = *prevBitOperands;
      }
      else operationses = &(bitOperationses[assign]);
      if (INFO) cout << "[sa] bit operations: " << endl;
      cJSON_AddNumberToObject(json_read, "is_bit_var",  1);
      cJSON *json_bitOpses = cJSON_CreateArray();
      for (auto osit = operationses->begin(); osit != operationses->end(); ++osit) {
        cJSON *json_bitOps = cJSON_CreateArray();
        for (auto oit = (*osit).begin(); oit != (*osit).end(); ++oit) {
          cJSON *json_bitOp  = cJSON_CreateObject();
          Assignment::Ptr opAssign = (*oit);
          if (INFO) cout << "	operation: " << opAssign->format() << opAssign->insn().format();
          if (bitOperands.find(opAssign) != bitOperands.end()) {
            if (INFO) cout << "	operand: " << bitOperands[opAssign].format();
          } else {
            cout << "[warn] Bit operand not found? " << endl;		
            continue;
          }
          if (INFO) cout << endl;
          cJSON_AddNumberToObject(json_bitOp, "insn_addr", opAssign->addr());
	  string operandStr = findMatchingOpExprStr(opAssign, bitOperands[opAssign]);
	  cout << "[sa] operand str: "<< operandStr << endl;
          cJSON_AddStringToObject(json_bitOp, "operand", operandStr.c_str());
          cJSON_AddStringToObject(json_bitOp, "operation", opAssign->insn().getOperation().format().c_str());
          cJSON_AddItemToArray(json_bitOps, json_bitOp);
        }
        cJSON_AddItemToArray(json_bitOpses,  json_bitOps);
      }
      cJSON_AddItemToObject(json_read, "bit_operationses",  json_bitOpses);

    } else {
      cJSON_AddNumberToObject(json_read, "is_bit_var",  0);
    }
    cJSON_AddItemToArray(json_reads, json_read);
  }
}

GraphPtr buildBackwardSlice(Function *f, Block *b, Instruction insn, long unsigned int addr, char *regName,
                            bool *madeProgress, bool atEndPoint) {

  // Convert the instruction to assignments
  AssignmentConverter ac(true, false);
  vector<Assignment::Ptr> assignments;
  ac.convert(insn, addr, f, b, assignments);

  // An instruction can corresponds to multiple assignments
  if (INFO) cout << endl << "[slice] " << " Finding all assignments of the instruction: "
                 << insn.format() << endl;
  Assignment::Ptr assign; //TODO, how to handle multiple ones?
  for (auto ait = assignments.begin(); ait != assignments.end(); ++ait) {
    if(INFO) cout << "[slice] " << "assignment: " << (*ait)->format() << endl;
    assign = *ait;
  }
  if(DEBUG_SLICE) cout << endl;

  Slicer s(assign, b, f, true, false);
  CustomSlicer cs;
  bool filter = false;
  if (strcmp(regName, "") != 0) {
    cs.regName = regName;
    filter = true;
    cs.filter = true;
  }
  cs.insn = insn;
  cs.atEndPoint = atEndPoint;
  GraphPtr slice = s.backwardSlice(cs);
  //cout << slice->size() << endl;
  string filePath("/home/anygroup/perf_debug_tool/binary_analysis/graph"); //TODO, put the right path here
  slice->printDOT(filePath);
  if (filter && !cs.foundFilteredReg) *madeProgress = false;
  if (!cs.slicedMoreThanOneStep) *madeProgress = false;
  return slice;
}

void handleRegDefInCallers(AbsRegion targetReg, Address startAddr,
                           Block *startBb, Function *startFunc,
                           boost::unordered_map<Address, Function*> &ret,
                           boost::unordered_set<Address> &visitedAddrs,
                           bool recursedOnce) { // TODO add to declaration

  //if (DEBUG)
  cout << "[def-in-caller] Checking for defs in function " << startFunc->name() << endl;
  if (visitedAddrs.find(startAddr) != visitedAddrs.end()) {
    if (DEBUG) cout << "[def-in-caller] Already visited, returning " << endl;
    return;
  }
  visitedAddrs.insert(startAddr);

  std::vector<Block *> list;
  boost::unordered_set<Block *> visited;
  getReversePostOrderListHelper(startFunc->entry(), list, visited);
  //std::reverse(list.begin(), list.end());

  boost::unordered_set<Block *> checked;
  AssignmentConverter ac(true, false);
  for (auto bit = list.begin(); bit != list.end(); bit++) {
    bool checkBB = false;
    Block *bb = *bit;
    if (bb == startBb) {
      checkBB = true;
    } else {
      if (checked.size() == 0) continue;

      Block::edgelist targets = bb->targets();
      for (auto it = targets.begin(); it != targets.end(); it++) {
        if ((*it)->type() == CALL || (*it)->type() == RET || (*it)->type() == CATCH)
          continue;
        Block* src = (*it)->src();
        Block* trg = (*it)->trg();
        if (checked.find(trg) != checked.end()) {
          checkBB = true;
          break;
        }
      }
    }

    if (!checkBB) continue;

    Block::Insns insns;
    bb->getInsns(insns);
    auto it = insns.rbegin();
    if (bb == startBb) {
      for (; it != insns.rend(); it++) {
        Address addr = (*it).first;
        Instruction insn = (*it).second;
        if (addr == startAddr) {
          it++;
          break;
        }
      }
    }
    bool foundDef = false;
    for (; it != insns.rend(); it++) {
      Address addr = (*it).first;
      Instruction insn = (*it).second;
      // if assignment assigns the register, stop here, return the assignment
      vector<Assignment::Ptr> assignments;
      ac.convert(insn, addr, startFunc, bb, assignments);
      for (auto ait = assignments.begin(); ait != assignments.end(); ++ait) {
        Assignment::Ptr assign = *ait;
        if (assign->out() == targetReg) {
          //if (DEBUG)
          cout << "[def-in-caller] Found matching def " << assign->format() << endl;
          ret.insert({assign->addr(), startFunc});
          foundDef = true;
        }
      }
      if (foundDef) break;
    }
    if (foundDef) continue;
    Block::edgelist sources = bb->sources();
    for (auto it = sources.begin(); it != sources.end(); it++) {
      if ((*it)->type() == RET || (*it)->type() == CATCH || (*it)->type() == FALLTHROUGH ||
          (*it)->type() == CALL_FT)
        continue;
      Block *src = (*it)->src();
      std::vector<Function *> funcs;
      src->getFuncs(funcs);
      for (auto fit = funcs.begin(); fit != funcs.end(); fit++) {
        Function *caller = *fit;
        boost::unordered_set<Address> CallsiteAddrs;
        getAllInvokes(caller, startFunc, CallsiteAddrs); // TODO verify this
        cout << CallsiteAddrs.size() << endl;
        for (auto cait = CallsiteAddrs.begin(); cait != CallsiteAddrs.end(); cait++) {
          Address CallsiteAddr = *cait;
          Block *CallsiteBlock = getBasicBlock2(caller, CallsiteAddr);
          int old_size = ret.size();
          handleRegDefInCallers(targetReg, CallsiteAddr, CallsiteBlock, caller, ret, visitedAddrs, true);
          int new_size = ret.size();
          if (new_size > old_size) foundDef = true;
          else assert(new_size == old_size);
        }
      }
    }
    if (!foundDef) checked.insert(bb);
  }
}

// Check for instructions that define a given register represented by targetReg
// If the definition is not found, follow returns in the current function
// to recursively check callee functions for definitions.
// Inside each function, essentially does a backward traversal from the use point, or the return statement.
// To ensure any definition found is reachable by the use point or return statement,
// Only check predecessors of the basic block containing the use point or return statement.
// Once a definition is found, stop checking any control flow predecessor of the basic block containing the definition.
void handleRegDefInCallees(AbsRegion targetReg, Address startAddr,
                           Block *startBb, Function *startFunc,
                           boost::unordered_map<Address, Function*> &ret,
                           boost::unordered_set<Address> &visitedAddrs) { // TODO add to declaration

  if (DEBUG) cout << "[def-in-callee] Checking for pass by reference def in function " << startFunc->name() << endl;
  if (visitedAddrs.find(startAddr) != visitedAddrs.end()) {
    if (DEBUG) cout << "[def-in-callee] Already visited, returning " << endl;
    return;
  }
  visitedAddrs.insert(startAddr);

  std::vector<Block *> list;
  boost::unordered_set<Block *> visited;
  getReversePostOrderListHelper(startFunc->entry(), list, visited);
  //std::reverse(list.begin(), list.end());

  boost::unordered_set<Block *> checked;
  AssignmentConverter ac(true, false);
  for (auto bit = list.begin(); bit != list.end(); bit++) {
    bool checkBB = false;
    Block *bb = *bit;
    if (bb == startBb) {
      checkBB = true;
    } else {
      if (checked.size() == 0) continue;

      Block::edgelist targets = bb->targets();
      for (auto it = targets.begin(); it != targets.end(); it++) {
        if ((*it)->type() == CALL || (*it)->type() == RET || (*it)->type() == CATCH)
          continue;
        Block* src = (*it)->src();
        Block* trg = (*it)->trg();
        if (checked.find(trg) != checked.end()) {
          checkBB = true;
          break;
        }
      }
    }

    if (!checkBB) continue;

    Block::Insns insns;
    bb->getInsns(insns);
    auto it = insns.rbegin();
    if (bb == startBb) {
      for (; it != insns.rend(); it++) {
        Address addr = (*it).first;
        Instruction insn = (*it).second;
        if (addr == startAddr) {
          it++;
          break;
        }
      }
    }
    bool foundDef = false;
    for (; it != insns.rend(); it++) {
      Address addr = (*it).first;
      Instruction insn = (*it).second;
      // if assignment assigns the register, stop here, return the assignment
      vector<Assignment::Ptr> assignments;
      ac.convert(insn, addr, startFunc, bb, assignments);
      for (auto ait = assignments.begin(); ait != assignments.end(); ++ait) {
        Assignment::Ptr assign = *ait;
        if (assign->out() == targetReg) {
          if (DEBUG) cout << "[def-in-callee] Found matching def " << assign->format() << endl;
          ret.insert({assign->addr(), startFunc});
          foundDef = true;
        }
      }
      if (foundDef) break;

      entryID id = insn.getOperation().getID();
      if (id == e_call || id == e_callq) {
        Block::edgelist targets = bb->targets();
        for (auto tit = targets.begin(); tit != targets.end(); tit++) {
          if ((*tit)->type() != CALL)
            continue;
          Block *trg = (*tit)->trg();
          std::vector<Function *> funcs;
          trg->getFuncs(funcs);
          Function * func = getFunction(funcs);
          if (func == NULL) continue;
          boost::unordered_set<std::pair<Address, Block *>> retInsns;
          getAllRets(func, retInsns);
          for (auto rit = retInsns.begin(); rit != retInsns.end(); rit++) {
            int old_size = ret.size();
            handleRegDefInCallees(targetReg, (*rit).first, (*rit).second, func, ret, visitedAddrs);
            int new_size = ret.size();
            if (new_size > old_size) foundDef = true;
            else assert(new_size == old_size);
          }
        }
      }
    }
    if (!foundDef) checked.insert(bb);
  }
}
/*
// TODO, is this the right name?
void getReversePostOrderListHelper(Node::Ptr node,
                                   std::vector<Node::Ptr> *list,
                                   boost::unordered_set<Node::Ptr> &visited) {
  if (visited.find(node) != visited.end()) {
    return;
  }
  visited.insert(node);
  NodeIterator iBegin, iEnd;
  node->ins(iBegin, iEnd);
  // Checking through successors.
  for (NodeIterator it = iBegin; it != iEnd; ++it) {
    SliceNode::Ptr iNode = boost::static_pointer_cast<SliceNode>(*it);
    getReversePostOrderListHelper(iNode, list, visited);
  }
  list->push_back(node);
}

void getReversePostOrderList(GraphPtr slice,
                             std::vector<Node::Ptr> *list) {
  boost::unordered_set<Node::Ptr> visited;
  NodeIterator begin, end;
  slice->exitNodes(begin, end);//Exit nods are the root nodes.
  for (NodeIterator it = begin; it != end; ++it) {
    getReversePostOrderListHelper(*it, list, visited);
  }
}
*/
std::string findMatchingOpExprStr(Assignment::Ptr assign, AbsRegion region) {
  AbsRegion curr;
  AbsRegionConverter arc(true, false);

  std::set<RegisterAST::Ptr> regsRead;
  assign->insn().getReadSet(regsRead);

  for (auto i = regsRead.begin(); i != regsRead.end(); ++i) {
    if (DEBUG_BIT)  cout << "[bit_var] reg read: " << (*i)->format() << endl;
    /*
    if(assign->insn().getArch() == Arch_aarch64) {
      MachRegister machReg = (*i)->getID();
      std::vector<MachRegister> flagRegs = {aarch64::n, aarch64::z, aarch64::c, aarch64::v};
      if((machReg & 0xFF) == (aarch64::pstate & 0xFF) && (machReg & 0xFF0000) == (aarch64::SPR)) {
        for(std::vector<MachRegister>::iterator itr = flagRegs.begin(); itr != flagRegs.end(); itr++) {
          curr = arc.convert(RegisterAST::Ptr(new RegisterAST(*itr)));
        }
      } else {
        curr = arc.convert(*i);
      }
    } else {
      curr = arc.convert(*i);
    }*/
    curr = arc.convert(*i);
    if (curr == region) {
      return (*i)->format();
    }
  }

  /*
  if (assign->insn().readsMemory()) {
    std::set<Expression::Ptr> memReads;
    assign->insn().getMemoryReadOperands(memReads);
    for (std::set<Expression::Ptr>::const_iterator r = memReads.begin();
         r != memReads.end();
         ++r) {
      curr = arc.convert(*r, assign->addr(), assign->func(), assign->block());
    }
  }*/

  std::vector<Operand> ops;
  assign->insn().getOperands(ops);
  for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
    std::set<RegisterAST::Ptr> regsRead;
    (*oit).getReadSet(regsRead);
    if (regsRead.size() > 0) continue;

    std::set<RegisterAST::Ptr> regsWrite;
    (*oit).getWriteSet(regsWrite);
    if (regsWrite.size() > 0) continue;

    if (DEBUG_BIT) cout << "[bit_var] Is constant: " << (*oit).getValue()->format() << endl;
    return (*oit).getValue()->format();
  }
}

std::string getMemReadStrIfNotRegReadStr(Instruction insn, bool *memReadFound, bool *regFound) {
  // TODO, refactor this function!
  Expression::Ptr read;
  std::string readStr;

  std::set<Expression::Ptr> memReads;
  insn.getMemoryReadOperands(memReads);
  if (memReads.size() > 0) { // prioritize reads from memory
    *memReadFound = true;
    if (CRASH_ON_ERROR) assert(memReads.size() == 1);
    else {
      if (memReads.size() > 1) {
        cout << "[sa/warn] Instruction has multiple reads, just handling one for now: ";
        cout << insn.format() << endl;	
      }
    }
    Expression::Ptr read = *memReads.begin();
    if (INFO) cout << "[sa] Memory read: " << read->format() << endl;
    readStr.append("memread|");
    readStr.append(read->format());
  } else { // then check reads from register
    *memReadFound = false;
    int readCount = 0;
    std::vector<Operand> ops;
    insn.getOperands(ops);

    for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
      if (insn.isRead((*oit).getValue())) {
        read = (*oit).getValue();

        MachRegister machReg; long off=0;
        getRegAndOff(read, &machReg, &off); //TODO, sometimes, even non mem reads can have an offset?
        if (machReg != InvalidReg && off == 0) *regFound = true;

        if (INFO) cout << "[sa] current read: " << read->format() << endl;
        readCount++;
      }
    }
    if (INFO) cout << "[sa] total number of reads: " << readCount << endl;
    if (readCount == 1) {
      readStr.append("regread|");
      readStr.append(read->format());
    } else {
      if (INFO) cout << "[sa][warn] multiple reads! " << endl;
    }
  }
  return readStr;
}
