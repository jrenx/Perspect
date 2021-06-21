#include "dataflow_analysis.hpp"
#include "stack_analysis.hpp"
#include "bitvar_analysis.hpp"
#include "static_df_analysis.hpp"

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

boost::unordered_map<std::string, std::string> regMap =
    {{"al"  ,"rax"}, {"ah"  ,"rax"}, {"ax"  ,"rax"}, {"eax","rax"},
     {"bl"  ,"rbx"}, {"bh"  ,"rbx"}, {"bx"  ,"rbx"}, {"ebx","rbx"},
     {"cl"  ,"rcx"}, {"ch"  ,"rcx"}, {"cx"  ,"rcx"}, {"ecx","rcx"},
     {"dl"  ,"rdx"}, {"dh"  ,"rdx"}, {"dx"  ,"rdx"}, {"edx","rdx"},
     {"sil" ,"rsi"}, {"si"  ,"rsi"}, {"esi" ,"rsi"},
     {"dil" ,"rdi"}, {"di"  ,"rdi"}, {"edi" ,"rdi"},
     {"bpl" ,"rbp"}, {"bp"  ,"rbp"}, {"ebp" ,"rbp"},
     {"spl" ,"rsp"}, {"sp"  ,"rsp"}, {"esp" ,"rsp"},
     {"r8b" , "r8"}, {"r8w" , "r8"}, {"r8d" , "r8"},
     {"r9b" , "r9"}, {"r9w" , "r9"}, {"r9d" , "r9"},
     {"r10b","r10"}, {"r10w","r10"}, {"r10d","r10"},
     {"r11b","r11"}, {"r11w","r11"}, {"r11d","r11"},
     {"r12b","r12"}, {"r12w","r12"}, {"r12d","r12"},
     {"r13b","r13"}, {"r13w","r13"}, {"r13d","r13"},
     {"r14b","r14"}, {"r14w","r14"}, {"r14d","r14"},
     {"r15b","r15"}, {"r15w","r15"}, {"r15d","r15"}};

void backwardSliceHelper(SymtabCodeSource *stcs, CodeObject *co,
                         cJSON *json_reads, boost::unordered_set<Address> &visited,
                         char *progName, char *funcName,
                         long unsigned int addr, char *regName, bool isKnownBitVar, bool atEndPoint) {

  if (INFO) cout << endl;
  if (INFO) cout << "[sa] -------------------------------" << endl;
  if (INFO) cout << "[sa] Making a backward slice: " << endl;
  if (INFO) cout << "[sa] prog: " << progName << endl;
  if (INFO) cout << "[sa] func: " << funcName << endl;
  if (INFO) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;

  if (visited.find(addr) != visited.end()) {
    if (INFO) cout << "[sa] address already visited, returning... " << endl;
    return;
  }
  visited.insert(addr);

  Function *func = getFunction2(stcs, co, funcName);
  Block *bb = getBasicBlock2(func, addr);
  Instruction insn = bb->getInsn(addr);

  if (strcmp(regName, "[x86_64::special]") == 0) {
    bool foundMemRead = false;
    std::string newRegStr = getLoadRegName(insn, &foundMemRead);
    if (!foundMemRead) {
      regName = (char *) newRegStr.c_str();
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
  if (!isKnownBitVar) {
    MachRegister stackReadReg;
    long stackReadOff;
    inputInsnReadsFromStack = readsFromStack(insn, addr, &stackReadReg, &stackReadOff);
    cout << "[sa] input instruction reads from stack? " << inputInsnReadsFromStack << endl;
    if (!inputInsnReadsFromStack) {
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
        assert(targetRegionFound);
        boost::unordered_map < Address, Function * > ret;
        boost::unordered_set <Address> visitedAddrs;
        handlePassByReference(targetRegion, addr, bb, func, ret, visitedAddrs);
        cout << "[sa]  found " << ret.size() << " pass by reference defs " << endl;
        for (auto rit = ret.begin(); rit != ret.end(); rit++) {
          Function *newFunc = (*rit).second;
          char *newFuncName = (char *) newFunc->name().c_str();
          bool atEndPoint = strcmp(newFuncName, funcName) != 0;
          //TODO, in the future just return the instructions as well...
          Address newAddr = (*rit).first;

          bool foundMemRead = false;
          std::string newRegStr = getLoadRegName(newFunc, newAddr, &foundMemRead);
          if (foundMemRead) atEndPoint = true;
          char *newRegName = (char *) newRegStr.c_str();
          // TODO, in the future even refactor the signature of the backwardSliceHelper function ...
          backwardSliceHelper(stcs, co, json_reads, visited, progName, newFuncName, newAddr, newRegName, isKnownBitVar,
                              atEndPoint);
        }
        return;
      }
    }
  }

  boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> bitVariables;
  boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> bitVariablesToIgnore;
  boost::unordered_map<Assignment::Ptr, AbsRegion> bitOperands;
  boost::unordered_map<Assignment::Ptr, std::vector<Assignment::Ptr>> bitOperations;
  if (!isKnownBitVar) {
    locateBitVariables(slice, bitVariables, bitVariablesToIgnore, bitOperands, bitOperations);
  } else {
    std::set<Expression::Ptr> memWrites;
    insn.getMemoryWriteOperands(memWrites);
    if (memWrites.size() != 1) {
      cout << "[sa][warn] Instruction does not have exactly one memory write? " << insn.format()
              << " number of writes " << memWrites.size() << endl;
    }
    assert(memWrites.size() == 1);
    analyzeKnownBitVariables(slice, *memWrites.begin(), bitVariables, bitVariablesToIgnore, bitOperands,
                             bitOperations);
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

    if(DEBUG) cout << endl;
    if(INFO) cout << "[sa] In result slice: " << endl;
    if(INFO) cout << "[sa]" << assign->format() << " ";
    if(INFO) cout << "insn: " << assign->insn().format() << " ";
    if(INFO) cout << "addr: " << std::hex << assign->addr() << std::dec << endl;

    bool isBitVar = bitVariables.find(assign) != bitVariables.end();
    bool isIgnoredBitVar = bitVariablesToIgnore.find(assign) != bitVariablesToIgnore.end();

    if(INFO) cout << "is bit var: " << isBitVar  << " ";
    if(INFO) cout << "is ignored bit var: " << isIgnoredBitVar  << " ";
    if(INFO) cout << endl;

    if (isIgnoredBitVar) {
      if(INFO) cout << "do not persist read because variable is an ignored bit variable " << endl;
      continue;
    }

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
          Address newAddr = (*stit).first;

          bool foundMemRead = false;
          std::string newRegStr = getLoadRegName(newFunc, newAddr, &foundMemRead);
          if (foundMemRead) atEndPoint = true;
          char * newRegName = (char *)newRegStr.c_str();
          backwardSliceHelper(stcs, co, json_reads, visited, progName, newFuncName, newAddr, newRegName, isKnownBitVar, atEndPoint);
        }
        if (stackWrites.size() > 0) continue;
      } else if (readsFromStaticAddr(assign->insn(), assign->addr(),
                                     &readOff)) { //FIXME: currently only reads from same function.
        cout << "[sa] result of slicing is reading from static addr, looking for writes to static addrs..." << endl;
        boost::unordered_set<Address> writesToStaticAddrs = checkAndGetWritesToStaticAddrs(
            func, assign->insn(), assign->addr(), readOff); //TODO, make this interprocedural too?
        cout << " [sa]  found " << writesToStaticAddrs.size() << " writes to static addresses " << endl;
        for (auto wit = writesToStaticAddrs.begin(); wit != writesToStaticAddrs.end(); wit++) {
          const char *empty = "";
          backwardSliceHelper(stcs, co, json_reads, visited, progName, funcName, *wit, (char *)empty, isKnownBitVar);
        }
        continue;
      }
    }

    if (INFO) cout << "[sa] checking result instruction: " << assign->insn().format() << endl;

    bool memReadFound = false, regFound = false;
    std::string readStr = getReadStr(assign->insn(), &memReadFound, &regFound);
    if (!memReadFound && !regFound) {
      if (INFO) cout << "[sa] result is a constant load, ignore" << endl;
      continue;
    }
    if (INFO) cout << "[sa] => Instruction addr: " << std::hex << assign->addr() << std::dec << endl;
    if (INFO) cout << "[sa] => Read expr: " << readStr << endl;
    if (INFO) cout << "[sa] => Read same as write: " << (isKnownBitVar ? 1 : 0) << endl; // TODO maybe fix this
    if (INFO) cout << "[sa] => Is bit var: " << isBitVar << endl;
    cJSON *json_read = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_read, "insn_addr", assign->addr());
    cJSON_AddStringToObject(json_read, "expr", readStr.c_str());
    cJSON_AddStringToObject(json_read, "func", funcName);
    cJSON_AddNumberToObject(json_read, "read_same_as_write", isKnownBitVar ? 1 : 0); // TODO, see analyzeKnownBitVariables for proper way to handle this

    if (isBitVar) {
      std::vector<Assignment::Ptr> operations = bitOperations[assign];
      if (INFO) cout << "[sa] bit operations: " << endl;
      cJSON_AddNumberToObject(json_read, "is_bit_var",  1);
      cJSON *json_bitOps = cJSON_CreateArray();
      for (auto oit = operations.begin(); oit != operations.end(); ++oit) {
        cJSON *json_bitOp  = cJSON_CreateObject();
        Assignment::Ptr opAssign = (*oit);
        if (INFO) cout << "	operation: " << opAssign->format() << opAssign->insn().format();
        if (bitOperands.find(opAssign) != bitOperands.end()) {
          if (INFO) cout << "	operand: " << bitOperands[opAssign].format();
        }
        if (INFO) cout << endl;
        cJSON_AddNumberToObject(json_bitOp, "insn_addr", opAssign->addr());
        cJSON_AddStringToObject(json_bitOp, "operand", findMatchingOpExprStr(opAssign, bitOperands[opAssign]).c_str());
        cJSON_AddStringToObject(json_bitOp, "operation", opAssign->insn().getOperation().format().c_str());
        cJSON_AddItemToArray(json_bitOps, json_bitOp);
      }
      cJSON_AddItemToObject(json_read, "bit_operations",  json_bitOps);
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
  string filePath("/home/anygroup/perf_debug_tool/binary_analysis/graph");
  slice->printDOT(filePath);
  if (filter && !cs.foundFilteredReg) *madeProgress = false;
  if (!cs.slicedMoreThanOneStep) *madeProgress = false;
  return slice;
}

void handlePassByReference(AbsRegion targetReg, Address startAddr,
                           Block *startBb, Function *startFunc,
                           boost::unordered_map<Address, Function*> &ret,
                           boost::unordered_set<Address> &visitedAddrs) { // TODO add to declaration

  if (DEBUG) cout << "[pass-by-ref] Checking for pass by reference def in function " << startFunc->name() << endl;
  if (visitedAddrs.find(startAddr) != visitedAddrs.end()) {
    if (DEBUG) cout << "[pass-by-ref] Already visited, returning " << endl;
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
          if (DEBUG) cout << "[pass-by-ref] Found matching def " << assign->format() << endl;
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
            handlePassByReference(targetReg, (*rit).first, (*rit).second, func, ret, visitedAddrs);
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

std::string getReadStr(Instruction insn, bool *memReadFound, bool *regFound) {
  // TODO, refactor this function!
  Expression::Ptr read;
  std::string readStr;

  std::set<Expression::Ptr> memReads;
  insn.getMemoryReadOperands(memReads);
  if (memReads.size() > 0) { // prioritize reads from memory
    *memReadFound = true;
    assert (memReads.size() == 1);
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

std::string inline getLoadRegName(Function *newFunc, Address newAddr, bool *foundMemRead) {
  Block *newBB = getBasicBlock2(newFunc, newAddr);
  Instruction newInsn = newBB->getInsn(newAddr);
  return getLoadRegName(newInsn, foundMemRead);
}
std::string inline getLoadRegName(Instruction newInsn, bool *foundMemRead) {
  bool memReadFound = false, regFound = false;
  std::string readStr = getReadStr(newInsn, &memReadFound, &regFound);
  std::string delim = "|";
  int delimIndex = readStr.find(delim);
  std::string type = readStr.substr(0, delimIndex);
  std::string reg = "";
  if (regFound && type == "regread") {
    reg = readStr.substr(delimIndex + 1, readStr.length());
    boost::algorithm::to_lower(reg);
    if (regMap.find(reg) != regMap.end()) {
      reg = regMap[reg];
    }
    reg = "[x86_64::" + reg + "]";
  } else if (type == "memread") {
    cout << "[sa][warn] expect a register read here? " << endl; //TODO how to handle this??
    *foundMemRead = true;
  }
  return reg;
}