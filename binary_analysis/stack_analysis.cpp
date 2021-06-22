#include "stack_analysis.hpp"
#include "bitvar_analysis.hpp"

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

namespace boost {
  class StackStore {
  private:
    MachRegister machReg_;
    long offset_;
    long stackheight_;
  public:
    bool isSpecial; // TODO, a bit ugly
    std::size_t hash;
    std::string str;

    StackStore(MachRegister machReg, long offset, long stackheight) :
        machReg_(machReg), offset_(offset), stackheight_(stackheight) {
      isSpecial = false;
      std::stringstream hash_ss;
      hash_ss << machReg_.name() << " + " << (offset_ + stackheight_);
      std::string hash_str = hash_ss.str();

      hash = std::hash<std::string>{}(hash_str);

      std::stringstream retVal;
      retVal << machReg_.name() << " + " << std::hex << offset_ << " @ " << std::dec << stackheight_;
      str = retVal.str();
    }

    bool operator==(const StackStore &rhs) const {
      return machReg_ == rhs.machReg_ &&
             (offset_ + stackheight_) == (rhs.offset_ + rhs.stackheight_);
    }

    bool operator!=(const StackStore &rhs) const {
      return !(*this == rhs);
    }

    std::string format() const {
      return str;
    }

    friend std::ostream& operator<<(std::ostream& stream, const StackStore& s)
    {
      stream << s.format() << std::endl;
      return stream;
    }
  };

  std::size_t hash_value(const StackStore &ss) {
    // Compute individual hash values for first,
    // second and third and combine them using XOR
    // and bit shifting:

    return ss.hash;
  }
}

boost::unordered_map<Address, Function *> checkAndGetStackWrites(Function *f, Instruction readInsn, Address readAddr,
                                                                 MachRegister readReg, long readOff, int initHeight, int level) {
  cout << "[stack] Checking function: " << f->name() << " for "
       << readReg.name() << " + " << readOff << " @ " << readInsn.format() << endl;
  if (stackCache->find(readAddr) != stackCache->end()) {
    return (*stackCache)[readAddr];
  }
  std::vector<Block *> list;
  boost::unordered_set<Block *> visited;
  getReversePostOrderListHelper(f->entry(), list, visited);
  std::reverse(list.begin(), list.end());

  boost::unordered_map<Address, long> insnToStackHeight;
  getStackHeights(f, list, insnToStackHeight, initHeight);

  boost::unordered_set<Address> readAddrs;
  readAddrs.insert(readAddr);

  StackStore stackRead(readReg, readOff, insnToStackHeight[readAddr]); // TODO rename StackStore to StackAccess...
  bool resultIntractable = false;
  boost::unordered_map<Address, Function *> ret;
  checkAndGetStackWritesHelper(ret, &resultIntractable, f, list, insnToStackHeight, readAddrs, stackRead, level);
  //if (resultIntractable) ret.clear();
  stackCache->insert({readAddr, ret});
  return ret;
}

boost::unordered_map<Address, Function *> checkAndGetStackWritesHelper(boost::unordered_map<Address, Function *> &ret,
                                                                       bool *resultIntractable,
                                                                       Function *f,
                                                                       std::vector<Block *> &list,
                                                                       boost::unordered_map<Address, long> &insnToStackHeight,
                                                                       boost::unordered_set<Address> &readAddrs,
                                                                       StackStore &stackRead, int level) {
  //if (DEBUG_STACK)
  cout << "[stack] Looking for writes in function " << f->name()
       << " at level " << level << " for " << stackRead << endl;
  boost::unordered_map<Address, boost::unordered_map<Address, Function *>> insnToReachableStores; //FIXME if I'm more comfortable with pointers store pointers instead ...

  for (auto bit = list.begin(); bit != list.end(); bit++) {
    Block::Insns insns;
    Block *b = *bit;
    b->getInsns(insns);
    for (auto iit = insns.begin(); iit != insns.end(); iit++) {
      Address addr = (*iit).first;
      Instruction insn = (*iit).second;
      if (DEBUG && DEBUG_STACK)
        cout << "[stack] checking instruction: " << insn.format() << " @" << std::hex << addr << std::dec << endl;
      boost::unordered_map<Address, Function *> reachableStores;

      if (level == 0) {
        boost::unordered_map<Address, Function *> allRets;
        if (iit == insns.begin() && bit == list.begin()) {
          boost::unordered_set<Function *> allCallers;
          Block::edgelist sources = b->sources();
          for (auto it = sources.begin(); it != sources.end(); it++) {
            if ((*it)->type() == RET || (*it)->type() == CATCH || (*it)->type() == FALLTHROUGH ||
                (*it)->type() == CALL_FT)
              continue;
            Block *src = (*it)->src();
            std::vector<Function *> funcs;
            src->getFuncs(funcs);
            Function *caller = getFunction(funcs);
            if (caller == NULL) {
              cout << "[stack][warn] caller function cannot be determined, unhandled dynamic invocation site: "
                   << insn.format() << endl;
              continue;
            }
            if (caller == f) {
              cout << "[stack] Still in the same function, ignore ... " << endl;
            }
            allCallers.insert(caller);
          }
          for (auto fit = allCallers.begin(); fit != allCallers.end(); fit++) {
            Function *caller = *fit;
            if (DEBUG_STACK)
              cout << "[stack] checking instruction: " << insn.format() << " @" << std::hex << addr << std::dec << endl;
            if (DEBUG_STACK)
              cout << "[stack] => Checking for stack writes in caller " << caller->name()
                   << " callee is " << f->name() << endl;
            boost::unordered_set<Address> readAddrs;
            getAllInvokes(caller, f, readAddrs); // TODO verify this

            std::vector<Block *> callerList;
            boost::unordered_set<Block *> visited;
            getReversePostOrderListHelper(caller->entry(), callerList, visited);
            std::reverse(callerList.begin(), callerList.end());

            for (auto rait = readAddrs.begin(); rait != readAddrs.end(); rait++) {
              Address readAddr = *rait;
              if (DEBUG_STACK) cout << "[stack] => Checking for read address " << std::hex << readAddr << std::dec  << endl;
              boost::unordered_map<Address, long> callerInsnToStackHeight;
              getStackHeights(caller, callerList, callerInsnToStackHeight, 0);
              int stackOffSet = 8 - callerInsnToStackHeight[readAddr];
              callerInsnToStackHeight.clear();
              getStackHeights(caller, callerList, callerInsnToStackHeight, stackOffSet);
              boost::unordered_set<Address> cuuReadAddrs;
              cuuReadAddrs.insert(readAddr);
              checkAndGetStackWritesHelper(allRets, resultIntractable, caller, callerList, callerInsnToStackHeight, cuuReadAddrs, stackRead,
                                                                             level - 1);

              if (DEBUG_STACK && DEBUG)
                cout << "[stack] looked for stores" // at " << std::hex << addr << std::dec
                     << " from caller " << caller->name()
                     << " currently found " << allRets.size() << " stores " << endl;
            }
          }
        }

        entryID id = insn.getOperation().getID();
        if (id == e_call || id == e_callq) { //TODO rename level to calstackdepth? //TODO add jump here
          Block::edgelist targets = b->targets();
          for (auto it = targets.begin(); it != targets.end(); it++) {
            if ((*it)->type() != CALL)
              continue;
            Block *trg = (*it)->trg();
            std::vector<Function *> funcs;
            trg->getFuncs(funcs);
            Function *callee = getFunction(funcs);
            if (callee == NULL) {
              cout << "[stack][warn] callee function cannot be determined, unhandled dynamic invocation site: "
                   << insn.format() << endl;
              continue;
            }
            if (DEBUG_STACK)
              cout << "[stack] =>Checking for stack writes in callee " << callee->name() << endl;
            boost::unordered_set<Address> readAddrs;
            getAllRets(callee, readAddrs);

            std::vector<Block *> calleeList;
            boost::unordered_set<Block *> visited;
            getReversePostOrderListHelper(callee->entry(), calleeList, visited);
            std::reverse(calleeList.begin(), calleeList.end());

            boost::unordered_map<Address, long> calleeInsnToStackHeight;
            getStackHeights(callee, calleeList, calleeInsnToStackHeight, insnToStackHeight[addr] - 8);

            cout << "[stack] checking invocation @ "  << std::hex << addr << std::dec << endl;
            checkAndGetStackWritesHelper(allRets, resultIntractable, callee, calleeList, calleeInsnToStackHeight, readAddrs, stackRead,
                                                                           level + 1);

            if (DEBUG_STACK && DEBUG)
              cout << "[stack] looked for stores" // at " << std::hex << addr << std::dec
                   << " from callee " << callee->name()
                   << " currently found " << allRets.size() << " stores " << endl;
          }
        }
        if (allRets.size() > 0) {
          reachableStores.insert(allRets.begin(), allRets.end());
          //insnToReachableStores.insert({addr, reachableStores});
          if (DEBUG_STACK && DEBUG) printReachableStores(reachableStores);
        }
      }

      if (insn.getOperation().getID() == e_lea) { //TODO, make a separate function...
        //cout << std::hex << addr << std::dec << endl;
        if (!insn.readsMemory()) {
          boost::unordered_map<Address, StackStore> indirectWrites;
          get_indirect_write_to_stack(insn, addr, b, f, insnToStackHeight[addr], stackRead, indirectWrites);
          //cout << indirectWrites.size() << endl;
          for (auto iwit = indirectWrites.begin(); iwit != indirectWrites.end(); iwit++) {
            Address useAddr = (*iwit).first;
            //cout << useAddr << endl;
            StackStore stackStore = (*iwit).second;
            if (insnToReachableStores.find(useAddr) == insnToReachableStores.end()) {
              boost::unordered_map<Address, Function *> reachableIndirectStores;
              insnToReachableStores.insert({useAddr, reachableIndirectStores});
            }
            insnToReachableStores[useAddr].insert({useAddr, f});
            //printReachableStores(insnToReachableStores[useAddr]);
          }
        }
      }

      std::vector<Operand> ops;
      insn.getOperands(ops);
      for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
        Operand op = *oit;
        if (!writesToStack(op, insn, addr)) continue;

        Expression::Ptr exp = op.getValue();
        //std::vector<Expression::Ptr> children;
        //exp->getChildren(children);
        MachRegister machReg; long off = 0;
        getRegAndOff(exp, &machReg, &off);
        //getRegAndOff(*children.begin(), &machReg, &off);

        //assert(reachableStores.find(exp) == reachableStores.end());
        StackStore stackStore(machReg, off, insnToStackHeight[addr]);
        if (DEBUG_STACK && DEBUG)
          cout << "[stack] current stack store " << stackStore << " @ " << std::hex << addr << std::dec << endl;
        if (stackStore == stackRead) {
          reachableStores.insert({addr, f}); // should not have duplicates
          if (DEBUG_STACK && DEBUG)
            cout << "[stack] found a match!" << endl;
        }
      }
      insnToReachableStores.insert({addr, reachableStores}); // should not have duplicates
      if (DEBUG_STACK && DEBUG)
        cout << "[stack] stores at " << std::hex << addr << std::dec << endl;
      if (DEBUG_STACK && DEBUG) printReachableStores(insnToReachableStores[addr]);
    }
  }

  bool changed = true;
  int iter = 0;
  while (changed) {
    iter ++;
    if (DEBUG && DEBUG_STACK) cout << "[stack] Updating for " << iter << " iterations. " << endl;
    changed = false;
    for (auto bit = list.begin(); bit != list.end(); bit++) {
      Block::Insns insns;
      Block *b = *bit;
      if (DEBUG && DEBUG_STACK) cout << "[stack] ===========================================================" << endl;
      if (DEBUG && DEBUG_STACK) cout << "[stack] Checking basic block from "
                                     << std::hex << b->start() << " to " << b->end() << std::dec << endl;
      b->getInsns(insns);
      // for the first instruction get sources, union them
      // otherwise, just get the previous
      // then, for the same entry, override
      // if any update, then changed .. how to compare two vectors are equal?
      boost::unordered_map<Address, Function *> prevReachableStores;
      Block::edgelist sources = b->sources();
      for (auto eit = sources.begin(); eit != sources.end(); eit++) {
        if ((*eit)->type() == CALL || (*eit)->type() == RET || (*eit)->type() == CATCH)
          continue;
        Block* src = (*eit)->src();
        Block* trg = (*eit)->trg();
        assert(trg == b);
        if (DEBUG && DEBUG_STACK) cout << "[stack]     predecessor block " << src->start() << " to " << src->end() << endl;
        boost::unordered_map<Address, Function *> predReachableStores = insnToReachableStores[src->last()];
        prevReachableStores.insert(predReachableStores.begin(), predReachableStores.end());
      }
      if (DEBUG && DEBUG_STACK) cout << "[stack] aggregated stack stores from predecessors:" << endl;
      if (DEBUG && DEBUG_STACK) printReachableStores(prevReachableStores);

      for (auto iit = insns.begin(); iit != insns.end(); iit++) {
        Address addr = (*iit).first;
        Instruction insn = (*iit).second;
        if (DEBUG_STACK && DEBUG)
          cout << "[stack] Working on instruction: " << insn.format()
               << " @" << std::hex << addr << std::dec << endl;

        if (DEBUG && DEBUG_STACK) cout << "[stack]   stack stores from previous instructions:" << endl;
        if (DEBUG && DEBUG_STACK) printReachableStores(prevReachableStores);

        if (DEBUG && DEBUG_STACK) cout << "[stack]   stack stores before update:" << endl;
        boost::unordered_map<Address, Function *> currReachableStores = insnToReachableStores[addr];
        if (DEBUG && DEBUG_STACK) printReachableStores(currReachableStores);

        if (currReachableStores.size() > 0) {
          prevReachableStores = currReachableStores;
          changed = false;
        } else {
          insnToReachableStores[addr] = prevReachableStores;
        }

        if (DEBUG_STACK && DEBUG) cout << "[stack]   stack stores after update:" << endl;
        if (DEBUG_STACK && DEBUG) printReachableStores(insnToReachableStores[addr]);

        if (DEBUG && DEBUG_STACK) cout << "[stack]" << endl;
      }
    }
  }
  //bool stackWritesIntractable = false;
  for (auto rait = readAddrs.begin(); rait != readAddrs.end(); rait++) {
    Address readAddr = *rait;
    // << "[stack] current stack read addr is: " << std::hex << readAddr << std::dec << endl;
    boost::unordered_map<Address, Function *> &curr = insnToReachableStores[readAddr];
    ret.insert(curr.begin(), curr.end()); // FIXME maybe assert no duplicate
  }
  //if (stackWritesIntractable) return ret.clear();  //TODO
  return ret;
}

void get_indirect_write_to_stack(Instruction insn, Address addr, Block *b, Function *f,
                                 int stackHeight, StackStore &stackRead,
                                 boost::unordered_map<Address, StackStore> &indirectWrites) { //TODO add the declaration to the top
  MachRegister machReg; long off=0;
  std::vector<Operand> ops;
  insn.getOperands(ops);
  bool loadStackAddr = false;
  bool stackWritesIntractable = false;
  for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
    if (!insn.isRead((*oit).getValue())) continue;
    std::vector<MachRegister> machRegs;
    getRegAndOff((*oit).getValue(), machRegs, &off);
    for (int i = 0; i < machRegs.size(); i++) {
      if (machRegs[i] == x86_64::rsp || machRegs[i] == x86_64::esp) {
        if (DEBUG_STACK)
          cout << "[stack] Found load stack address: " << " @ " << insn.format()
               << " @ " << std::hex << addr << std::dec << endl;
        machReg = machRegs[i];
        loadStackAddr = true;
        break;
      }
    }
    if (machRegs.size() > 1) {
      cout << "[stack] All writes to stack might be intractable! @" << std::hex << addr << std::dec << endl;
      stackWritesIntractable = true;
      break;
    }
  }
  if (stackWritesIntractable) {
    StackStore specialStore = stackRead;
    specialStore.isSpecial = true;
    indirectWrites.insert({addr, specialStore});
    return;
  }
  if (!loadStackAddr) return;
  // make assignment, get the assigned register
  AssignmentConverter ac(true, false);
  vector<Assignment::Ptr> assignments;
  ac.convert(insn, addr, f, b, assignments);
  assert(assignments.size() == 1);
  AbsRegion addrReg = assignments[0]->out();
  if (DEBUG_STACK)
    cout << "[stack] stack address stored to " << addrReg.format() << endl;
  // go back in same bb to find a write to the reg
  // make that into the new stack store
  // if nothing found prin a warning
  Block::Insns currInsns;
  b->getInsns(currInsns);
  bool foundUse = false;
  bool currIsOffsetStore = false;
  bool prevIsOffsetStore = false;
  for (auto iit = currInsns.rbegin(); iit != currInsns.rend(); iit++) {
    Address currAddr = (*iit).first;
    if (currAddr == addr) break;
    Instruction currInsn = (*iit).second;

    ops.clear();
    currInsn.getOperands(ops);
    AbsRegionConverter arc(true, false);
    //if (!insn.writesMemory()) continue;
    bool writesMemory = false;
    for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
      if ((*oit).writesMemory()) {
        writesMemory = true;
        break;
      }
    }
    for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
      std::set<RegisterAST::Ptr> regsRead;
      if (writesMemory) {
        if (!(*oit).writesMemory() && !(*oit).readsMemory()) {
          (*oit).getReadSet(regsRead);
          for (auto rit = regsRead.begin(); rit != regsRead.end(); ++rit) {
            AbsRegion curr = arc.convert(*rit);
            if (curr == addrReg) {
              cout << "[stack] reg containing stack addr propogated to other addr ..." << endl;
              cout << "[stack] All writes to stack might be intractable! @" << std::hex << currAddr << std::dec << endl;
              stackWritesIntractable = true;
              break;
            }
          }
          if (stackWritesIntractable) break;
          continue;
        }
      }
      if (stackWritesIntractable) {
        StackStore specialStore = stackRead;
        //cout << stackRead << endl;
        specialStore.isSpecial = true;
        //cout << specialStore << endl;
        indirectWrites.insert({addr, specialStore});
        return;
      }
      if (!(*oit).writesMemory()) continue;
      //if (DEBUG || DEBUG_SLICE) cout << "[slice] memory write op: " << (*oit).format(insn.getArch()) << endl;

      (*oit).getReadSet(regsRead);
      for (auto rit = regsRead.begin(); rit != regsRead.end(); ++rit) {
        AbsRegion curr = arc.convert(*rit);
        //if (DEBUG || DEBUG_SLICE) cout << "[slice] reg read: " << curr.format() << endl;
        if (curr == addrReg) {
          std::vector<MachRegister> machRegs;
          long currOff = 0;
          getRegAndOff((*oit).getValue(), machRegs, &currOff);
          if (machRegs.size() == 2) {
            for (int i = 0; i < machRegs.size(); i++) {
              if (machRegs[i] == x86_64::ds || machRegs[i] == x86_64::es) {
                currOff = 0;
                currIsOffsetStore = true;
                break;
              }
            }
          }
          if (currIsOffsetStore && !prevIsOffsetStore) {
            prevIsOffsetStore = true;
            currOff = 8;
          } else if (currIsOffsetStore && prevIsOffsetStore) {
            prevIsOffsetStore = false;
            currIsOffsetStore = false;
          }
          StackStore stackStore(machReg, off + currOff, stackHeight);
          //if (DEBUG_STACK && DEBUG)
          //cout << "[stack] current stack store " << currInsn.format() << " @ " << std::hex << currAddr << std::dec << endl;
          //cout << stackStore << endl;
          //cout << stackRead << endl;
          if (stackStore == stackRead) {
            cout << "[stack] Found indirect store to stack address: " << " @ " << currInsn.format()
                 << " @ " << std::hex << currAddr << std::dec << endl;
            indirectWrites.insert({currAddr, stackStore});
          }
        }
      }
    }
  }
}

bool readsFromStack(Instruction insn, Address addr, MachRegister *reg, long *off) { // TODO add signature to top
  if (DEBUG && DEBUG_STACK) cout << "[stack] Checking memory read @ " << insn.format() << endl;

  std::set<Expression::Ptr> memReads;
  insn.getMemoryReadOperands(memReads);
  // FIXME: For now just handle those that have one memory write.
  if (DEBUG && DEBUG_STACK)
    cout << "[stack] Number of memory reads: " << memReads.size() << endl;

  for (auto it = memReads.begin(); it != memReads.end(); it++) {
    if (DEBUG && DEBUG_STACK) cout << "[stack] Checking memory read " << (*it)->format() << endl;
    getRegAndOff(*it, reg, off);
    if (DEBUG && DEBUG_STACK) cout << "[stack] Register read is " << reg->name() << endl;
    if ((*reg) == x86_64::rsp || (*reg) == x86_64::esp) {
      if (DEBUG_STACK) cout << "[stack] Found store to stack: " << " @ " << insn.format() << " @ " << addr << endl;
      return true;
    }
  }
  return false;
}

bool writesToStack(Operand op, Instruction insn, Address addr) { // TODO add signature to top //TODO maybe refactor this
  if (!op.writesMemory()) return false;

  if (DEBUG && DEBUG_STACK)
    cout << "[stack] Checking memory write @ " << op.format(insn.getArch()) << endl;

  std::set<Expression::Ptr> memWrites;
  insn.getMemoryWriteOperands(memWrites);
  // FIXME: For now just handle those that have one memory write.
  if (DEBUG && DEBUG_STACK)
    cout << "[stack] Number of memory writes: " << memWrites.size() << endl;
  assert(memWrites.size() == 1);

  std::set<RegisterAST::Ptr> regsRead;
  op.getReadSet(regsRead);
  if (DEBUG && DEBUG_STACK)
    cout << "[stack] Register read count: " << regsRead.size() << endl;
  for (auto rit = regsRead.begin(); rit != regsRead.end(); rit++) {
    RegisterAST::Ptr regAst = *rit;
    MachRegister reg = regAst->getID();
    if (reg == x86_64::rsp || reg == x86_64::esp) { //FIXME: RSP reg has other variants too
      if (DEBUG_STACK && DEBUG)
        cout << "[stack] Found store to stack: " << op.format(insn.getArch())
             << " @ " << insn.format() << " @ " << addr << endl;

      std::set<RegisterAST::Ptr> regsWrite;
      op.getWriteSet(regsWrite);
      assert(regsWrite.size() == 0);

      return true;
    }
  }
  return false;
}

void getStackHeights(Function *f, std::vector<Block *> &list,
                     boost::unordered_map<Address, long> &insnToStackHeight, int initHeight) {
  // FIXME: just one pass, multiple predecessors are supposed to have the same stack height right?
  long currHeight = initHeight;
  bool repeat = true;
  while (repeat) {
    repeat = false;
    for (auto bit = list.begin(); bit != list.end(); bit++) {
      Block::Insns insns;
      Block *b = *bit;
      b->getInsns(insns);
      for (auto iit = insns.begin(); iit != insns.end(); iit++) {
        bool changesStackPointer = false;
        Address addr = (*iit).first;
        Instruction insn = (*iit).second;

        if (iit == insns.begin()) {
          if (DEBUG_STACK && DEBUG) {
            cout << "[stack] Calculating the stack height @ " << std::hex << addr << std::dec << endl;
          }

          Block::edgelist sources = b->sources();
          int prevHeight = 0;
          bool hasAnAnalyzedPrede = false;
          for (auto eit = sources.begin(); eit != sources.end(); eit++) {
            Block *src = (*eit)->src();
            Block *trg = (*eit)->trg();
            /*
            if (DEBUG_STACK && DEBUG) {
              cout << "[stack]     predecessor @ " << std::hex << src->start() << std::dec << " to "
                   << std::hex << src->last() << std::dec << endl;
            }*/

            if ((*eit)->type() == CALL || (*eit)->type() == RET || (*eit)->type() == CATCH)
              continue;

            // Even jump edges can go to other functions
            std::vector<Function *> funcs;
            src->getFuncs(funcs);
            bool inSameFunction = false;
            for (auto fit = funcs.begin(); fit != funcs.end(); fit ++) {
              if (*fit == f) {
                inSameFunction = true;
              }
            }
            if (!inSameFunction) {
              cout << "[stack] predecessor not in the same function even through is not a call edge. " << endl;
              cout << "[stack]     predecessor @ " << std::hex << src->start() << " to "
                   << src->last() << std::dec << endl;
              continue;
            }

            if (insnToStackHeight.find(src->last()) == insnToStackHeight.end()) {
              if (DEBUG_STACK && DEBUG) {
                cout << "[stack]     predecessor height @ " << std::hex << src->last() << std::dec
                     << " is not yet analyzed, need one more iteration..." << endl;
                repeat = true;
              }
              continue;
            }
            if (DEBUG_STACK && DEBUG) {
              cout << "[stack]     predecessor height @ " << std::hex << src->last() << std::dec
                   << " is " << insnToStackHeight[src->last()] << endl;
            }
            assert(!hasAnAnalyzedPrede || insnToStackHeight[src->last()] == prevHeight);
            prevHeight = insnToStackHeight[src->last()];
            hasAnAnalyzedPrede = true;
          }
          if (hasAnAnalyzedPrede) {
            currHeight = prevHeight;
          }
        }
        if (DEBUG && DEBUG_STACK) cout << "[stack] Checking register write @ " << insn.format() << endl;
        std::set<RegisterAST::Ptr> regsWrite;
        insn.getWriteSet(regsWrite);

        for (auto rit = regsWrite.begin(); rit != regsWrite.end(); rit++) {
          RegisterAST::Ptr regAst = *rit;
          MachRegister reg = regAst->getID();
          if (reg == x86_64::rsp || reg == x86_64::esp) {
            if (DEBUG_STACK && DEBUG) cout << "[stack] Found stack pointer manipulation @ " << insn.format() << endl;
            changesStackPointer = true;
            break;
          }
          //StackAnalysis sa(f);
          //StackAnalysis::DefHeightSet set = sa.findDefHeight(b, addr, Absloc(reg));
          //cout << "HERE: " << reg.name() << " " << (*set.begin()).height.format() << " " << insn.format() << " @ " << addr << endl;
        }

        if (!changesStackPointer) {
          if (DEBUG_STACK && DEBUG)
            cout << "[stack] height @ " << std::hex << addr << std::dec << " is " << currHeight << endl;
          insnToStackHeight[addr] = currHeight;
          continue;
        }
        //cout << "[stack] Operand ID: " << insn.getOperation().getID() << endl;
        entryID id = insn.getOperation().getID();
        switch (id) {
          case e_call:
          case e_callq:
          case e_ret_near:
          case e_ret_far: {
            if (DEBUG_STACK && DEBUG) cout << "[stack] Ignore calls and ret." << endl;
            break;
          }
          case e_sub: {
            std::vector<Operand> ops;
            insn.getOperands(ops);
            MachRegister machReg;
            long off = 0;
            for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
              getRegAndOff((*oit).getValue(), &machReg, &off);
            }
            if (DEBUG_STACK && DEBUG)
              cout << "[stack] subtracting stack pointer " << machReg.name() << " by " << off << endl;
            currHeight -= off;
            break;
          }
          case e_add: {
            std::vector<Operand> ops;
            insn.getOperands(ops);
            MachRegister machReg;
            long off = 0;
            for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
              getRegAndOff((*oit).getValue(), &machReg, &off);
            }
            if (DEBUG_STACK && DEBUG)
              cout << "[stack] encountered add, increasing stack pointer " << machReg.name() << " by " << off << endl;
            currHeight += off;
            break;
          }
            //https://stackoverflow.com/questions/45127993/how-many-bytes-does-the-push-instruction-push-onto-the-stack-when-i-dont-specif
            //https://www.cs.uaf.edu/2015/fall/cs301/lecture/09_16_stack.html
          case e_push: { //TODO, important!! for 32bit it's 4 bytes!! need a config for that!
            if (DEBUG_STACK && DEBUG)
              cout << "[stack] encountered push, decreasing stack pointer by 8" << endl;
            currHeight -= 8;
            break;
          }
          case e_pop: {
            if (DEBUG_STACK && DEBUG)
              cout << "[stack] encountered push, increasing stack pointer by 8" << endl;
            currHeight += 8;
            break;
          }
          default:
            if (DEBUG_STACK)
              cout << "[stack][warn] Unhandled case: " << insn.format() << endl;
        }
        if (DEBUG_STACK && DEBUG) cout << "[stack] height @ " << addr << " is " << currHeight << endl;
        insnToStackHeight[addr] = currHeight;
      }
    }
  }
}

void printReachableStores(boost::unordered_map<Address, Function *> &reachableStores) {
  cout << "[stack]          stack store  @ "  << std::hex;
  for (auto sit = reachableStores.begin(); sit != reachableStores.end(); sit++) {
    cout << (*sit).first << std::dec << " " << (*sit).second->name() << " ";
  }
  cout << std::dec << endl;
}

void getAllRets(Function *f, boost::unordered_set<Address> &rets) {
  for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
    Block::Insns insns;
    (*bit)->getInsns(insns);
    for (auto iit = insns.begin(); iit != insns.end(); iit++) {
      Address addr = (*iit).first;
      Instruction insn = (*iit).second;
      entryID id = insn.getOperation().getID();
      if (id == e_ret_near || id == e_ret_far)
        rets.insert(addr);
    }
  }
}

void getAllRets(Function *f, boost::unordered_set<std::pair<Address, Block *>> &rets) {
  for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
    Block::Insns insns;
    (*bit)->getInsns(insns);
    for (auto iit = insns.begin(); iit != insns.end(); iit++) {
      Address addr = (*iit).first;
      Instruction insn = (*iit).second;
      entryID id = insn.getOperation().getID();
      if (id == e_ret_near || id == e_ret_far)
        rets.insert(std::pair<Address, Block *>(addr, *bit));
    }
  }
}

void getAllInvokes(Function *f, Function *callee, boost::unordered_set<Address> &rets) {
  for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
    Block::Insns insns;
    (*bit)->getInsns(insns);
    for (auto iit = insns.begin(); iit != insns.end(); iit++) {
      Address addr = (*iit).first;
      Instruction insn = (*iit).second;
      entryID id = insn.getOperation().getID();
      if (id == e_call || id == e_callq) {
        Block::edgelist targets = (*bit)->targets();
        bool found = false;
        for (auto it = targets.begin(); it != targets.end(); it++) {
          if ((*it)->type() != CALL)
            continue;
          Block *trg = (*it)->trg();
          std::vector<Function *> funcs;
          trg->getFuncs(funcs);
          if (getFunction(funcs) == callee) {
            found = true;
            break;
          }
        }
        if (found) rets.insert(addr);
      }
    }
  }
}

Function *getFunction(std::vector<Function *> &funcs) {
  if (funcs.size() > 1) {
    for (auto fit = funcs.begin(); fit != funcs.end(); fit++) {
      cout << "[stack] function: " << (*fit)->name() << endl;
    }
  } else if (funcs.size() == 0) {
    return NULL;
  }
  assert(funcs.size() == 1);
  return *funcs.begin();
}