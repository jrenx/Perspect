#include "static_df_analysis.hpp"
#include "util.hpp"
#include <stdio.h>
#include <iostream>

#include <vector>
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>

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

bool readsFromStaticAddr(Instruction insn, Address addr, long *off) {
  if (DEBUG && DEBUG_STACK) cout << "[sa] Checking memory read @ " << insn.format() << endl;

  std::set<Expression::Ptr> memReads;
  insn.getMemoryReadOperands(memReads);
  // FIXME: For now just handle those that have one memory write.
  if (DEBUG)
    cout << "[sa] Number of memory reads: " << memReads.size() << endl;

  MachRegister reg;
  for (auto it = memReads.begin(); it != memReads.end(); it++) {
    // FIXME: is this check better or the check in getMemWritesToStaticAddresses?
    if (DEBUG) cout << "[sa] Checking memory read " << (*it)->format() << endl;
    getRegAndOff(*it, &reg, off);
    if (DEBUG) cout << "[sa] Register read is " << reg.name() << endl;
    if (reg == InvalidReg) {
      if (DEBUG) cout << "[stack] Found read from static addr: " << " @ " << insn.format() << " @ " << addr << endl;
      return true;
    }
  }
  return false;
}

bool writesToStaticAddr(Instruction insn, Address addr, long *off) {
  //TODO refactor and combine with readsFromStaticAddr?
  if (DEBUG) cout << "[sa] Checking memory write @ " << insn.format() << endl;

  std::set<Expression::Ptr> memWrites;
  insn.getMemoryWriteOperands(memWrites);
  // FIXME: For now just handle those that have one memory write.
  if (DEBUG)
    cout << "[sa] Number of memory reads: " << memWrites.size() << endl;

  MachRegister reg;
  for (auto it = memWrites.begin(); it != memWrites.end(); it++) {
    // FIXME: is this check better or the check in getMemWritesToStaticAddresses?
    if (DEBUG) cout << "[sa] Checking memory write " << (*it)->format() << endl;
    getRegAndOff(*it, &reg, off);
    if (DEBUG) cout << "[sa] Register read is " << reg.name() << endl;
    if (reg == InvalidReg) {
      if (DEBUG) cout << "[stack] Found write to static addr: " << " @ " << insn.format() << " @ " << addr << endl;
      return true;
    }
  }
  return false;
}

boost::unordered_set<Address> checkAndGetWritesToStaticAddrs(Function *f, Instruction readInsn,
                                                             Address readAddr, long readOff) { // TODO can we refactor and combine this with the stack store logic?
  cout << endl << "[sa] Checking function: " << f->name() << " for "
       << readOff << " @ " << readInsn.format() << endl;
  std::vector<Block *> list;
  boost::unordered_set<Block *> visited;
  getReversePostOrderListHelper(f->entry(), list, visited);
  std::reverse(list.begin(), list.end());

  boost::unordered_map<Address, boost::unordered_map<long, boost::unordered_set<Address>>>
                                                           insnToReachableStores; //FIXME if I'm more comfortable with pointers store pointers instead ... // FIXME store or write?
  for (auto bit = list.begin(); bit != list.end(); bit++) {
    Block::Insns insns;
    Block *b = *bit;
    b->getInsns(insns);
    for (auto iit = insns.begin(); iit != insns.end(); iit++) {
      Address addr = (*iit).first;
      Instruction insn = (*iit).second;
      std::vector<Operand> ops;
      insn.getOperands(ops);
      if (DEBUG) cout << "[sa] checking instruction: " << insn.format() << " @" << addr << endl;
      boost::unordered_map<long, boost::unordered_set<Address>> reachableStores;

      for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
        Operand op = *oit;
        long off = 0;
        if (!writesToStaticAddr(insn, addr, &off)) continue;

        boost::unordered_set<Address> s;
        s.insert(addr);

        if (off == readOff) {
          reachableStores.insert({off, s});
        }
      }
      insnToReachableStores.insert({addr, reachableStores});
    }
  }

  bool changed = true;
  int iter = 0;
  while (changed) {
    iter ++;
    if (DEBUG) cout << "[sa] Updating for " << iter << " iterations. " << endl;
    changed = false;
    for (auto bit = list.begin(); bit != list.end(); bit++) {
      Block::Insns insns;
      Block *b = *bit;
      if (DEBUG && DEBUG_STACK) cout << "[sa] ===========================================================" << endl;
      if (DEBUG && DEBUG_STACK) cout << "[sa] Checking basic block from " << std::hex << b->start()
                                     << " to " << b->end() << std::dec << endl;
      b->getInsns(insns);
      // for the first instruction get sources, union them
      // otherwise, just get the previous
      // then, for the same entry, override
      // if any update, then changed .. how to compare two vectors are equal?
      boost::unordered_map<long, boost::unordered_set<Address>> prevReachableStores;
      Block::edgelist sources = b->sources();
      for (auto eit = sources.begin(); eit != sources.end(); eit++) {
        if ((*eit)->type() == CALL || (*eit)->type() == RET || (*eit)->type() == CATCH)
          continue;
        Block* src = (*eit)->src();
        Block* trg = (*eit)->trg();
        assert(trg == b);
        if (DEBUG) cout << "[sa]     predecessor block " << src->start() << " to " << src->end() << endl;
        boost::unordered_map<long, boost::unordered_set<Address>> predReachableStores =
            insnToReachableStores[src->last()];
        for (auto mit = predReachableStores.begin(); mit != predReachableStores.end(); mit++) {
          long currOff = (*mit).first;
          boost::unordered_set<Address> s = (*mit).second;
          if (prevReachableStores.find(currOff) == prevReachableStores.end()) {
            prevReachableStores.insert({currOff, s}); // Should be a separate copy otherwise wouldn't work
          } else {
            for (auto sit = s.begin(); sit != s.end(); sit++) {
              prevReachableStores[currOff].insert(*sit);
            }
          }
        }
      }
      if (DEBUG) cout << "[sa] aggregated stores from predecessors:" << endl;

      for (auto iit = insns.begin(); iit != insns.end(); iit++) {
        Address addr = (*iit).first;
        Instruction insn = (*iit).second;
        if (DEBUG_STACK)
          cout << "[sa] Working on instruction: " << insn.format()
               << " @" << std::hex << addr << std::dec << endl;

        boost::unordered_map<long, boost::unordered_set<Address>> currReachableStores =
            insnToReachableStores[addr];

        /*
        if (addr != b->start() && addr != b->last() && currReachableStores.size() == 0) {
          continue;
        }*/

        //if (DEBUG && DEBUG_STACK) cout << "[sa]   stores to static addresses before update:" << endl;

        for (auto mit = currReachableStores.begin(); mit != currReachableStores.end(); mit++) {
          long currOff = (*mit).first;
          boost::unordered_set<Address> s = (*mit).second;
          prevReachableStores.insert({currOff, s});
        }

        if (currReachableStores.size() != prevReachableStores.size()) {
          changed = true;
        } else {
          for (auto mit = currReachableStores.begin(); mit != currReachableStores.end(); mit++) {
            long currOff = (*mit).first;
            /*
            if (prevReachableStores.find(ss) == prevReachableStores.end()) {
              changed = true;
              break;
            }*/

            boost::unordered_set<Address> s1 = (*mit).second;
            boost::unordered_set<Address> s2 = prevReachableStores[currOff];
            if (s1.size() != s2.size()) {
              changed = true;
              break;
            }

            for (auto sit = s1.begin(); sit != s1.end(); sit++) {
              if (s2.find(*sit) == s2.end()) {
                changed = true;
                break;
              }
            }
            if (changed) break;
          }
        }

        insnToReachableStores[addr] = prevReachableStores;

        //if (DEBUG)
        //  cout << "[sa]   stores to static addresses after update:" << endl;
        //if (DEBUG)

        //prevReachableStores = currReachableStores;
        //if (DEBUG) cout << "[sa]   stores to static addresses from previous instructions:" << endl;
        //if (DEBUG) cout << "[sa]" << endl;
      }
    }
  }
  return insnToReachableStores[readAddr][readOff];
}
