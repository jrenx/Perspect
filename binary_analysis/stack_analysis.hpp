#ifndef STACK_ANALYSIS_HPP
#define STACK_ANALYSIS_HPP
#include "util.hpp"

#include <vector>
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>
#include <boost/algorithm/string.hpp>

#include "Instruction.h"
#include "InstructionDecoder.h"
#include "CodeObject.h"
#include "CFG.h"
#include "Graph.h"
#include "slicing.h"

extern bool INFO;
extern bool DEBUG;
extern bool DEBUG_SLICE;
extern bool DEBUG_BIT;
extern bool DEBUG_STACK;
namespace boost {
  class StackStore;
}

extern boost::unordered_map<Address, boost::unordered_map<Address, Function *>> *stackCache;

boost::unordered_map<Address, Function *> checkAndGetStackWrites(Function *f, Instruction readInsn, Address readAddr,
                                                                 MachRegister readReg, long readOff, int initHeight, int level=0);
boost::unordered_map<Address, Function *> checkAndGetStackWritesHelper(bool *resultIntractable, Function *f,
                                                                       std::vector<Block *> &list,
                                                                       boost::unordered_map<Address, long> &insnToStackHeight,
                                                                       boost::unordered_set<Address> &readAddrs,
                                                                       StackStore &stackRead, int level);
void get_indirect_write_to_stack(Instruction insn, Address addr, Block *b, Function *f,
                                 int stackHeight, StackStore &stackRead,
                                 boost::unordered_map<Address, StackStore> &indirectWrites);
bool readsFromStack(Instruction insn, Address addr, MachRegister *reg, long *off);
bool writesToStack(Operand op, Instruction insn, Address addr);
void getStackHeights(Function *f, std::vector<Block *> &list, boost::unordered_map<Address, long> &insnToStackHeight, int initHeight);

void printReachableStores(boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> &reachableStores);

void getAllRets(Function *f, boost::unordered_set<Address> &rets);
void getAllRets(Function *f, boost::unordered_set<std::pair<Address, Block *>> &rets);
void getAllInvokes(Function *f, Function *callee, boost::unordered_set<Address> &rets);
Function *getFunction(std::vector<Function *> &funcs);

#endif