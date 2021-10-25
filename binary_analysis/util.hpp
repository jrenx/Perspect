#ifndef UTIL_HPP
#define UTIL_HPP

#define USE_BPATCH

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

#ifdef USE_BPATCH
#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_point.h"
#include "BPatch_function.h"
#include "BPatch_flowGraph.h"
#endif

using namespace std;
using namespace boost;
using namespace Dyninst;
using namespace InstructionAPI;
using namespace ParseAPI;
using namespace DataflowAPI;

extern bool INFO;
extern bool DEBUG;
extern bool DEBUG_SLICE;
extern bool DEBUG_BIT;
extern bool DEBUG_STACK;
extern bool CRASH_ON_ERROR;

#ifdef USE_BPATCH
typedef enum {
  create,
  attach,
  open
} accessType_t;

BPatch_addressSpace *startInstrumenting(accessType_t accessType, const char *name, int pid, const char *argv[]);
BPatch_image *getImage(const char *progName);

void printInsnInfo(BPatch_basicBlock *block);
void getLineInfo(BPatch_basicBlock *block, vector<unsigned short> &allLines);
void printLineInfo(BPatch_basicBlock *block);
void printAddrToLineMappings(BPatch_image *appImage, const char *funcName);

void getAllControlFlowPredecessors(vector<BPatch_basicBlock *> &predecessors,
                                   BPatch_image *appImage, const char *funcName, long unsigned int addr);

BPatch_basicBlock *getImmediateDominator(BPatch_image *appImage, const char *funcName, long unsigned int addr);
BPatch_function *getFunction(BPatch_image *appImage, const char *funcName);
Instruction getIfCondition(BPatch_basicBlock *block);
BPatch_basicBlock *getBasicBlock(BPatch_flowGraph *fg, long unsigned int addr);
#endif

Block *getImmediateDominator2(Function *f, long unsigned int addr);
Function *getFunction2(vector<Function *> *allFuncs, const char *funcName);
Function *getFunction2(vector<Function *> *allFuncs, const char *funcName, long unsigned int addr);
Instruction getIfCondition2(Block *b);
Block *getBasicBlock2(Function *f, long unsigned int addr);
Block *getBasicBlockContainingInsnBeforeAddr(Function *f, long unsigned int addr);

void getReversePostOrderListHelper(Block *b,
                                   std::vector<Block *> &list,
                                   boost::unordered_set<Block *> &visited);

void getRegAndOff(Expression::Ptr exp, MachRegister *machReg, long *off);
void getRegAndOff(Expression::Ptr exp, std::vector<MachRegister> &machRegs, long *off);
std::string getLoadRegName(Instruction insn);

#ifdef USE_BPATCH
cJSON * printBBIdsToJsonHelper(BPatch_Vector<BPatch_basicBlock *> &bbs);
cJSON *printBBsToJsonHelper(BPatch_Vector<BPatch_basicBlock *> &bbs,
                            boost::unordered_map<BPatch_basicBlock *, vector<BPatch_basicBlock *>> *backEdges = NULL);
#else
cJSON *printBBIdsToJsonHelper(vector<Block *> &bbs, boost::unordered_map<Block *, int> &blockIds);

cJSON *printBBsToJsonHelper(vector<Block *> &bbs,
                             boost::unordered_map<Block *, vector<Block *>> &backEdges,
                              Function *f, SymtabAPI::Symtab *symTab);
#endif
void getReversePostOrderListHelper(Node::Ptr node, std::vector<Node::Ptr> *list, boost::unordered_set<Node::Ptr> &visited);
void getReversePostOrderList(GraphPtr slice, std::vector<Node::Ptr> *list);
#endif
