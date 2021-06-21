#ifndef STATIC_DF_ANALYSIS_HPP
#define STATIC_DF_ANALYSIS_HPP

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

extern bool INFO;
extern bool DEBUG;
extern bool DEBUG_SLICE;
extern bool DEBUG_BIT;
extern bool DEBUG_STACK;

bool readsFromStaticAddr(Instruction insn, Address addr, long *off); // TODO rename off
bool writesToStaticAddr(Instruction insn, Address addr, long *off);
boost::unordered_set<Address> checkAndGetWritesToStaticAddrs(Function *f, Instruction readInsn,
                                                             Address readAddr, long readOff);

#endif