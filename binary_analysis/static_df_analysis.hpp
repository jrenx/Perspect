#include <boost/unordered_set.hpp>
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

bool readsFromStaticAddr(Instruction insn, Address addr, long *off); // TODO rename off
bool writesToStaticAddr(Instruction insn, Address addr, long *off);
boost::unordered_set<Address> checkAndGetWritesToStaticAddrs(Function *f, Instruction readInsn,
                                                             Address readAddr, long readOff);