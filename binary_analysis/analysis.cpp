#include <stdio.h>
#include <vector>
#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_point.h"
#include "BPatch_function.h"
#include "BPatch_flowGraph.h"
#include "Instruction.h"
#include "InstructionDecoder.h"
#include "slicing.h"
#include "CodeObject.h"
#include "CFG.h"
#include "Graph.h"
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>
#include <boost/heap/priority_queue.hpp>
#include <iostream>
#include <fstream>
#include "cJSON.h"
#include <boost/algorithm/string.hpp>

using namespace std;
using namespace Dyninst;
using namespace InstructionAPI;
using namespace ParseAPI;
using namespace DataflowAPI;
using namespace boost;

/***************************************************************/
BPatch bpatch;
bool INFO = true;
bool DEBUG = false;
bool DEBUG_SLICE = false;
bool DEBUG_BIT = false;
bool DEBUG_STACK = false;

typedef enum {
  create,
  attach,
  open
} accessType_t;

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

BPatch_addressSpace *startInstrumenting(accessType_t accessType, const char *name, int pid, const char *argv[]);
BPatch_image *getImage(const char *progName);

void getLineInfo(BPatch_basicBlock *block, vector<unsigned short> &allLines);
void printLineInfo(BPatch_basicBlock *block);
void printAddrToLineMappings(BPatch_image *appImage, const char *funcName);

void getAllControlFlowPredecessors(vector<BPatch_basicBlock *> &predecessors,
		BPatch_image *appImage, const char *funcName, long unsigned int addr);

BPatch_basicBlock *getImmediateDominator(BPatch_image *appImage, const char *funcName, long unsigned int addr);
Block *getImmediateDominator2(Function *f, long unsigned int addr);

BPatch_function *getFunction(BPatch_image *appImage, const char *funcName);
//Function *getFunction2(const char *binaryPath, const char *funcName);
Function *getFunction2(SymtabCodeSource *stcs, CodeObject *co, const char *funcName);

Instruction getIfCondition(BPatch_basicBlock *block);
Instruction getIfCondition2(Block *b);

BPatch_basicBlock *getBasicBlock(BPatch_flowGraph *fg, long unsigned int addr);
Block *getBasicBlock2(Function *f, long unsigned int addr);
Block *getBasicBlockContainingInsnBeforeAddr(Function *f, long unsigned int addr);

GraphPtr buildBackwardSlice(Function *f, Block *b, Instruction insn, long unsigned int addr, char *regName, bool *madeProgress,
    bool atEndPoint = false);
void backwardSliceHelper(SymtabCodeSource *stcs, CodeObject *co, cJSON *json_reads, boost::unordered_set<Address> &visited,
                         char *progName, char *funcName,
                         long unsigned int addr, char *regName,
                         bool isKnownBitVar=false, bool atEndPoint=false);

std::string getReadStr(Instruction insn, bool *regFound);
std::string inline getLoadRegName(Function *newFunc, Address newAddr, bool *foundMemRead);
std::string inline getLoadRegName(Instruction newInsn, bool *foundMemRead);
void getReversePostOrderListHelper(Block *b,
                                   std::vector<Block *> &list,
                                   boost::unordered_set<Block *> &visited);

void getReversePostOrderListHelper(Node::Ptr node, std::vector<Node::Ptr> *list, boost::unordered_set<Node::Ptr> &visited);
void getReversePostOrderList(GraphPtr slice, std::vector<Node::Ptr> *list);

int getBitMaskDigits(Instruction insn, std::vector<AbsRegion> &regions);
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

boost::unordered_map<Address, Function *> checkAndGetStackWrites(Function *f, Instruction readInsn, Address readAddr,
                                                     MachRegister readReg, long readOff, int initHeight, int level=0);
boost::unordered_map<Address, Function *> checkAndGetStackWritesHelper(bool *resultIntractable, Function *f,
                                                           std::vector<Block *> &list,
                                                           boost::unordered_map<Address, long> &insnToStackHeight,
                                                           boost::unordered_set<Address> &readAddrs,
                                                           StackStore &stackRead, int level);
void getStackHeights(Function *f, std::vector<Block *> &list, boost::unordered_map<Address, long> &insnToStackHeight, int initHeight);
bool readsFromStack(Instruction insn, Address addr, MachRegister *reg, long *off);
bool writesToStack(Operand op, Instruction insn, Address addr);

void getRegAndOff(Expression::Ptr exp, MachRegister *machReg, long *off);
void printReachableStores(boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> &reachableStores);
void getAllRets(Function *f, boost::unordered_set<Address> &rets);
void getAllRets(Function *f, boost::unordered_set<std::pair<Address, Block *>> &rets);
void getAllInvokes(Function *f, Function *callee, boost::unordered_set<Address> &rets);
Function *getFunction(std::vector<Function *> &funcs);

boost::unordered_set<Address> checkAndGetWritesToStaticAddrs(Function *f, Instruction readInsn,
                                                             Address readAddr, long readOff);
bool readsFromStaticAddr(Instruction insn, Address addr, long *off); // TODO rename off
bool writesToStaticAddr(Instruction insn, Address addr, long *off);

std::string findMatchingOpExprStr(Assignment::Ptr assign, AbsRegion region);

cJSON * printBBIdsToJsonHelper(BPatch_Vector<BPatch_basicBlock *> &bbs);
cJSON *printBBsToJsonHelper(BPatch_Vector<BPatch_basicBlock *> &bbs,
    boost::unordered_map<BPatch_basicBlock *, vector<BPatch_basicBlock *>> *backEdges = NULL);

/*
long unsigned int getImmedDom(char *progName, char *funcName, long unsigned int addr);
void getAllBBs(char *progName, char *funcName, long unsigned int addr);
void getAllPredes(char *progName, char *funcName, long unsigned int addr);
long unsigned int getFirstInstrInBB(char *progName, char *funcName, long unsigned int addr);
long unsigned int getLastInstrInBB(char *progName, char *funcName, long unsigned int addr);
long unsigned int getInstrAfter(char *progName, char *funcName, long unsigned int addr);
void getImmedPred(char *progName, char *funcName, long unsigned int addr);
void getCalleeToCallsites(char *progName);
void getNestedMemWritesToStaticAddresses(char * addrToFuncNames, char *progName);
void getMemWritesToStaticAddresses(char *progName);
void getRegsWritten(char *progName, char *funcName, long unsigned int addr);
void backwardSlices(char *addrToRegNames, char *progName);
void backwardSlice(char *progName, char *funcName, long unsigned int addr, char *regName);
*/
// Attach, create, or open a file for rewriting
BPatch_addressSpace *startInstrumenting(accessType_t accessType, const char *name, int pid, const char *argv[]) {
  BPatch_addressSpace *handle = NULL;

  switch (accessType) {
    case create:
      handle = bpatch.processCreate(name, argv);
      if (!handle) { fprintf(stderr, "processCreate failed\n"); }
      break;
    case attach:
      handle = bpatch.processAttach(name, pid);
      if (!handle) { fprintf(stderr, "processAttach failed\n"); }
      break;
    case open:
      // Open the binary file and all dependencies
      handle = bpatch.openBinary(name, true);
      if (!handle) { fprintf(stderr, "openBinary failed\n"); }
      break;
  }

  return handle;
}

//TODO refactor and put in a separate file with proper include n stuff...
BPatch_image *getImage(const char *progName) {
  int progPID = 42;
  const char *progArgv[] = {"test.zip"};
  accessType_t mode = open;

  // Just open the binary for analysis, doesn't actually instrument it!
  BPatch_addressSpace *app = startInstrumenting(mode, progName, progPID, progArgv);
  if (!app) {
    fprintf(stderr, "opening the binary failed\n");
    exit(1);
  }

  BPatch_image *appImage = app->getImage();
  return appImage;
}

void printInsnInfo(BPatch_basicBlock *block) {
  std::vector<std::pair<Dyninst::InstructionAPI::Instruction,Address>> insns;
  block->getInstructions(insns);
  for (auto it = insns.begin(); it != insns.end(); ++it) {
    Address addr = (*it).second;
    fprintf(stdout, "  address: %lx.\n", addr);
  }
}

void getLineInfo(BPatch_basicBlock *block, vector<unsigned short> &allLines) {
  BPatch_Vector<BPatch_sourceBlock*> sourceBlocks;
  block->getSourceBlocks(sourceBlocks);
  for (int i = 0; i < sourceBlocks.size(); i++) {
    BPatch_Vector<unsigned short> lines;
    sourceBlocks[i]->getSourceLines(lines);
    for (int j = 0; j < lines.size(); j++) {
      allLines.push_back(lines[j]);
    }
  }
}

void printLineInfo(BPatch_basicBlock *block) {
  fprintf(stdout, " start %lx end %lx\n", block->getStartAddress(), block->getLastInsnAddress());
  vector<unsigned short> allLines;
  getLineInfo(block, allLines);
  fprintf(stdout, "  source lines: ");
  for (auto it = allLines.begin(); it != allLines.end(); it++) {
    fprintf(stdout, " %u ", *it);
  }
}

void printAddrToLineMappings(BPatch_image *appImage, const char *funcName) {

  vector<BPatch_function *> functions;
  appImage->findFunction(funcName, functions);
  BPatch_function *f;
  if (functions.size() == 0) {
    fprintf(stderr, "Loading function %s failed.\n", funcName);
    return;
  } else if (functions.size() == 1) {
    f = functions[0];
  } else if (functions.size() > 1) {
    std::string funcStr(funcName);
    fprintf(stderr, "More than one function with name %s, using one.\n", funcName);
    for (auto it = functions.begin(); it != functions.end(); it++) {
      if ((*it)->getName() == funcStr) {
        cout << "[sa] Using function " << (*it)->getName() << endl;
        f = *it;
      }
    }
  }

  BPatch_flowGraph *fg = f->getCFG();

  set <BPatch_basicBlock *> blocks;
  fg->getAllBasicBlocks(blocks);

  for (auto blockIter = blocks.begin();
       blockIter != blocks.end();
       ++blockIter) {
    BPatch_basicBlock *block = *blockIter;
    printLineInfo(block);
  }
}

void getAllControlFlowPredecessors(vector<BPatch_basicBlock *> &allPredes,
		BPatch_image *appImage, const char *funcName, long unsigned int addr) {
  BPatch_flowGraph *fg = getFunction(appImage, funcName)->getCFG();
  BPatch_basicBlock *bb = getBasicBlock(fg, addr);
  boost::unordered_set<BPatch_basicBlock *> visited;
  std::queue<BPatch_basicBlock *> worklist; // TODO change to a boost queue?
  worklist.push(bb);
  while (worklist.size() > 0) {
    if(DEBUG) cout << "Checking predecessor ..." << endl;
    BPatch_basicBlock *curr = worklist.front();
    worklist.pop();
    if(DEBUG) printLineInfo(curr);
    if(DEBUG) printInsnInfo(curr);
    if (visited.find(curr) != visited.end()) {
      if(DEBUG) cout << "Already visited " << endl;
      continue;
    }
    visited.insert(curr);
    allPredes.push_back(curr);
    BPatch_Vector<BPatch_basicBlock *> predes;
    curr->getSources(predes);
    for (int i=0; i<predes.size(); i++) {
      worklist.push(predes[i]);
      if(DEBUG) cout << "Adding predecessor to queue..." << endl;
      printLineInfo(predes[i]);
      printInsnInfo(predes[i]);
    }
  }
}


BPatch_basicBlock *getImmediateDominator(BPatch_image *appImage, const char *funcName, long unsigned int addr) {

  BPatch_flowGraph *fg = getFunction(appImage, funcName)->getCFG();
  return getBasicBlock(fg, addr)->getImmediateDominator();
}

Instruction getIfCondition(BPatch_basicBlock *block) {
  vector <Instruction> insns;
  block->getInstructions(insns);
  Instruction ret = *insns.rbegin();
  assert(ret.getCategory() == InsnCategory::c_BranchInsn);
  return ret;
}
/***************************************************************/
BPatch_function *getFunction(BPatch_image *appImage, const char *funcName){
  vector<BPatch_function *> functions;
  appImage->findFunction(funcName, functions);
  if (functions.size() == 0) {
    fprintf(stderr, "Loading function %s failed.\n", funcName);
    return NULL;
  } else if (functions.size() > 1) {
    std::string funcStr(funcName);
    fprintf(stderr, "More than one function with name %s, using one.\n", funcName);
    for (auto it = functions.begin(); it != functions.end(); it++) {
      if ((*it)->getName() == funcStr) {
        cout << "[sa] Using function " << (*it)->getName() << endl;
        return *it;
      }
    }
  }
  return functions[0]; // TODO is this gonna be a problem?
}

//TODO, in the future, get a batch get function
Function *getFunction2(SymtabCodeSource *stcs, CodeObject *co, const char *funcName) {
  string funcNameStr(funcName);
  const CodeObject::funclist &all = co->funcs();
  if (all.size() == 0) {
    fprintf(stderr, "No function in file.\n");
    return NULL;
  }

  for (auto fit = all.begin(); fit != all.end(); ++fit) {
    Function *f = *fit;
    if (f->name().compare(funcNameStr) == 0) {
      return f;
    }
  }
  return NULL;
}

BPatch_basicBlock *getBasicBlock(BPatch_flowGraph *fg, long unsigned int addr) {
  set <BPatch_basicBlock *> blocks;
  fg->getAllBasicBlocks(blocks);

  BPatch_basicBlock *target = NULL;
  for (auto blockIter = blocks.begin();
       blockIter != blocks.end();
       ++blockIter) {
    BPatch_basicBlock *block = *blockIter;
    if (DEBUG) cout << "Locating basic block of instruction: " << addr << endl;
    if (DEBUG) printLineInfo(block);
    if (DEBUG) cout << endl;
    if (addr >= block->getStartAddress() && addr < block->getEndAddress()) {
      target = block;
      break;
    }
  }

  if (target == NULL) {
    fprintf(stderr, "Failed to find basic block @ %lx.\n", addr);
    return NULL;
  }
  return target;
}

Block *getBasicBlockContainingInsnBeforeAddr(Function *f, long unsigned int addr) {
  Block *target = NULL;
  for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
    Block *b = *bit;
    if (addr > b->start() && addr <= b->end()) { // "Address immediately following the last instruction in the block."
      target = b;
      break;
    }
  }

  if (target == NULL) {
    cerr << "Failed to find basic block in function " << f->name() << " before " << addr << endl;
    return NULL;
  }
  return target;
}

Block *getBasicBlock2(Function *f, long unsigned int addr) {
  Block *target = NULL;
  for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
    Block *b = *bit;
    if (addr >= b->start() && addr < b->end()) { // "Address immediately following the last instruction in the block."
      target = b;
      break;
    }
  }

  if (target == NULL) {
    cerr << "Failed to find basic block in function " << f->name() << " @ " << addr << endl;
    return NULL;
  }
  return target;
}

Block *getImmediateDominator2(Function *f, long unsigned int addr) {
  Block *target = NULL;
  for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
    Block *b = *bit;
    if (addr >= b->start() && addr < b->end()) { // "Address immediately following the last instruction in the block."
      target = b;
      break;
    }
  }

  if (target == NULL) {
    cerr << "Failed to find basic block for function " << f->name() << " @ " << addr << endl;
    return NULL;
  }
  return f->getImmediateDominator(target);
}

Instruction getIfCondition2(Block *b) {
  // Decode the instruction
  const unsigned char *buf = (const unsigned char *) b->obj()->cs()->getPtrToInstruction(b->last());
  InstructionDecoder dec(buf, InstructionDecoder::maxInstructionLength, b->obj()->cs()->getArch());
  Instruction ret = dec.decode();
  assert(ret.getCategory() == InsnCategory::c_BranchInsn);
  return ret;
}

class CustomSlicer : public Slicer::Predicates {
public:
  char *regName = NULL;
  bool filter = false;
  bool foundFilteredReg = false;
  bool slicedMoreThanOneStep = false;
  Instruction insn;
  bool init = true;
  bool atEndPoint = false;
  virtual bool endAtPoint(Assignment::Ptr ap) {
    if(DEBUG || DEBUG_SLICE) cout << endl;
    if(DEBUG || DEBUG_SLICE) cout << "[slice] Should continue slicing the assignment?" << endl;
    if(DEBUG_SLICE) cout << "[slice] " << "assignment: " << ap->format();
    //cout << "  ";
    //cout << ap->insn().readsMemory();
    if(DEBUG_SLICE) cout << endl;

    slicedMoreThanOneStep = true;
    if (filter) {
      if (!foundFilteredReg) {
        if(DEBUG_SLICE) cout << "[slice] " << "Intended reg not found, ignoring assignment: " << ap->format();
        return false;
      }
    }
    init = false;
    filter = false;
    if (ap->insn().readsMemory()) {

      std::set<Expression::Ptr> memReads;
      ap->insn().getMemoryReadOperands(memReads);
      if(DEBUG) cout << "[sa] Memory read: " << (*memReads.begin())->format() << endl;

      int id = ap->insn().getOperation().getID();
      if (id == e_cmp) {
        MachRegister machReg; long off=0;
        getRegAndOff(*memReads.begin(), &machReg, &off); //TODO, sometimes, even non mem reads can have an offset?
        if (machReg == InvalidReg) {
          cout << "Compare with constant do not load memory right?" << endl;
          return false;
        }
      }

      std::string readStr = (*memReads.begin())->format();
      if (std::any_of(std::begin(readStr), std::end(readStr), ::isalpha)) { // TODO, does this make sense?
	      if (DEBUG) cout << "[sa] is a true memory read." << endl;
	      return true;
      }
      if (DEBUG) cout << "[sa] is not a true memory read." << endl;
	    return false;
    } else {
      return false;
    }
  }

  //int i = 5;
  virtual bool addPredecessor(AbsRegion reg) {
    std:string regStr = reg.format();
    if (DEBUG || DEBUG_SLICE) cout << endl;
    if (DEBUG || DEBUG_SLICE) cout << "[slice] Should add the dataflow predecessor?" << endl;
    if (DEBUG_SLICE) cout << "[slice] should stop slicing? " << atEndPoint << endl;
    if (atEndPoint == true) return false;
    if (DEBUG_SLICE) cout << "[slice] " << "predecessor reg: " << regStr << endl;
    if (init && insn.readsMemory()) return false; //TODO, actually could have multiple data dependencies, not just a memory read! need to handle this corner case sometimes
    if (filter) {
      if (reg.format().compare(regName) != 0) {
	      if(DEBUG_SLICE) cout << "[slice] " << "Filtering against " << regName <<
	       				      " filter out: " << regStr << endl;
        return false;
      } else {
        foundFilteredReg = true;
      }
    }

    if (init) {
      std::vector<Operand> ops;
      insn.getOperands(ops);
      AbsRegionConverter arc(true, false);
      for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
        if (!(*oit).writesMemory()) continue;

        if (DEBUG || DEBUG_SLICE) cout << "[slice] memory write op: " << (*oit).format(insn.getArch()) << endl;
        std::set<RegisterAST::Ptr> regsRead;
        (*oit).getReadSet(regsRead);
        for (auto rit = regsRead.begin(); rit != regsRead.end(); ++rit) {
          AbsRegion curr = arc.convert(*rit);
          if (DEBUG || DEBUG_SLICE) cout << "[slice] reg read: " << curr.format() << endl;
          if (curr == reg) {
            if (DEBUG || DEBUG_SLICE) cout << "[sa] register is a memory address, ignore..." << endl;
            return false;
          }
        }
      }
    }
    if (regStr.rfind("[x86", 0) == 0) {
      //if (std::any_of(std::begin(regStr), std::end(regStr), ::isalpha)){
      if (DEBUG) cout << "[sa] is a true reg: " << regStr << endl;
      return true;
    } else {
      if (DEBUG) cout << "[sa] is not a true reg: " << regStr << endl;
      return false;
    }
    return true; // TODO should be redundant...
    //i --;
    //return i > 0;
    //return false;
  }
};

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

// by the time a block is visited, all its children has been visited
void getReversePostOrderListHelper(Block *b,
                                   std::vector<Block *> &list,
                                   boost::unordered_set<Block *> &visited) {

  if (DEBUG) cout << "[postorder] Visiting " << std::hex << b->start() << std::dec << endl;
  if (visited.find(b) != visited.end()) {
    if (DEBUG) cout << "[postorder] Already visited " << endl;
    return;
  }

  Block::edgelist targets = b->targets();
  visited.insert(b);

  for (auto it = targets.begin(); it != targets.end(); it++) {
    if ((*it)->type() == CALL || (*it)->type() == RET || (*it)->type() == CATCH)
      continue;
    Block* src = (*it)->src();
    Block* trg = (*it)->trg();
    getReversePostOrderListHelper(trg, list, visited);
  }
  list.push_back(b);
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

void printReachableStores(boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> &reachableStores) {
  for (auto mit = reachableStores.begin(); mit != reachableStores.end(); mit++) {
    StackStore ss = (*mit).first;
    boost::unordered_map<Address, Function *> s = (*mit).second;
    cout << "[stack]          stack store: " << ss.format() << " @ "  << std::hex;
    for (auto sit = s.begin(); sit != s.end(); sit++) {
      cout << (*sit).first << std::dec << " " << (*sit).second->name() << " ";
    }
    cout << std::dec << endl;
  }
}

void getRegAndOff(Expression::Ptr exp, MachRegister *machReg, long *off) {
  RegisterAST::Ptr regAST = boost::dynamic_pointer_cast<RegisterAST>(exp);
  if (regAST != NULL) {
    (*machReg) = regAST->getID();
    if (DEBUG_STACK && DEBUG)
      cout << "[stack]   found register: " << machReg->name() << endl; //TODO
  } else {
    Immediate::Ptr immedAST = boost::dynamic_pointer_cast<Immediate>(exp);
    if (immedAST != NULL) {
      std::stringstream ss;
      ss << std::hex << immedAST->format();
      ss >> (*off);
      if (DEBUG_STACK && DEBUG)
        cout << "[stack]   found immediate: " << *off << endl;//TODO
    }
  }

  std::vector<Expression::Ptr> children;
  exp->getChildren(children);
  for (auto vit = children.begin(); vit != children.end(); vit++) {
    getRegAndOff(*vit, machReg, off);
  }
}

void getRegAndOff(Expression::Ptr exp, std::vector<MachRegister> &machRegs, long *off) { // TODO, add to declaration
  RegisterAST::Ptr regAST = boost::dynamic_pointer_cast<RegisterAST>(exp);
  if (regAST != NULL) {
     machRegs.push_back(regAST->getID());
    if (DEBUG_STACK && DEBUG)
      cout << "[stack]   found register: " << regAST->getID().name() << endl; //TODO
  } else {
    Immediate::Ptr immedAST = boost::dynamic_pointer_cast<Immediate>(exp);
    if (immedAST != NULL) {
      std::stringstream ss;
      ss << std::hex << immedAST->format();
      ss >> (*off);
      if (DEBUG_STACK && DEBUG)
        cout << "[stack]   found immediate: " << *off << endl;//TODO
    }
  }

  std::vector<Expression::Ptr> children;
  exp->getChildren(children);
  for (auto vit = children.begin(); vit != children.end(); vit++) {
    getRegAndOff(*vit, machRegs, off);
  }
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

boost::unordered_map<Address, Function *> checkAndGetStackWrites(Function *f, Instruction readInsn, Address readAddr,
                                        MachRegister readReg, long readOff, int initHeight, int level) {
  cout << "[stack] Checking function: " << f->name() << " for "
       << readReg.name() << " + " << readOff << " @ " << readInsn.format() << endl;
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
  boost::unordered_map<Address, Function *> ret = checkAndGetStackWritesHelper(&resultIntractable, f, list, insnToStackHeight, readAddrs, stackRead, level);
  if (resultIntractable) ret.clear();
  return ret;
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

void inline get_indirect_write_to_stack(Instruction insn, Address addr, Block *b, Function *f,
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

boost::unordered_map<Address, Function *> checkAndGetStackWritesHelper(bool *resultIntractable,
                                                            Function *f,
                                                            std::vector<Block *> &list,
                                                           boost::unordered_map<Address, long> &insnToStackHeight,
                                                           boost::unordered_set<Address> &readAddrs,
                                                           StackStore &stackRead, int level) {
  //if (DEBUG_STACK)
    cout << "[stack] Looking for writes in function " << f->name()
         << " at level " << level << " for " << stackRead << endl;
  boost::unordered_map<Address, boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>>>
      insnToReachableStores; //FIXME if I'm more comfortable with pointers store pointers instead ...

  for (auto bit = list.begin(); bit != list.end(); bit++) {
    Block::Insns insns;
    Block *b = *bit;
    b->getInsns(insns);
    for (auto iit = insns.begin(); iit != insns.end(); iit++) {
      Address addr = (*iit).first;
      Instruction insn = (*iit).second;
      if (DEBUG && DEBUG_STACK)
        cout << "[stack] checking instruction: " << insn.format() << " @" << std::hex << addr << std::dec << endl;
      boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> reachableStores;

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
              boost::unordered_map<Address, Function *> ret =
                  checkAndGetStackWritesHelper(resultIntractable, caller, callerList, callerInsnToStackHeight, cuuReadAddrs, stackRead,
                                               level - 1);
              allRets.insert(ret.begin(), ret.end());

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
            boost::unordered_map<Address, Function *> ret =
                checkAndGetStackWritesHelper(resultIntractable, callee, calleeList, calleeInsnToStackHeight, readAddrs, stackRead,
                                             level + 1);
            allRets.insert(ret.begin(), ret.end());

            if (DEBUG_STACK && DEBUG)
              cout << "[stack] looked for stores" // at " << std::hex << addr << std::dec
                   << " from callee " << callee->name()
                   << " currently found " << allRets.size() << " stores " << endl;
          }
        }
        if (allRets.size() > 0) {
          reachableStores.insert({stackRead, allRets});
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
              boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> reachableIndirectStores;
              insnToReachableStores.insert({useAddr, reachableIndirectStores});
            }
            boost::unordered_map<Address, Function*> s;
            s.insert({useAddr, f});
            insnToReachableStores[useAddr].insert({stackStore, s});
            //printReachableStores(insnToReachableStores[useAddr]);
          }
        }
      }

      std::vector<Operand> ops;
      insn.getOperands(ops);
      for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
        Operand op = *oit;
        if (!writesToStack(op, insn, addr)) continue;
        boost::unordered_map<Address, Function*> s;
        s.insert({addr, f});
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
          reachableStores.insert({stackRead, s}); // should not have duplicates
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
      boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> prevReachableStores;
      Block::edgelist sources = b->sources();
      for (auto eit = sources.begin(); eit != sources.end(); eit++) {
        if ((*eit)->type() == CALL || (*eit)->type() == RET || (*eit)->type() == CATCH)
          continue;
        Block* src = (*eit)->src();
        Block* trg = (*eit)->trg();
        assert(trg == b);
        if (DEBUG && DEBUG_STACK) cout << "[stack]     predecessor block " << src->start() << " to " << src->end() << endl;
        boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> predReachableStores =
            insnToReachableStores[src->last()];
        for (auto mit = predReachableStores.begin(); mit != predReachableStores.end(); mit++) {
          StackStore ss = (*mit).first;
          boost::unordered_map<Address, Function *> s = (*mit).second;
          if (prevReachableStores.find(ss) == prevReachableStores.end()) {
            prevReachableStores.insert({ss, s}); // Should be a separate copy otherwise wouldn't work
            // also, it should be ok to not overwrite here
          } else {
            for (auto sit = s.begin(); sit != s.end(); sit++) {
              prevReachableStores[ss].insert(*sit); // FIXME: beware, if a key already exists will not insert
            }
          }
        }
      }
      if (DEBUG && DEBUG_STACK) cout << "[stack] aggregated stack stores from predecessors:" << endl;
      if (DEBUG && DEBUG_STACK) printReachableStores(prevReachableStores);

      for (auto iit = insns.begin(); iit != insns.end(); iit++) {
        Address addr = (*iit).first;
        Instruction insn = (*iit).second;
        if (DEBUG_STACK && DEBUG)
          cout << "[stack] Working on instruction: " << insn.format()
                                       << " @" << std::hex << addr << std::dec << endl;

        boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> currReachableStores =
            insnToReachableStores[addr];

        /*
        if (addr != b->start() && addr != b->last() && currReachableStores.size() == 0) {
          continue;
        }*/

        if (DEBUG && DEBUG_STACK) cout << "[stack]   stack stores before update:" << endl;
        if (DEBUG && DEBUG_STACK) printReachableStores(insnToReachableStores[addr]);
        for (auto mit = currReachableStores.begin(); mit != currReachableStores.end(); mit++) {
          StackStore ss = (*mit).first;
          boost::unordered_map<Address, Function *> s = (*mit).second;
          prevReachableStores[ss] = s;
        }
        if (DEBUG && DEBUG_STACK) printReachableStores(prevReachableStores);

        if (currReachableStores.size() != prevReachableStores.size()) {
          changed = true;
        } else {
          for (auto mit = currReachableStores.begin(); mit != currReachableStores.end(); mit++) {
            StackStore ss = (*mit).first;
            /*
            if (prevReachableStores.find(ss) == prevReachableStores.end()) {
              changed = true;
              break;
            }*/

            boost::unordered_map<Address, Function *> s1 = (*mit).second;
            boost::unordered_map<Address, Function *> s2 = prevReachableStores[ss];
            if (s1.size() != s2.size()) {
              changed = true;
              break;
            }

            for (auto sit = s1.begin(); sit != s1.end(); sit++) {
              Address currAddr = (*sit).first;
              Function *currFunc = (*sit).second;
              if (s2.find(currAddr) == s2.end()) {
                changed = true;
                break;
              }
              if (s1[currAddr] != s2[currAddr]) {
                changed = true;
                break;
              }
            }
            if (changed) break;
          }
        }

        insnToReachableStores[addr] = prevReachableStores;

        if (DEBUG_STACK && DEBUG)
          cout << "[stack]   stack stores after update:" << endl;
        if (DEBUG_STACK && DEBUG)
          printReachableStores(insnToReachableStores[addr]);

        //prevReachableStores = currReachableStores;
        if (DEBUG && DEBUG_STACK) cout << "[stack]   stack stores from previous instructions:" << endl;
        if (DEBUG && DEBUG_STACK) printReachableStores(prevReachableStores);
        if (DEBUG && DEBUG_STACK) cout << "[stack]" << endl;
      }
    }
  }
  boost::unordered_map<Address, Function *> ret;
  //bool stackWritesIntractable = false;
  for (auto rait = readAddrs.begin(); rait != readAddrs.end(); rait++) {
    Address readAddr = *rait;
    // << "[stack] current stack read addr is: " << std::hex << readAddr << std::dec << endl;
    boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> currResults =
        insnToReachableStores[readAddr];
    for (auto crit = currResults.begin(); crit != currResults.end(); crit++) {
      if ((*crit).first == stackRead) {
        if ((*crit).first.isSpecial) {
          *resultIntractable = true;
        }
      }
    }
    boost::unordered_map<Address, Function *> &curr = insnToReachableStores[readAddr][stackRead];
    ret.insert(curr.begin(), curr.end()); // FIXME maybe assert no duplicate
  }
  //if (stackWritesIntractable) return ret.clear();  //TODO
  return ret;
}

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
      // (DEBUG) printReachableStores(prevReachableStores);

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
        //if (DEBUG && DEBUG_STACK) printReachableStores(insnToReachableStores[addr]);

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
        //  printReachableStores(insnToReachableStores[addr]);

        //prevReachableStores = currReachableStores;
        //if (DEBUG) cout << "[sa]   stores to static addresses from previous instructions:" << endl;
        //if (DEBUG) printReachableStores(prevReachableStores);
        //if (DEBUG) cout << "[sa]" << endl;
      }
    }
  }
  return insnToReachableStores[readAddr][readOff];
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

std::string getReadStr(Instruction insn, bool *regFound) {
  // TODO, refactor this function!
  Expression::Ptr read;
  std::string readStr;

  std::set<Expression::Ptr> memReads;
  insn.getMemoryReadOperands(memReads);
  if (memReads.size() > 0) { // prioritize reads from memory
    assert (memReads.size() == 1);
    Expression::Ptr read = *memReads.begin();
    if (INFO) cout << "[sa] Memory read: " << read->format() << endl;
    readStr.append("memread|");
    readStr.append(read->format());
  } else { // then check reads from register
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
  bool regFound = false;
  std::string readStr = getReadStr(newInsn, &regFound);
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
      regName = "";
    }
  }

  if (INFO) cout << "[sa] insn: " << insn.format() << endl;
  if (INFO) cout << "[sa] reg: " << regName << endl;
  if (INFO) cout << endl;

  bool madeProgress = true;
  GraphPtr slice = buildBackwardSlice(func, bb, insn, addr, regName, &madeProgress, atEndPoint);

  MachRegister stackReadReg; long stackReadOff;
  bool inputInsnReadsFromStack = readsFromStack(insn,addr, &stackReadReg, &stackReadOff);
  cout << "[sa] input instruction reads from stack? " << inputInsnReadsFromStack << endl;
  if (!inputInsnReadsFromStack) {
    if (strcmp(regName, "") != 0 && !madeProgress && !atEndPoint) {
      AssignmentConverter ac(true, false);
      vector<Assignment::Ptr> assignments;
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
      boost::unordered_map<Address, Function *> ret;
      boost::unordered_set<Address> visitedAddrs;
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
        backwardSliceHelper(stcs, co, json_reads, visited, progName, newFuncName, newAddr, newRegName, isKnownBitVar, atEndPoint);
      }
      return;
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
    if (memWrites.size() > 1) {
      cout << "[sa][warn] Instruction has more than one memory write? " << insn.format() << endl;
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
          backwardSliceHelper(stcs, co, json_reads, visited, progName, funcName, *wit, "", isKnownBitVar);
        }
        continue;
      }
    }

    if (INFO) cout << "[sa] checking result instruction: " << assign->insn().format() << endl;

    bool regFound = false;
    std::string readStr = getReadStr(assign->insn(), &regFound);

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

void analyzeKnownBitVariables(GraphPtr slice,
                        Expression::Ptr memWrite,
                        boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariables,
                        boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariablesToIgnore,
                        boost::unordered_map<Assignment::Ptr, AbsRegion> &bitOperands,
                        boost::unordered_map<Assignment::Ptr, std::vector<Assignment::Ptr>> &bitOperations
) {

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

void locateBitVariables(GraphPtr slice, 
		  boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariables,
		  boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariablesToIgnore,
		  boost::unordered_map<Assignment::Ptr, AbsRegion> &bitOperands,
		  boost::unordered_map<Assignment::Ptr, std::vector<Assignment::Ptr>> &bitOperations
		) {

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

cJSON *printBBIdsToJsonHelper(BPatch_Vector<BPatch_basicBlock *> &bbs) {
  cJSON *json_bbs  = cJSON_CreateArray();
  for (int i=0; i<bbs.size(); i++) {
    BPatch_basicBlock *bb = bbs[i];
    cJSON *json_bb  = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_bb, "id", bb->getBlockNumber());
    cJSON_AddItemToArray(json_bbs, json_bb);
  }
  return json_bbs;
}

cJSON *printBBsToJsonHelper(BPatch_Vector<BPatch_basicBlock *> &bbs,
                            boost::unordered_map<BPatch_basicBlock *,
                                                 BPatch_Vector<BPatch_basicBlock *>> *backEdges) {
  cJSON *json_bbs = cJSON_CreateArray();
  for(auto it = bbs.begin(); it != bbs.end(); ++it) {
    //out << std::hex << (*it)->getStartAddress() << endl;
    BPatch_basicBlock *bb = *it;
    cJSON *json_bb  = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_bb, "id", bb->getBlockNumber());
    cJSON_AddNumberToObject(json_bb, "start_insn", bb->getStartAddress());
    cJSON_AddNumberToObject(json_bb, "end_insn", bb->getLastInsnAddress());

    vector <Instruction> insns;
    bb->getInstructions(insns);
    Instruction ret = *insns.rbegin();
    int isBranch = (ret.getCategory() == InsnCategory::c_BranchInsn) ? 1 : 0;
    cJSON_AddNumberToObject(json_bb, "ends_in_branch", isBranch);
    int isEntry = (bb->isEntryBlock() == true) ? 1 : 0;
    cJSON_AddNumberToObject(json_bb, "is_entry", isEntry);

    BPatch_Vector<BPatch_basicBlock *> predes;
    bb->getSources(predes);
    cJSON_AddItemToObject(json_bb, "predes",  printBBIdsToJsonHelper(predes));

    BPatch_Vector<BPatch_basicBlock *> succes;
    bb->getTargets(succes);
    cJSON_AddItemToObject(json_bb, "succes",  printBBIdsToJsonHelper(succes));

    BPatch_basicBlock * immedDom = bb->getImmediateDominator();
    if (immedDom != NULL)
      cJSON_AddNumberToObject(json_bb, "immed_dom",  immedDom->getBlockNumber());

    if (backEdges != NULL) {
      if (backEdges->find(bb) != backEdges->end()) {
        cJSON_AddItemToObject(json_bb, "backedge_targets",  printBBIdsToJsonHelper((*backEdges)[bb]));
      }
    }

    // TODO: optimize this by putting it into one string?
    cJSON *json_lines = cJSON_CreateArray();
    vector<unsigned short> allLines;
    getLineInfo(bb, allLines);
    for (auto it = allLines.begin(); it != allLines.end(); it++) {
      cJSON *json_line  = cJSON_CreateObject();
      cJSON_AddNumberToObject(json_line, "line", *it);
      cJSON_AddItemToArray(json_lines, json_line);
    }
    cJSON_AddItemToObject(json_bb, "lines", json_lines);


cJSON_AddItemToArray(json_bbs, json_bb);
  }
  return json_bbs;
}

extern "C" {
long unsigned int getImmedDom(char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the immediate control flow dominator: " << endl;
  if(DEBUG) cout << "[sa] prog: " << progName << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr <<  std::dec << endl;
  if(DEBUG) cout << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
  //  return NULL;
  //}
  SymtabCodeSource *stcs = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  Function *func = getFunction2(stcs, co, funcName);
  Block *immedDom = getImmediateDominator2(func, addr);
  //Instruction ifCond = getIfConditionAddr2(immedDom);
  if(DEBUG) cout << "[sa] immed dom: " << immedDom->last() << endl;
  delete stcs;
  delete co;
  return immedDom->last();

}


void getAllBBs(char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting all control flow predecessors: " << endl;
  if(DEBUG) cout << "[sa] prog: " << progName << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr <<  std::dec << endl;
  if(DEBUG) cout << endl;
  BPatch_image *appImage = getImage(progName);
  vector<BPatch_basicBlock *> bbs;
  boost::unordered_map<BPatch_basicBlock *, BPatch_Vector<BPatch_basicBlock *>> backEdges;
  BPatch_function *f = getFunction(appImage, funcName);
  if (f != NULL) {
    BPatch_flowGraph *fg = f->getCFG();

    BPatch_Vector < BPatch_basicBlockLoop * > loops;
    fg->getLoops(loops);
    for (int i = 0; i < loops.size(); i++) {
      BPatch_basicBlockLoop *loop = loops[i];
      std::vector<BPatch_edge *> edges;
      loop->getBackEdges(edges);
      for (auto it = edges.begin(); it != edges.end(); it++) {
        BPatch_edge *edge = *it;
        BPatch_basicBlock *source = edge->getSource();
        BPatch_basicBlock *target = edge->getTarget();
        backEdges[source].push_back(target);
      }
    }

    set<BPatch_basicBlock *> blocks;
    fg->getAllBasicBlocks(blocks);
    for (auto blockIter = blocks.begin();
         blockIter != blocks.end();
         ++blockIter) {
      BPatch_basicBlock *block = *blockIter;

      if (addr >= block->getStartAddress() && addr < block->getEndAddress()) {
        bbs.insert(bbs.begin(), block);
      } else {
        bbs.push_back(block);
      }
    }
  } else {
    cout << "[sa][warn] Ignoring function " << funcName << " for now enable to load..." << endl;
    //TODO consider using parseAPI later?
  }
  std::ofstream out("getAllBBs_result");
  cJSON *json_bbs = printBBsToJsonHelper(bbs, &backEdges);

  char *rendered = cJSON_Print(json_bbs);
  cJSON_Delete(json_bbs);
  out << rendered;
  out.close();
  if(DEBUG) cout << "[sa] all results saved to \"getAllPredes_result\"";
  if(DEBUG) cout << endl;
  return;
}

void getAllPredes(char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting all control flow predecessors: " << endl;
  if(DEBUG) cout << "[sa] prog: " << progName << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr  <<  std::dec << endl;
  if(DEBUG) cout << endl;
  BPatch_image *appImage = getImage(progName);
  vector<BPatch_basicBlock *> predes;
  getAllControlFlowPredecessors(predes, appImage, funcName, addr);

  std::ofstream out("getAllPredes_result");
  cJSON *json_bbs = printBBsToJsonHelper(predes);

  char *rendered = cJSON_Print(json_bbs);
  cJSON_Delete(json_bbs);
  out << rendered;
  out.close();
  if(DEBUG) cout << "[sa] all results saved to \"getAllPredes_result\"";
  if(DEBUG) cout << endl;
  return;
}

long unsigned int getFirstInstrInBB(char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the first instruction of the basic block: " << endl;
  if(DEBUG) cout << "[sa] prog: " << progName << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
  //  return NULL;
  //}
  SymtabCodeSource *stcs = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  Function *func = getFunction2(stcs, co, funcName);
  Block *bb = getBasicBlock2(func, addr);
  //Instruction ifCond = getIfConditionAddr2(immedDom);
  if(DEBUG) cout << "[sa] first instr: " << bb->start() << endl;

  delete stcs;
  delete co;

  return bb->start();

}

long unsigned int getLastInstrInBB(char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the last instruction of the basic block: " << endl;
  if(DEBUG) cout << "[sa] prog: " << progName << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
  //  return NULL;
  //}
  SymtabCodeSource *stcs = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  Function *func = getFunction2(stcs, co, funcName);
  Block *bb = getBasicBlock2(func, addr);
  //Instruction ifCond = getIfConditionAddr2(immedDom);
  if(DEBUG) cout << "[sa] last instr: " << bb->last() << endl;

  delete stcs;
  delete co;

  return bb->last();
}

long unsigned int getInstrAfter(char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the instruction after: " << endl;
  if(DEBUG) cout << "[sa] prog: " << progName << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
  //  return NULL;
  //}
  SymtabCodeSource *stcs = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  Function *func = getFunction2(stcs, co, funcName);
  Block *bb = getBasicBlock2(func, addr);
  Block::Insns insns;
  bb->getInsns(insns);
  long unsigned int nextInsn = addr;
  bool return_next = false;
  for (auto it = insns.begin(); it != insns.end(); it++) {
    if (return_next) {
      nextInsn = it->first;
      break;
    }
    if (it->first == addr) {
      return_next = true;
    }
  }
  if (nextInsn == addr)
    nextInsn = bb->end();
  //Instruction ifCond = getIfConditionAddr2(immedDom);
  if(DEBUG) cout << "[sa] instr after: " << nextInsn << endl;
  delete stcs;
  delete co;
  return nextInsn;
}

void getImmedPred(char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the immediate control flow predecessor: " << endl;
  if(DEBUG) cout << "[sa] prog: " << progName << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
  //  return NULL;
  //}
  SymtabCodeSource *stcs = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  Function *func = getFunction2(stcs, co, funcName);
  Block *immedDom = getImmediateDominator2(func, addr);
  Instruction ifCond = getIfCondition2(immedDom);
  //TODO
  delete stcs;
  delete co;
}

void getCalleeToCallsites(char *progName) {
  if (DEBUG) cout << "[sa] ================================" << endl;
  if (DEBUG) cout << "[sa] prog: " << progName << endl;

  SymtabAPI::Symtab *symTab;
  //string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", progName);
  //  return;
  //}
  SymtabCodeSource *sts = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(sts);
  co->parse();
  const CodeObject::funclist &all = co->funcs();
  if (all.size() == 0) {
    fprintf(stderr, "No function in file %s.\n", progName);
    return;
  }

  boost::unordered_map<Function *, std::vector<std::pair<Function *, Address>>>
      functionToCallsite;
  for (auto fit = all.begin(); fit != all.end(); ++fit) {
    Function *f = *fit;
    if (DEBUG) cout << "[sa] current function: " << f->name() << endl;
    Function::edgelist list = f->callEdges();
    for(auto cit = list.begin(); cit != list.end(); cit++) {
      Block* src = (*cit)->src();
      Block* trg = (*cit)->trg();
      Function *trg_func = co->findFuncByEntry(trg->region(), trg->start());
      if (trg_func == NULL) {
        if (DEBUG) cout << "[sa]   function not found at: " << trg->start() << endl;
        continue;
      }
      if (DEBUG) cout << "[sa]   calls function: " << trg_func->name() << endl;
      Block::Insns insns;
      src->getInsns(insns);
      long unsigned int addr = 0;
      Instruction insn;
      for (auto iit = insns.begin(); iit != insns.end(); iit++) { //TODO is call
        insn = (*iit).second;
        if (DEBUG) cout << "[sa]   checking src insn: " << insn.format() << endl;
        if (insn.getCategory() != c_CallInsn && insn.getCategory() != c_BranchInsn) continue;
        addr = (*iit).first;
      }
      functionToCallsite[trg_func].push_back(std::pair<Function *, Address>(f, addr));
    }
  }

  cJSON *json_funcs  = cJSON_CreateArray();
  for (auto mit = functionToCallsite.begin(); mit != functionToCallsite.end(); mit++) {
    Function *f = mit->first;
    std::vector<std::pair<Function *, Address>> callsites = mit->second;
    cJSON *json_func = cJSON_CreateObject();
    cJSON_AddStringToObject(json_func, "func", f->name().c_str());
    cJSON *json_callsites  = cJSON_CreateArray();
    for (auto cit = callsites.begin(); cit != callsites.end(); cit++) {
      cJSON *json_callsite = cJSON_CreateObject();
      cJSON_AddNumberToObject(json_callsite, "insn_addr", cit->second);
      cJSON_AddStringToObject(json_callsite, "func_name", cit->first->name().c_str());
      cJSON_AddItemToArray(json_callsites, json_callsite);
    }
    cJSON_AddItemToObject(json_func, "callsites",  json_callsites);
    cJSON_AddItemToArray(json_funcs, json_func);
  }

  char *rendered = cJSON_Print(json_funcs);
  cJSON_Delete(json_funcs);
  std::ofstream out("functionToCallSites_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"functionToCallSites_result\"";
  if(DEBUG) cout << endl;
  delete sts;
  delete co;
}

void getMemWrites(char *addrToFuncNames, char *progName) {
  if (DEBUG) cout << "[sa] ================================" << endl;
  if (DEBUG) cout << "[sa] Getting memory writes for instructions: " << endl;
  if (DEBUG) cout << "[sa] addr to func: " << addrToFuncNames << endl;
  if (DEBUG) cout << "[sa] prog: " << progName << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
  //  return NULL;
  //}
  SymtabCodeSource *stcs = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  cJSON *json_insns = cJSON_CreateArray();

  cJSON *json_addrToFuncNames = cJSON_Parse(addrToFuncNames);
  int size = cJSON_GetArraySize(json_addrToFuncNames);
  if (DEBUG) cout << "[sa] size of addr to func array is:　" << size << endl;
  for (int i = 0; i < size; i++) {
    cJSON *json_pair = cJSON_GetArrayItem(json_addrToFuncNames, i);
    cJSON *json_funcName = cJSON_GetObjectItem(json_pair, "func_name");
    cJSON *json_addr = cJSON_GetObjectItem(json_pair, "addr");

    errno = 0;
    char *end;
    cout << json_addr->valuestring << endl;
    long unsigned int addr = strtol(json_addr->valuestring, &end, 10);
    if (errno != 0)
      cout << " Encountered error " << errno << " while parsing " << json_addr->valuestring << endl;
    char *funcName = json_funcName->valuestring;

    cJSON *json_insn  = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_insn, "addr", addr);
    cJSON_AddStringToObject(json_insn, "func_name", funcName);

    // parse string here, can the string be a json?
    if (INFO) cout << endl << "[sa] addr: 0x" << std::hex << addr << std::dec << endl;
    if (INFO) cout << "[sa] func: " << funcName << endl;

    Function *func = getFunction2(stcs, co, funcName);
    Block *bb = getBasicBlock2(func, addr);
    Instruction insn = bb->getInsn(addr);
    long unsigned int trueAddr = 0;
    int isLoopInsn = 0; //TODO: fix the casings
    if (insn.getOperation().getPrefixID() == prefix_rep ||
        insn.getOperation().getPrefixID() == prefix_repnz) {
      // Is a looped move
      trueAddr = addr;
      isLoopInsn = 1;
      if (INFO) cout << "[sa] special looped move: ID: "
                     << insn.getOperation().getID()  << " op: "
                     << insn.getOperation().format() << endl;
    } else if (func->entry() == bb && bb->start() == addr) {
      // Instruction is already the first in the function
      if (INFO) cout << "[sa] instruction is the first in the function: " << insn.format() << endl;
      trueAddr = addr;
    } else {
      bb = getBasicBlockContainingInsnBeforeAddr(func, addr);
      //Instruction insn;
      Block::Insns insns;
      bb->getInsns(insns);
      for (auto it = insns.begin(); it != insns.end(); it++) {
        //cout << "[tmp] " << std::hex << (*it).first  << " " << (*it).second.format() << endl;
        if ((*it).first == addr)
          break;
        trueAddr = (*it).first;
        insn = (*it).second;
      }
    }
    if (INFO) cout << "[sa] insn: " << insn.format() << endl;
    cJSON_AddNumberToObject(json_insn, "true_addr", trueAddr);
    cJSON_AddNumberToObject(json_insn, "is_loop_insn", isLoopInsn);

    cJSON *json_writes = cJSON_CreateArray();
    std::set<Expression::Ptr> memWrites;
    insn.getMemoryWriteOperands(memWrites);
    for (auto wit = memWrites.begin(); wit != memWrites.end(); wit ++) {
      Expression::Ptr write = *wit;
      if (INFO) cout << "[sa] Memory write: " << write->format() << endl;
      std::string writeStr;
      writeStr.append("memwrite|");
      writeStr.append(write->format());
      if (!std::any_of(std::begin(writeStr), std::end(writeStr), ::isalpha)) {
        cout << "[sa][warn] Memory write expression has not register in it? " << writeStr << endl;
      }
      cJSON *json_write = cJSON_CreateObject();
      cJSON_AddStringToObject(json_write, "expr", writeStr.c_str());
      cJSON_AddItemToArray(json_writes, json_write);
    }
    std::vector<Operand> ops;
    insn.getOperands(ops);
    // TODO is this good enough?
    cJSON_AddStringToObject(json_insn, "src", ops.rbegin() != ops.rend() ? (*ops.rbegin()).format(insn.getArch()).c_str() : "");
    cJSON_AddItemToObject(json_insn, "writes", json_writes);
    cJSON_AddItemToArray(json_insns, json_insn);
    if (DEBUG) cout << endl;
  }
  char *rendered = cJSON_Print(json_insns);
  cJSON_Delete(json_insns);
  std::ofstream out("writesPerInsn_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"writesPerInsn_result\"";
  if(DEBUG) cout << endl;
  delete stcs;
  delete co;
}

//TODO: make it less hacky!
void getNestedMemWritesToStaticAddresses(
    boost::unordered_map<Address, std::pair<Block*, Function*>> staticWriteInsns,
    char *progName) {
  if (DEBUG) cout << "[sa] ================================" << endl;
  if (DEBUG) cout << "[sa] prog: " << progName << endl;
  cJSON *json_insns = cJSON_CreateArray();
  AssignmentConverter ac(true, false);
  for (auto it = staticWriteInsns.begin(); it != staticWriteInsns.end(); it++) {

    Address target_addr = (*it).first; //TODO, change others to valueint and not string!
    Function *f = (*it).second.second;
    Block *b = (*it).second.first;

    Block::Insns insns;
    b->getInsns(insns);
    AbsRegion region;
    MachRegister targetReg;
    bool found = false;
    for (auto iit = insns.rbegin(); iit != insns.rend(); iit++) {
      long unsigned int addr = (*iit).first;
      Instruction insn = (*iit).second;
      //cout << insn.format() << endl;

      if (addr == target_addr) {
        vector<Assignment::Ptr> assignments;
        ac.convert(insn, addr, f, b, assignments);
        //cout << assignments.size() << endl;
        if (assignments.size() != 1) continue;
        Assignment::Ptr assign = *assignments.begin();
        if (assign->inputs().size() != 1) continue;
        found = true;
        region = *(assign->inputs().begin());
        targetReg = region.absloc().reg();
        //cout << assign->inputs().size() << endl;
        //cout << insn.format() << " " << assign->format() << endl;
        //cout << "HERE " << assign->format() << " " << region.format() << endl;
        continue;
      }
      if (found == true) {
        std::set<Expression::Ptr> memWrites;
        insn.getMemoryWriteOperands(memWrites);
        if (memWrites.size() != 1) continue;
        Expression::Ptr write = NULL;
        for (auto it = memWrites.begin(); it != memWrites.end(); it++) {
          //cout << "HERE1 " << (*it)->format() << endl;
          MachRegister machReg; long off = 0;
          getRegAndOff(*it, &machReg, &off);
          //cout << "MACHINE: " << machReg.name() << endl;
          if (targetReg == machReg) {
            //cout << "FOUND" << endl;
            write = *it;
            break;
          }
        }
        if (write != NULL) {
          cJSON *json_insn  = cJSON_CreateObject();
          cJSON_AddNumberToObject(json_insn, "target_addr", target_addr);
          cJSON_AddNumberToObject(json_insn, "addr", addr);
          cJSON_AddStringToObject(json_insn, "func_name", f->name().c_str()); //TODO

          cJSON_AddNumberToObject(json_insn, "true_addr", addr);
          cJSON_AddNumberToObject(json_insn, "is_loop_insn", 0); //FIXME

          cJSON *json_writes  = cJSON_CreateArray();
          //std::string writeStr = write->format();
          std::string writeStr;
          writeStr.append("memwrite|");
          writeStr.append(write->format());
          cJSON *json_write = cJSON_CreateObject();
          cJSON_AddStringToObject(json_write, "expr", writeStr.c_str());
          cJSON_AddItemToArray(json_writes, json_write);

          std::vector<Operand> ops;
          insn.getOperands(ops);
          // TODO is this good enough?
          cJSON_AddStringToObject(json_insn, "src", ops.rbegin() != ops.rend() ? (*ops.rbegin()).format(insn.getArch()).c_str() : "");
          cJSON_AddItemToObject(json_insn, "writes", json_writes);
          cJSON_AddItemToArray(json_insns, json_insn);
        }
      }
    }
  }

  char *rendered = cJSON_Print(json_insns);
  cJSON_Delete(json_insns);
  std::ofstream out("nestedWritesToStaticAddr_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"nestedWritesToStaticAddr_result\"";
  if(DEBUG) cout << endl;
}

void getMemWritesToStaticAddresses(char *progName) {
  if (DEBUG) cout << "[sa] ================================" << endl;
  if (DEBUG) cout << "[sa] prog: " << progName << endl;

  string binaryPathStr(progName);
  //SymtabAPI::Symtab *symTab;
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", progName);
  //  return;
  //}

  SymtabCodeSource *sts = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(sts);

  co->parse();
  const CodeObject::funclist &all = co->funcs();
  if (all.size() == 0) {
    fprintf(stderr, "No function in file %s.\n", progName);
    return;
  }

  cJSON *json_writes  = cJSON_CreateArray();
  boost::unordered_map<Address, std::pair<Block*, Function*>> staticWriteInsns;
  for (auto fit = all.begin(); fit != all.end(); ++fit) {
    Function *f = *fit;
    for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
      Block *b = *bit;
      Block::Insns insns;
      b->getInsns(insns);
      for (auto iit = insns.begin(); iit != insns.end(); iit++) {
        long unsigned int addr = (*iit).first;
        Instruction insn = (*iit).second;
        std::set<Expression::Ptr> memWrites;
        insn.getMemoryWriteOperands(memWrites);
        // FIXME: For now just handle those that have one memory write.
        if (memWrites.size() != 1) continue;
        std::vector<Operand> ops;
        insn.getOperands(ops);
        bool isWriteAddrStatic = true;
        if (DEBUG) cout << "[sa] checking instruction: " << insn.format() << endl;
        if (ops.size() == 0) continue;
        bool writesMemory = false;
        for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
          if (!(*oit).writesMemory()) continue;
          writesMemory = true;
          if (DEBUG) cout << "[sa] memory write op: " << (*oit).format(insn.getArch()) << endl;
          std::set<RegisterAST::Ptr> regsRead;
          (*oit).getReadSet(regsRead);
          if (DEBUG) cout << "[sa] register read count: " << regsRead.size() << endl;
          if (!regsRead.empty()) {
            isWriteAddrStatic = false;
            break;
          }
          std::set<RegisterAST::Ptr> regsWrite;
          (*oit).getWriteSet(regsWrite);
          if (DEBUG) cout << "[sa] register write count: " << regsWrite.size() << endl;
          if (!regsWrite.empty()) {
            isWriteAddrStatic = false;
            break;
          }
        }
        if (!isWriteAddrStatic) continue;
        if (!writesMemory) continue;
        std::pair<Block*, Function*> pair(b, f);
        staticWriteInsns.insert({addr, pair});
        Expression::Ptr write = *memWrites.begin();
        std::string writeStr = write->format();
        if (DEBUG) cout << "[sa] memory write to static address: " << write->format() << endl;
        //if (!std::any_of(std::begin(writeStr), std::end(writeStr), ::isalpha)) {
        //  cout << "[sa][warn] Memory write expression has not register in it? " << writeStr << endl;
        //}
        cJSON *json_write = cJSON_CreateObject();
        cJSON_AddStringToObject(json_write, "func", f->name().c_str());
        cJSON_AddNumberToObject(json_write, "insn_addr", addr);
        cJSON_AddStringToObject(json_write, "expr", writeStr.c_str());
        cJSON_AddItemToArray(json_writes, json_write);
      }
    }
  }

  char *rendered = cJSON_Print(json_writes);
  cJSON_Delete(json_writes);
  std::ofstream out("writesToStaticAddr_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"writesToStaticAddr_result\"";
  if(DEBUG) cout << endl;

  getNestedMemWritesToStaticAddresses(staticWriteInsns, progName);
  delete sts;
  delete co;
}

void getRegsWritten(char *progName, char *funcName, long unsigned int addr) {
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the registers written to by the instruction: " << endl;
  if(DEBUG) cout << "[sa] prog: " << progName << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
  //  return NULL;
  //}
  SymtabCodeSource *stcs = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  Function *func = getFunction2(stcs, co, funcName);
  Block *bb = getBasicBlock2(func, addr);
  Instruction insn = bb->getInsn(addr);

  std::set<RegisterAST::Ptr> writtenRegs;
  insn.getWriteSet(writtenRegs);

  std::ofstream out("result");
  //std::stringstream ss;
  for (auto it = writtenRegs.begin(); it != writtenRegs.end(); it++) {
    if(DEBUG) cout << "[sa] Register written: " << (*it)->getID().name() << endl;
    out << "|"; //<< addr << ",";
    out << (*it)->getID().name();
  }
  out.close();
  delete stcs;
  delete co;
}

void backwardSlices(char *addrToRegNames, char *progName) {
  if (INFO) cout << "[sa] ================================" << endl;
  if (INFO) cout << "[sa] Making multiple backward slices: " << endl;
  if (INFO) cout << "[sa] addr to reg: " << addrToRegNames << endl; // FIXME: maybe change to insn to reg, addr is instruction addr
  if (INFO) cout << "[sa] prog: " << progName << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
  //  return NULL;
  //}
  SymtabCodeSource *stcs = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  cJSON *json_slices = cJSON_CreateArray();

  cJSON *json_sliceStarts = cJSON_Parse(addrToRegNames);
  int size = cJSON_GetArraySize(json_sliceStarts);
  if (DEBUG) cout << "[sa] size of addr to reg array is:　" << size << endl;
  for (int i = 0; i < size; i++) {
    cJSON *json_sliceStart = cJSON_GetArrayItem(json_sliceStarts, i);
    cJSON *json_regName = cJSON_GetObjectItem(json_sliceStart, "reg_name");
    cJSON *json_addr = cJSON_GetObjectItem(json_sliceStart, "addr");
    cJSON *json_funcName = cJSON_GetObjectItem(json_sliceStart, "func_name");
    cJSON *json_isBitVar = cJSON_GetObjectItem(json_sliceStart, "is_bit_var");

    errno = 0;
    char *end;
    long unsigned int addr = strtol(json_addr->valuestring, &end, 10);
    if (errno != 0)
      cout << " Encountered error " << errno << " while parsing " << json_addr->valuestring << endl;

    char *regName = json_regName->valuestring;
    char *funcName = json_funcName->valuestring;
    bool isKnownBitVar = json_isBitVar->valueint == 1;
    if (errno != 0)
      cout << " Encountered error " << errno << " while parsing " << json_isBitVar->valuestring << endl;

    cJSON *json_slice  = cJSON_CreateObject();
    cJSON_AddStringToObject(json_slice, "reg_name", regName);
    cJSON_AddNumberToObject(json_slice, "addr", addr);
    cJSON_AddStringToObject(json_slice, "func_name", funcName);
    cJSON_AddNumberToObject(json_slice, "is_bit_var", json_isBitVar->valueint);

    // parse string here, can the string be a json?
    if (INFO) cout << endl << "[sa] addr: 0x" << std::hex << addr << std::dec << endl;
    if (INFO) cout << "[sa] reg: " << regName << endl;

    cJSON *json_reads = cJSON_CreateArray();
    boost::unordered_set<Address> visited;
    backwardSliceHelper(stcs, co, json_reads, visited, progName, funcName, addr, regName, isKnownBitVar);
    cJSON_AddItemToObject(json_slice, "reads", json_reads);
    cJSON_AddItemToArray(json_slices, json_slice);
    if (DEBUG) cout << endl;
  }
  char *rendered = cJSON_Print(json_slices);
  cJSON_Delete(json_slices);
  std::ofstream out("backwardSlices_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"backwardSlices_result\"";
  if(DEBUG) cout << endl;
  delete stcs;
  delete co;
}

void backwardSlice(char *progName, char *funcName, long unsigned int addr, char *regName) {

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  //bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  //if (isParsable == false) {
  //  fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
  //  return NULL;
  //}
  SymtabCodeSource *stcs = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  cJSON *json_reads = cJSON_CreateArray();
  boost::unordered_set<Address> visited;

  backwardSliceHelper(stcs, co, json_reads, visited, progName, funcName, addr, regName);

  char *rendered = cJSON_Print(json_reads);
  cJSON_Delete(json_reads);
  std::ofstream out("backwardSlice_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"backwardSlice_result\"";
  if(DEBUG) cout << endl;

  delete stcs;
  delete co;
}

}

int main() {
  char *progName = "909_ziptest_exe9";
  getMemWritesToStaticAddresses(progName);

  /*
char *progName = "909_ziptest_exe9";
BPatch_image *appImage = getImage(progName);
char *funcName = "runtime.morestack01";
Function *func = getFunction2(progName, funcName);
cout << func->name() << endl;
BPatch_function *f = getFunction(appImage, funcName);
cout << f->getName() << endl;

char *progName = "909_ziptest_exe9";
char *funcName = "runtime.findnull";
Function *f = getFunction2(progName, funcName);
std::vector<Block *> list;
boost::unordered_set<Block *> visited;
getReversePostOrderListHelper(f->entry(), list, visited);
std::reverse(list.begin(), list.end());
boost::unordered_map<Address, long> insnToStackHeight;
int initHeight = 0;
getStackHeights(f, list, insnToStackHeight, initHeight);
*/
  //getCalleeToCallsites(progName);
  //getMemWritesToStaticAddresses(progName);
  /*
  // Set up information about the program to be instrumented 
  char *progName = "909_ziptest_exe9";
  //const char *funcName = "scanblock";
  //char *funcName = "sweep";
  char *funcName = "runtime.memmove";
  //backwardSlices("[{\"reg_name\": \"\", \"addr\": \"4234200\"}, {\"reg_name\": \"\", \"addr\": \"4234203\"}]",
  //    progName, funcName);
  // /home/anygroup/go-repro/909-go/src/pkg/runtime/mgc0.c:467
  //long unsigned int addr = 0x409daa;
  long unsigned int addr = 0x408aff;
  //long unsigned int addr = 0x408b02;
  Function *func = getFunction2(progName, funcName);
  Block *bb = getBasicBlock2(func, addr);
  Instruction insn = bb->getInsn(addr);
  cout << insn.getOperation().format() << endl;
  //cout << insn.getOperation().getID() << endl;
  //cout << (insn.getOperation().getID()  == 329) << endl;
  cout << (insn.getOperation().getPrefixID() == prefix_rep) << endl;
  cout << (insn.getOperation().getPrefixID() == prefix_repnz) << endl;
  //getAllBBs(progName, funcName, addr);
  */

  //BPatch_image *appImage = getImage(progName);
  //printAddrToLineMappings(appImage, funcName);
  //BPatch_basicBlock *immedDom = getImmediateDominator(appImage, funcName, 0x40940c);
  //Instruction ifCond = getIfCondition(immedDom);
  /***************************************************************/
  //char *regName = "";
  //
  //boost::unordered_set<BPatch_basicBlock *> predes;
  //getAllControlFlowPredecessors(predes, appImage, funcName, addr);
  //
  //getAllPredes(progName, funcName, addr);
  //backwardSlice(progName, funcName, 0x409c55, regName);
  //getRegsWritten(progName, funcName, 0x409c55);
  //Function *func = getFunction2(progName, funcName);
  //Block *immedDom = getImmediateDominator2(func, 0x40940c);
  //Instruction ifCond = getIfCondition2(immedDom);
  //GraphPtr slice = buildBackwardSlice(func, immedDom, ifCond, NULL);

  /*
  boost::unordered_set<Assignment::Ptr> bitVariables;
  locateBitVariables(slice, bitVariables);

  // get all the leaf nodes.
  NodeIterator begin, end;
  slice->entryNodes(begin, end);
  //slice->allNodes(begin, end);
  for(NodeIterator it = begin; it != end; ++it) {
    SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(*it);
    Assignment::Ptr assign = aNode->assign();
    //cout << assign->format() << " " << assign->insn().format() << " " << assign->insn().getOperation().getID() << " " << endl;
    if (assign->insn().readsMemory()) {
      cout << assign->format() << " ";
      cout << assign->insn().format() << " ";
      cout << (bitVariables.find(assign) != bitVariables.end())  << " ";
      cout << endl;
    }
  }
  */
}
