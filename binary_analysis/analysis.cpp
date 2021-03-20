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
Function *getFunction2(const char *binaryPath, const char *funcName);

Instruction getIfCondition(BPatch_basicBlock *block);
Instruction getIfCondition2(Block *b);

BPatch_basicBlock *getBasicBlock(BPatch_flowGraph *fg, long unsigned int addr);
Block *getBasicBlock2(Function *f, long unsigned int addr);
Block *getBasicBlockContainingInsnBeforeAddr(Function *f, long unsigned int addr);

GraphPtr buildBackwardSlice(Function *f, Block *b, Instruction insn, long unsigned int addr, char *regName);
void backwardSliceHelper(cJSON *json_reads, char *progName, char *funcName, long unsigned int addr, char *regName, bool isKnownBitVar = false);

void getReversePostOrderListHelper(Node::Ptr node, std::vector<Node::Ptr> *list);
void getReversePostOrderList(GraphPtr slice, std::vector<Node::Ptr> *list);

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

void getRegAndOff(Expression::Ptr exp, MachRegister *machReg, long *off);

std::string findMatchingOpExprStr(Assignment::Ptr assign, AbsRegion region);

cJSON * printBBIdsToJsonHelper(BPatch_Vector<BPatch_basicBlock *> &bbs);
cJSON *printBBsToJsonHelper(BPatch_Vector<BPatch_basicBlock *> &bbs,
    boost::unordered_map<BPatch_basicBlock *, vector<BPatch_basicBlock *>> *backEdges = NULL);

namespace boost {
  class StackStore {
  private:
    MachRegister machReg_;
    long offset_;
    long stackheight_;
  public:
    std::size_t hash;
    std::string str;

    StackStore(MachRegister machReg, long offset, long stackheight) :
        machReg_(machReg), offset_(offset), stackheight_(stackheight) {
      hash = std::hash<std::string>{}(format());

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

  vector < BPatch_function * > functions;
  appImage->findFunction(funcName, functions);
  if (functions.size() == 0) {
    fprintf(stderr, "Loading function %s failed.\n", funcName);
    return;
  } else if (functions.size() > 1) {
    fprintf(stderr, "More than one function with name %s, using one.\n", funcName);
  }

  BPatch_flowGraph *fg = functions[0]->getCFG();

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
    fprintf(stderr, "More than one function with name %s, using one.\n", funcName);
  }
  return functions[0]; // TODO is this gonna be a problem?
}



Function *getFunction2(const char *binaryPath, const char *funcName) {
  SymtabAPI::Symtab *symTab;
  string binaryPathStr(binaryPath);
  string funcNameStr(funcName);
  bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  if (isParsable == false) {
    fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
    return NULL;
  }

  SymtabCodeSource *stcs = new SymtabCodeSource((char *)binaryPath);
  CodeObject *co = new CodeObject(stcs);

  co->parse();

  const CodeObject::funclist &all = co->funcs();
  if (all.size() == 0) {
    fprintf(stderr, "No function in file %s.\n", binaryPath);
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
  Instruction insn;
  virtual bool endAtPoint(Assignment::Ptr ap) {
    if(DEBUG || DEBUG_SLICE) cout << endl;
    if(DEBUG || DEBUG_SLICE) cout << "[slice] Should continue slicing the assignment?" << endl;
    if(DEBUG_SLICE) cout << "[slice] " << "assignment: " << ap->format();
    //cout << "  ";
    //cout << ap->insn().readsMemory();
    if(DEBUG_SLICE) cout << endl;
    filter = false;
    if (ap->insn().readsMemory()) {
      std::set<Expression::Ptr> memReads;
      ap->insn().getMemoryReadOperands(memReads);
      if(DEBUG) cout << "[sa] Memory read: " << (*memReads.begin())->format() << endl;
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
    if(DEBUG || DEBUG_SLICE) cout << endl;
    if(DEBUG || DEBUG_SLICE) cout << "[slice] Should add the dataflow predecessor?" << endl;
    if(DEBUG_SLICE) cout << "[slice] " << "predecessor reg: " << regStr << endl;
    if (insn.readsMemory()) return false;
    if (filter) {
      if (reg.format().compare(regName) != 0) {
	      if(DEBUG_SLICE) cout << "[slice] " << "Filtering against " << regName <<
	       				      " filter out: " << regStr << endl;
        return false;
      }
    }

    if (std::any_of(std::begin(regStr), std::end(regStr), ::isalpha)){
      if (DEBUG) cout << "[sa] is a true reg: " << regStr << endl;
      return true;
    } else {
      if (DEBUG) cout << "[sa] is not a true reg: " << regStr << endl;
      return false;
    }


    return true;
    //i --;
    //return i > 0;
    //return false;
  }
};

GraphPtr buildBackwardSlice(Function *f, Block *b, Instruction insn, long unsigned int addr, char *regName) {

  // Convert the instruction to assignments
  AssignmentConverter ac(true, false);
  vector<Assignment::Ptr> assignments;
  ac.convert(insn, addr, f, b, assignments);

  // An instruction can corresponds to multiple assignments
  if (INFO) cout << endl << "[slice] " << " Finding all assignments of the instruction: "
             << insn.format() << endl;
  Assignment::Ptr assign; //TODO, how to handle multiple ones?
  for (auto ait = assignments.begin(); ait != assignments.end(); ++ait) {
    if(DEBUG_SLICE) cout << "[slice] " << "assignment: " << (*ait)->format() << endl;
    assign = *ait;
  }
  if(DEBUG_SLICE) cout << endl;

  Slicer s(assign, b, f, true, false);
  CustomSlicer cs;
  if (strcmp(regName, "") != 0) {
    cs.regName = regName;
    cs.filter = true;
  }
  cs.insn = insn;
  GraphPtr slice = s.backwardSlice(cs);
  //cout << slice->size() << endl;
  string filePath("/home/anygroup/perf_debug_tool/binary_analysis/graph");
  slice->printDOT(filePath);
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

void getReversePostOrderListHelper(Block *b,
                                   std::vector<Block *> &list,
                                   boost::unordered_set<Block *> &visited) {

  if (visited.find(b) != visited.end()) {
    if(DEBUG) cout << "Already visited " << endl;
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

  if (DEBUG && DEBUG_STACK) cout << "[stack] Checking memory write @ " << op.format(insn.getArch()) << endl;

  std::set<Expression::Ptr> memWrites;
  insn.getMemoryWriteOperands(memWrites);
  // FIXME: For now just handle those that have one memory write.
  if (DEBUG && DEBUG_STACK) cout << "[stack] Number of memory writes: " << memWrites.size() << endl;
  assert(memWrites.size() == 1);

  std::set<RegisterAST::Ptr> regsRead;
  op.getReadSet(regsRead);
  if (DEBUG && DEBUG_STACK) cout << "[stack] Register read count: " << regsRead.size() << endl;
  for (auto rit = regsRead.begin(); rit != regsRead.end(); rit++) {
    RegisterAST::Ptr regAst = *rit;
    MachRegister reg = regAst->getID();
    if (reg == x86_64::rsp || reg == x86_64::esp) {
      if (DEBUG_STACK) cout << "[stack] Found store to stack: " << op.format(insn.getArch())
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
  //if (DEBUG && DEBUG_STACK)
    cout << "[stack] Number of memory reads: " << memReads.size() << endl;

  for (auto it = memReads.begin(); it != memReads.end(); it++) {
    cout << "[stack] Checking memory read " << (*it)->format() << endl;
    getRegAndOff(*it, reg, off);
    cout << "[stack] Register read is " << reg->name() << endl;
    if ((*reg) == x86_64::rsp || (*reg) == x86_64::esp) {
      if (DEBUG_STACK) cout << "[stack] Found store to stack: " << " @ " << insn.format() << " @ " << addr << endl;
      return true;
    }
  }
  return false;
}

void printReachableStores(boost::unordered_map<StackStore, boost::unordered_set<Address>> &reachableStores) {
  for (auto mit = reachableStores.begin(); mit != reachableStores.end(); mit++) {
    StackStore ss = (*mit).first;
    boost::unordered_set<Address> s = (*mit).second;
    cout << "[stack]          stack store: " << ss.format() << " @ "  << std::hex;
    for (auto sit = s.begin(); sit != s.end(); sit++) {
      cout << (*sit) << " ";
    }
    cout << std::dec << endl;
  }
}

void getRegAndOff(Expression::Ptr exp, MachRegister *machReg, long *off) {
  RegisterAST::Ptr regAST = boost::dynamic_pointer_cast<RegisterAST>(exp);
  if (regAST != NULL) {
    (*machReg) = regAST->getID();
    if (DEBUG_STACK)
      cout << "[stack]   found register: " << machReg->name() << endl; //TODO
  } else {
    Immediate::Ptr immedAST = boost::dynamic_pointer_cast<Immediate>(exp);
    if (immedAST != NULL) {
      std::stringstream ss;
      ss << std::hex << immedAST->format();
      ss >> (*off);
      if (DEBUG_STACK)
        cout << "[stack]   found immediate: " << *off << endl;//TODO
    }
  }

  std::vector<Expression::Ptr> children;
  exp->getChildren(children);
  for (auto vit = children.begin(); vit != children.end(); vit++) {
    getRegAndOff(*vit, machReg, off);
  }
}

void getStackHeights(std::vector<Block *> &list, boost::unordered_map<Address, long> &insnToStackHeight) { // TODO add declaration to front
  // FIXME: just one pass, multiple predecessors are supposed to have the same stack height right?
  long currHeight = 0;
  for (auto bit = list.begin(); bit != list.end(); bit++) {
    Block::Insns insns;
    Block *b = *bit;
    b->getInsns(insns);
    for (auto iit = insns.begin(); iit != insns.end(); iit++) {
      bool changesStackPointer = false;
      Address addr = (*iit).first;
      Instruction insn = (*iit).second;
      if (DEBUG && DEBUG_STACK) cout << "[stack] Checking register write @ " << insn.format() << endl;
      std::set<RegisterAST::Ptr> regsWrite;
      insn.getWriteSet(regsWrite);

      for (auto rit = regsWrite.begin(); rit != regsWrite.end(); rit++) {
        RegisterAST::Ptr regAst = *rit;
        MachRegister reg = regAst->getID();
        if (reg == x86_64::rsp || reg == x86_64::esp) {
          if (DEBUG_STACK) cout << "[stack] Found stack pointer manipulation @ " << insn.format() << endl;
          changesStackPointer = true;
          break;
        }
        //StackAnalysis sa(f);
        //StackAnalysis::DefHeightSet set = sa.findDefHeight(b, addr, Absloc(reg));
        //cout << "HERE: " << reg.name() << " " << (*set.begin()).height.format() << " " << insn.format() << " @ " << addr << endl;
      }

      if (!changesStackPointer) {
        if (DEBUG_STACK && DEBUG) cout << "[stack] height @ " << addr << " is " << currHeight << endl;
        insnToStackHeight.insert({addr, currHeight});
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
          MachRegister machReg; long off = 0;
          for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
            getRegAndOff((*oit).getValue(), &machReg, &off);
          }
          if (DEBUG_STACK && DEBUG) cout << "[stack] subtracting stack pointer " << machReg.name() << " by " << off << endl;
          currHeight -= off;
          break;
        }
        case e_add: {
          std::vector<Operand> ops;
          insn.getOperands(ops);
          MachRegister machReg; long off = 0;
          for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
            getRegAndOff((*oit).getValue(), &machReg, &off);
          }
          if (DEBUG_STACK && DEBUG) cout << "[stack] increasing stack pointer " << machReg.name() << " by " << off << endl;
          currHeight += off;
          break;
        }
        default:
          if (DEBUG_STACK)
            cout << "[stack][warn] Unhandled case: " << insn.format() << endl;
      }
      if (DEBUG_STACK) cout << "[stack] height @ " << addr << " is " << currHeight << endl;
      insnToStackHeight.insert({addr, currHeight});
    }
  }
}

boost::unordered_set<Address> checkAndGetStackWrites(Function *f, Instruction readInsn, Address readAddr, MachRegister readReg, long readOff) { //TODO, add the declaration to top
  cout << "[stack] Checking function: " << f->name() << " for "
       << readReg.name() << " + " << readOff << " @ " << readInsn.format() << endl;
  std::vector<Block *> list;
  boost::unordered_set<Block *> visited;
  getReversePostOrderListHelper(f->entry(), list, visited);
  std::reverse(list.begin(), list.end());

  boost::unordered_map<Address, long> insnToStackHeight;
  getStackHeights(list, insnToStackHeight);

  StackStore stackRead(readReg, readOff, insnToStackHeight[readAddr]); // TODO rename StackStore to StackAccess...

  boost::unordered_map<Address, boost::unordered_map<StackStore, boost::unordered_set<Address>>>
      insnToReachableStores; //FIXME if I'm more comfortable with pointers store pointers instead ...
  for (auto bit = list.begin(); bit != list.end(); bit++) {
    Block::Insns insns;
    Block *b = *bit;
    b->getInsns(insns);
    for (auto iit = insns.begin(); iit != insns.end(); iit++) {
      Address addr = (*iit).first;
      Instruction insn = (*iit).second;
      std::vector<Operand> ops;
      insn.getOperands(ops);
      if (DEBUG && DEBUG_STACK) cout << "[stack] checking instruction: " << insn.format() << " @" << addr << endl;
      boost::unordered_map<StackStore, boost::unordered_set<Address>> reachableStores;

      for (auto oit = ops.begin(); oit != ops.end(); ++oit) {
        Operand op = *oit;
        if (!writesToStack(op, insn, addr)) continue;
        boost::unordered_set<Address> s;
        s.insert(addr);
        Expression::Ptr exp = op.getValue();
        //std::vector<Expression::Ptr> children;
        //exp->getChildren(children);
        MachRegister machReg; long off = 0;
        getRegAndOff(exp, &machReg, &off);
        //getRegAndOff(*children.begin(), &machReg, &off);

        //assert(reachableStores.find(exp) == reachableStores.end());
        StackStore stackStore(machReg, off, insnToStackHeight[addr]);
        if (stackStore == stackRead) {
          reachableStores.insert({stackStore, s});
        }
      }
      insnToReachableStores.insert({addr, reachableStores});
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
      if (DEBUG && DEBUG_STACK) cout << "[stack] Checking basic block from " << b->start() << " to " << b->end() << endl;
      b->getInsns(insns);
      // for the first instruction get sources, union them
      // otherwise, just get the previous
      // then, for the same entry, override
      // if any update, then changed .. how to compare two vectors are equal?
      boost::unordered_map<StackStore, boost::unordered_set<Address>> prevReachableStores;
      Block::edgelist sources = b->sources();
      for (auto eit = sources.begin(); eit != sources.end(); eit++) {
        if ((*eit)->type() == CALL || (*eit)->type() == RET || (*eit)->type() == CATCH)
          continue;
        Block* src = (*eit)->src();
        Block* trg = (*eit)->trg();
        assert(trg == b);
        if (DEBUG && DEBUG_STACK) cout << "[stack]     predecessor block " << src->start() << " to " << src->end() << endl;
        boost::unordered_map<StackStore, boost::unordered_set<Address>> predReachableStores =
            insnToReachableStores[src->last()];
        for (auto mit = predReachableStores.begin(); mit != predReachableStores.end(); mit++) {
          StackStore ss = (*mit).first;
          boost::unordered_set<Address> s = (*mit).second;
          if (prevReachableStores.find(ss) == prevReachableStores.end()) {
            prevReachableStores.insert({ss, s}); // Should be a separate copy otherwise wouldn't work
          } else {
            for (auto sit = s.begin(); sit != s.end(); sit++) {
              prevReachableStores[ss].insert(*sit);
            }
          }
        }
      }
      if (DEBUG && DEBUG_STACK) cout << "[stack] aggregated stack stores from predecessors:" << endl;
      if (DEBUG && DEBUG_STACK) printReachableStores(prevReachableStores);

      for (auto iit = insns.begin(); iit != insns.end(); iit++) {
        Address addr = (*iit).first;
        Instruction insn = (*iit).second;
        if (DEBUG_STACK)
          cout << "[stack] Working on instruction: " << insn.format()
                                       << " @" << std::hex << addr << std::dec << endl;

        boost::unordered_map<StackStore, boost::unordered_set<Address>> currReachableStores =
            insnToReachableStores[addr];

        /*
        if (addr != b->start() && addr != b->last() && currReachableStores.size() == 0) {
          continue;
        }*/

        if (DEBUG && DEBUG_STACK) cout << "[stack]   stack stores before update:" << endl;
        if (DEBUG && DEBUG_STACK) printReachableStores(insnToReachableStores[addr]);

        for (auto mit = currReachableStores.begin(); mit != currReachableStores.end(); mit++) {
          StackStore ss = (*mit).first;
          boost::unordered_set<Address> s = (*mit).second;
          prevReachableStores.insert({ss, s});
        }

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

            boost::unordered_set<Address> s1 = (*mit).second;
            boost::unordered_set<Address> s2 = prevReachableStores[ss];
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

        if (DEBUG_STACK)
          cout << "[stack]   stack stores after update:" << endl;
        if (DEBUG_STACK)
          printReachableStores(insnToReachableStores[addr]);

        //prevReachableStores = currReachableStores;
        if (DEBUG && DEBUG_STACK) cout << "[stack]   stack stores from previous instructions:" << endl;
        if (DEBUG && DEBUG_STACK) printReachableStores(prevReachableStores);
        if (DEBUG && DEBUG_STACK) cout << "[stack]" << endl;
      }
    }
  }
  return insnToReachableStores[readAddr][stackRead];
}

void backwardSliceHelper(cJSON *json_reads, char *progName, char *funcName,
                          long unsigned int addr, char *regName, bool isKnownBitVar) {

  if (INFO) cout << endl;
  if (INFO) cout << "[sa] ================================" << endl;
  if (INFO) cout << "[sa] Making a backward slice: " << endl;
  if (INFO) cout << "[sa] prog: " << progName << endl;
  if (INFO) cout << "[sa] func: " << funcName << endl;
  if (INFO) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;

  Function *func = getFunction2(progName, funcName);
  Block *bb = getBasicBlock2(func, addr);
  Instruction insn = bb->getInsn(addr);

  if (INFO) cout << "[sa] insn: " << insn.format() << endl;
  if (INFO) cout << "[sa] reg: " << regName << endl;
  if (INFO) cout << endl;

  GraphPtr slice = buildBackwardSlice(func, bb, insn, addr, regName);

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
    analyzeKnownBitVariables(slice, *memWrites.begin(), bitVariables, bitVariablesToIgnore, bitOperands, bitOperations);
  } // TODO propogate the bit operands.

  // get all the leaf nodes.
  NodeIterator begin, end;
  slice->entryNodes(begin, end);

  for(NodeIterator it = begin; it != end; ++it) {
    SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(*it);
    Assignment::Ptr assign = aNode->assign();
    //cout << assign->format() << " " << assign->insn().format() << " " << assign->insn().getOperation().getID() << " " << endl;
    if (!assign->insn().readsMemory()) continue;

    if(DEBUG) cout << endl;
    if(INFO) cout << "[sa] In result slice: " << endl;
    if(INFO) cout << "[sa]" << assign->format() << " ";
    if(INFO) cout << "insn: " << assign->insn().format() << " " << endl;

    bool isBitVar = bitVariables.find(assign) != bitVariables.end();
    bool isIgnoredBitVar = bitVariablesToIgnore.find(assign) != bitVariablesToIgnore.end();

    if(INFO) cout << "is bit var: " << isBitVar  << " ";
    if(INFO) cout << "is ignored bit var: " << isIgnoredBitVar  << " ";
    if(INFO) cout << endl;

    if (isIgnoredBitVar) {
      if(INFO) cout << "do not persist read because variable is an ignored bit variable " << endl;
      continue;
    }

    MachRegister readReg; long readOff;
    if (readsFromStack(assign->insn(), assign->addr(), &readReg, &readOff)) {
      cout << "[sa] result of slicing is reading from stack, perform stack analysis..." << endl;
      boost::unordered_set<Address> stackWrites = checkAndGetStackWrites(func, assign->insn(), assign->addr(), readReg, readOff);
      for (auto stit = stackWrites.begin(); stit != stackWrites.end(); stit++) {
        backwardSliceHelper(json_reads, progName, funcName, *stit, "", isKnownBitVar);
      }
      continue;
    }

    std::set<Expression::Ptr> memReads;
    assign->insn().getMemoryReadOperands(memReads);
    assert(memReads.size() == 1);
    Expression::Ptr read = *memReads.begin();
    //	cout << read->eval() << endl;
    if (INFO) cout << "[sa] Memory read: " << read->format() << endl;
    std::string readStr = read->format();
    // TODO, so, right now only include it if there is a letter in the expression,
    // constants are ignored, need to fix this.
    if (!std::any_of(std::begin(readStr), std::end(readStr), ::isalpha)) //TODO, reads from constant addresses should be OK too
      continue;

    cJSON *json_read = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_read, "insn_addr", assign->addr());
    cJSON_AddStringToObject(json_read, "expr", readStr.c_str());
    cJSON_AddNumberToObject(json_read, "read_same_as_write", isKnownBitVar ? 1 : 0); // TODO, see analyzeKnownBitVariables for proper way to handle this

    if (isBitVar) {
      std::vector<Assignment::Ptr> operations = bitOperations[assign];
      if (INFO) cout << "[sa] bit operations: " << endl;
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
    }
    cJSON_AddItemToArray(json_reads, json_read);

  }
}

bool findMemoryLoadHelper(Expression::Ptr memWrite,
                          SliceNode::Ptr node,
                          std::vector<Node::Ptr> *list) {
  NodeIterator iBegin, iEnd;
  node->ins(iBegin, iEnd);
  // Checking through successors.
  bool containsMemLoad = false;
  Assignment::Ptr assign = node->assign();
  Instruction insn = assign->insn();
  std::set<Expression::Ptr> memReads;
  insn.getMemoryReadOperands(memReads);
  if (memReads.size() > 1) {
    if(DEBUG && DEBUG_BIT) cout << "Instruction has more than one memory read? " << insn.format() << endl;
  }
  if(DEBUG && DEBUG_BIT) cout << "Instruction " << insn.format() << " has " << memReads.size() << endl;
  if (memReads.size() == 1) {
    Expression::Ptr memRead = *memReads.begin();
    std::string readStr = memRead->format();
    std::string writeStr = memWrite->format();
    if(DEBUG && DEBUG_BIT) cout << "Read str: " << readStr << endl;
    if(DEBUG && DEBUG_BIT) cout << "Write str: " << writeStr << endl;
    if (readStr.compare(writeStr) == 0) {
      list->push_back(node);
      return true;
    }
  }

  for (NodeIterator it = iBegin; it != iEnd; ++it) {
    SliceNode::Ptr iNode = boost::static_pointer_cast<SliceNode>(*it);
    containsMemLoad = (containsMemLoad == true) ? true : findMemoryLoadHelper(memWrite, iNode, list);
  }
  if (containsMemLoad == true) {
    list->push_back(node);
  }
  return containsMemLoad;
}

void findMemoryLoad(Expression::Ptr memWrite,
                    GraphPtr slice,
                    std::vector<Node::Ptr> *list) {
  NodeIterator begin, end;
  slice->exitNodes(begin, end);//Exit nods are the root nodes.
  for (NodeIterator it = begin; it != end; ++it) {
    SliceNode::Ptr iNode = boost::static_pointer_cast<SliceNode>(*it);
    findMemoryLoadHelper(memWrite, iNode, list);
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

  //boost::unordered_set<Assignment::Ptr> visitedVariables;
  AbsRegion source;
  std::vector<Assignment::Ptr> operations;
  for(auto it = list.begin(); it != list.end(); ++it) {
    Node::Ptr node = *it;
    SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(node);
    Assignment::Ptr assign = aNode->assign();
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

void getReversePostOrderListHelper(Node::Ptr node,
                                   std::vector<Node::Ptr> *list) {
  NodeIterator iBegin, iEnd;
  node->ins(iBegin, iEnd);
  // Checking through successors.
  for (NodeIterator it = iBegin; it != iEnd; ++it) {
    SliceNode::Ptr iNode = boost::static_pointer_cast<SliceNode>(*it);
    getReversePostOrderListHelper(iNode, list);
  }
  list->push_back(node);
}

void getReversePostOrderList(GraphPtr slice,
                             std::vector<Node::Ptr> *list) {

  NodeIterator begin, end;
  slice->exitNodes(begin, end);//Exit nods are the root nodes.
  for (NodeIterator it = begin; it != end; ++it) {
    getReversePostOrderListHelper(*it, list);
  }
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
    Function *func = getFunction2(progName, funcName);
    Block *immedDom = getImmediateDominator2(func, addr);
    //Instruction ifCond = getIfConditionAddr2(immedDom);
    if(DEBUG) cout << "[sa] immed dom: " << immedDom->last() << endl;
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
    BPatch_flowGraph *fg = getFunction(appImage, funcName)->getCFG();

    boost::unordered_map<BPatch_basicBlock *, BPatch_Vector<BPatch_basicBlock *>> backEdges;
    BPatch_Vector<BPatch_basicBlockLoop*> loops;
    fg->getLoops(loops);
    for (int i = 0; i < loops.size(); i++) {
      BPatch_basicBlockLoop* loop = loops[i];
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
    Function *func = getFunction2(progName, funcName);
    Block *bb = getBasicBlock2(func, addr);
    //Instruction ifCond = getIfConditionAddr2(immedDom);
    if(DEBUG) cout << "[sa] first instr: " << bb->start() << endl;
    return bb->start();

  }

  long unsigned int getLastInstrInBB(char *progName, char *funcName, long unsigned int addr){
    if(DEBUG) cout << "[sa] ================================" << endl;
    if(DEBUG) cout << "[sa] Getting the last instruction of the basic block: " << endl;
    if(DEBUG) cout << "[sa] prog: " << progName << endl;
    if(DEBUG) cout << "[sa] func: " << funcName << endl;
    if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
    if(DEBUG) cout << endl;
    Function *func = getFunction2(progName, funcName);
    Block *bb = getBasicBlock2(func, addr);
    //Instruction ifCond = getIfConditionAddr2(immedDom);
    if(DEBUG) cout << "[sa] last instr: " << bb->last() << endl;
    return bb->last();
  }

  long unsigned int getInstrAfter(char *progName, char *funcName, long unsigned int addr){
    if(DEBUG) cout << "[sa] ================================" << endl;
    if(DEBUG) cout << "[sa] Getting the instruction after: " << endl;
    if(DEBUG) cout << "[sa] prog: " << progName << endl;
    if(DEBUG) cout << "[sa] func: " << funcName << endl;
    if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
    if(DEBUG) cout << endl;
    Function *func = getFunction2(progName, funcName);
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
    return nextInsn;
  }

  void getImmedPred(char *progName, char *funcName, long unsigned int addr){
    if(DEBUG) cout << "[sa] ================================" << endl;
    if(DEBUG) cout << "[sa] Getting the immediate control flow predecessor: " << endl;
    if(DEBUG) cout << "[sa] prog: " << progName << endl;
    if(DEBUG) cout << "[sa] func: " << funcName << endl;
    if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
    if(DEBUG) cout << endl;
    Function *func = getFunction2(progName, funcName);
    Block *immedDom = getImmediateDominator2(func, addr);
    Instruction ifCond = getIfCondition2(immedDom);
    //TODO
  }

void getCalleeToCallsites(char *progName) {
  if (DEBUG) cout << "[sa] ================================" << endl;
  if (DEBUG) cout << "[sa] prog: " << progName << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  if (isParsable == false) {
    fprintf(stderr, "File cannot be parsed: %s.\n", progName);
    return;
  }

  SymtabCodeSource *sts = new SymtabCodeSource((char *)progName);
  CodeObject *co = new CodeObject(sts);

  co->parse();
  const CodeObject::funclist &all = co->funcs();
  if (all.size() == 0) {
    fprintf(stderr, "No function in file %s.\n", progName);
    return;
  }

  boost::unordered_map<Function *, std::vector<std::pair<Instruction, long unsigned int>>>
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
      functionToCallsite[f].push_back(std::pair<Instruction, long unsigned int>(insn, addr));
    }
  }

  cJSON *json_funcs  = cJSON_CreateArray();
  for (auto mit = functionToCallsite.begin(); mit != functionToCallsite.end(); mit++) {
    Function *f = mit->first;
    std::vector<std::pair<Instruction, long unsigned int>> callsites = mit->second;
    cJSON *json_func = cJSON_CreateObject();
    cJSON_AddStringToObject(json_func, "func", f->name().c_str());
    cJSON *json_callsites  = cJSON_CreateArray();
    for (auto cit = callsites.begin(); cit != callsites.end(); cit++) {
      cJSON *json_callsite = cJSON_CreateObject();
      cJSON_AddNumberToObject(json_callsite, "insn_addr", cit->second);
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
}

  void getMemWritesToStaticAddresses(char *progName) {
    if (DEBUG) cout << "[sa] ================================" << endl;
    if (DEBUG) cout << "[sa] prog: " << progName << endl;

    SymtabAPI::Symtab *symTab;
    string binaryPathStr(progName);
    bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
    if (isParsable == false) {
      fprintf(stderr, "File cannot be parsed: %s.\n", progName);
      return;
    }

    SymtabCodeSource *sts = new SymtabCodeSource((char *)progName);
    CodeObject *co = new CodeObject(sts);

    co->parse();
    const CodeObject::funclist &all = co->funcs();
    if (all.size() == 0) {
      fprintf(stderr, "No function in file %s.\n", progName);
      return;
    }

    cJSON *json_writes  = cJSON_CreateArray();

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
  }

  void getMemWrites(char *addrToFuncNames, char *progName) {
    if (DEBUG) cout << "[sa] ================================" << endl;
    if (DEBUG) cout << "[sa] Getting memory writes for instructions: " << endl;
    if (DEBUG) cout << "[sa] addr to func: " << addrToFuncNames << endl;
    if (DEBUG) cout << "[sa] prog: " << progName << endl;

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

      Function *func = getFunction2(progName, funcName);
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
        std::string writeStr = write->format();
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
  }


  void getRegsWritten(char *progName, char *funcName, long unsigned int addr) {
    if(DEBUG) cout << "[sa] ================================" << endl;
    if(DEBUG) cout << "[sa] Getting the registers written to by the instruction: " << endl;
    if(DEBUG) cout << "[sa] prog: " << progName << endl;
    if(DEBUG) cout << "[sa] func: " << funcName << endl;
    if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
    if(DEBUG) cout << endl;

    Function *func = getFunction2(progName, funcName);
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
  }

  void backwardSlices(char *addrToRegNames, char *progName) {
    if (DEBUG) cout << "[sa] ================================" << endl;
    if (DEBUG) cout << "[sa] Making multiple backward slices: " << endl;
    if (DEBUG) cout << "[sa] addr to reg: " << addrToRegNames << endl; // FIXME: maybe change to insn to reg, addr is instruction addr
    if (DEBUG) cout << "[sa] prog: " << progName << endl;

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
      bool isKnownBitVar = (json_isBitVar->valueint == 1) ? true : false;
      if (errno != 0)
        cout << " Encountered error " << errno << " while parsing " << json_isBitVar->valuestring << endl;

      cJSON *json_slice  = cJSON_CreateObject();
      cJSON_AddNumberToObject(json_slice, "addr", addr);
      cJSON_AddStringToObject(json_slice, "reg_name", regName);

      // parse string here, can the string be a json?
      if (INFO) cout << endl << "[sa] addr: 0x" << std::hex << addr << std::dec << endl;
      if (INFO) cout << "[sa] reg: " << regName << endl;

      cJSON *json_reads = cJSON_CreateArray();
      backwardSliceHelper(json_reads, progName, funcName, addr, regName, isKnownBitVar);
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
  }

  void backwardSlice(char *progName, char *funcName, long unsigned int addr, char *regName) {

    cJSON *json_reads = cJSON_CreateArray();
    backwardSliceHelper(json_reads, progName, funcName, addr, regName);

    char *rendered = cJSON_Print(json_reads);
    cJSON_Delete(json_reads);
    std::ofstream out("backwardSlice_result");
    out << rendered;
    out.close();

    if(DEBUG) cout << "[sa] all results saved to \"backwardSlice_result\"";
    if(DEBUG) cout << endl;
  }
}

int main() {
  char *progName = "909_ziptest_exe9";
  getCalleeToCallsites(progName);
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
