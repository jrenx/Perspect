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

using namespace std;
using namespace Dyninst;
using namespace InstructionAPI;
using namespace ParseAPI;
using namespace DataflowAPI;

/***************************************************************/
BPatch bpatch;
bool DEBUG_C = true;
bool DEBUG_SLICE = true;

typedef enum {
  create,
  attach,
  open
} accessType_t;

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

void printLineInfo(BPatch_basicBlock *block) {
  fprintf(stdout, "start %lx end %lx\n", block->getStartAddress(), block->getEndAddress());
  BPatch_Vector < BPatch_sourceBlock * > sourceBlocks;
  block->getSourceBlocks(sourceBlocks);
  for (int i = 0; i < sourceBlocks.size(); i++) {
    BPatch_Vector<unsigned short> lines;
    sourceBlocks[i]->getSourceLines(lines);
    for (int j = 0; j < lines.size(); j++) {
      fprintf(stdout, "source line: %u.\n", lines[j]);
    }
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

BPatch_basicBlock *getImmediateDominator(BPatch_image *appImage, const char *funcName, long unsigned int addr) {

  vector < BPatch_function * > functions;
  appImage->findFunction(funcName, functions);
  if (functions.size() == 0) {
    fprintf(stderr, "Loading function %s failed.\n", funcName);
    return NULL;
  } else if (functions.size() > 1) {
    fprintf(stderr, "More than one function with name %s, using one.\n", funcName);
  }

  BPatch_flowGraph *fg = functions[0]->getCFG();

  set <BPatch_basicBlock *> blocks;
  fg->getAllBasicBlocks(blocks);

  BPatch_basicBlock *target = NULL;
  for (auto blockIter = blocks.begin();
       blockIter != blocks.end();
       ++blockIter) {
    BPatch_basicBlock *block = *blockIter;
    printLineInfo(block);
    if (addr >= block->getStartAddress() && addr <= block->getEndAddress()) { //TODO inclusive?
      target = block;
      break;
    }
  }

  if (target == NULL) {
    fprintf(stderr, "Failed to find basic block for function %s @ %lx.\n", funcName, addr);
    return NULL;
  }
  return target->getImmediateDominator();
}

Instruction getIfCondition(BPatch_basicBlock *block) {
  vector <Instruction> insns;
  block->getInstructions(insns);
  Instruction ret = *insns.rbegin();
  assert(ret.getCategory() == InsnCategory::c_BranchInsn);
  return ret;
}
/***************************************************************/

Function *getFunction(const char *binaryPath, const char *funcName) {
  SymtabAPI::Symtab *symTab;
  string binaryPathStr(binaryPath);
  string funcNameStr(funcName);
  bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  if (isParsable == false) {
    fprintf(stderr, "File cannot be parsed: %s.\n", binaryPath);
    return NULL;
  }

  SymtabCodeSource *sts = new SymtabCodeSource((char *)binaryPath);
  CodeObject *co = new CodeObject(sts);

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
    cerr << "Failed to find basic block for function" << f->name() << " @ " << addr << endl;
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
    cerr << "Failed to find basic block for function" << f->name() << " @ " << addr << endl;
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
  virtual bool endAtPoint(Assignment::Ptr ap) {
    if(DEBUG_C|DEBUG_SLICE) cout << endl;
    if(DEBUG_C|DEBUG_SLICE) cout << "[slice] Should continue slicing the assignment?" << endl;
    if(DEBUG_SLICE) cout << "[slice] " << "assignment: " << ap->format();
    //cout << "  ";
    //cout << ap->insn().readsMemory();
    if(DEBUG_SLICE) cout << endl;
    filter = false;
    if (ap->insn().readsMemory()) {
   	std::set<Expression::Ptr> memReads;
	ap->insn().getMemoryReadOperands(memReads);
	if(DEBUG_C) cout << "[sa] Memory read: " << (*memReads.begin())->format() << endl;
	std::string readStr = (*memReads.begin())->format();
	if (std::any_of(std::begin(readStr), std::end(readStr), ::isalpha)){
	  if (DEBUG_C) cout << "[sa] is a true memory read." << endl;
	  return true;
	}
	if (DEBUG_C) cout << "[sa] is not a true memory read." << endl;
	return false;
    } else {
      return false;
    }
  }

  //int i = 5;
  virtual bool addPredecessor(AbsRegion reg) {
    std:string regStr = reg.format();
    if(DEBUG_C || DEBUG_SLICE) cout << endl;
    if(DEBUG_C|DEBUG_SLICE) cout << "[slice] Should add the dataflow predecessor?" << endl;
    if(DEBUG_SLICE) cout << "[slice] " << "predecessor reg: " << regStr << endl;
    if (filter) {
      if (reg.format().compare(regName) != 0) {
	if(DEBUG_SLICE) cout << "[slice] " << "Filtering against " << regName << 
	       				      " filter out: " << regStr << endl;
        return false;
      }
    }

    if (std::any_of(std::begin(regStr), std::end(regStr), ::isalpha)){
      if (DEBUG_C) cout << "[sa] is a true reg: " << regStr << endl;
      return true;
    } else {
      if (DEBUG_C) cout << "[sa] is not a true reg: " << regStr << endl;
      return false;
    }


    return true;
    //i --;
    //return i > 0;
    //return false;
  }
};

GraphPtr buildBackwardSlice(Function *f, Block *b, Instruction insn, char *regName) {

  // Convert the instruction to assignments
  AssignmentConverter ac(true, false);
  vector<Assignment::Ptr> assignments;
  ac.convert(insn, b->last(), f, b, assignments);

  // An instruction can corresponds to multiple assignments
  if(DEBUG_SLICE) cout << "[slice] " << " Finding all assignments of the instruction: " << endl;
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
  GraphPtr slice = s.backwardSlice(cs);
  //cout << slice->size() << endl;
  string filePath("/home/anygroup/perf_debug_tool/binary_analysis/graph");
  slice->printDOT(filePath);
  return slice;
}

void locateBitVariables(GraphPtr slice, 
		boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> &bitVariables) {
  boost::heap::priority_queue<Node::Ptr> q;

  NodeIterator begin, end;
  slice->exitNodes(begin, end);//Exit nods are the root nodes.
  for (NodeIterator it = begin; it != end; ++it)
    q.push(*it);

  boost::unordered_set<Assignment::Ptr> visitedVariables;
  while (!q.empty()) {
    Node::Ptr node = q.top();
    q.pop();

    NodeIterator iBegin, iEnd;
    node->ins(iBegin, iEnd);
    for (NodeIterator it = iBegin; it != iEnd; ++it)
      q.push(*it);

    SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(node);
    Assignment::Ptr assign = aNode->assign();
    entryID id = assign->insn().getOperation().getID();

    if (visitedVariables.find(assign) != visitedVariables.end()) {
      if(DEBUG_SLICE) cout << "[slice] " << "Already visited." << endl;
      continue;
    }
    visitedVariables.insert(assign);

    if(DEBUG_SLICE) cout << "[slice] " << "CHECKING instruction for bit variable: ";
    if(DEBUG_SLICE) cout << "[slice] " << assign->format() << " ";
    if(DEBUG_SLICE) cout << "[slice] " << assign->insn().format() << " ";
    if(DEBUG_SLICE) cout << "[slice] " << id << " ";
    if(DEBUG_SLICE) cout << endl;
    //for(auto bit = bitVariables.begin(); bit != bitVariables.end(); ++bit){
    //  cout << *bit << endl;
    //}

    if (id == e_and) {
      if(DEBUG_SLICE) cout << "[slice] " << "FOUND an AND instruction, considered a mask: ";
      if(DEBUG_SLICE) cout << "[slice] " << assign->format() << " ";
      if(DEBUG_SLICE) cout << "[slice] " << assign->insn().format() << endl;
      
      std::vector<AbsRegion> regions;
      for(auto iit = assign->inputs().begin(); iit != assign->inputs().end(); ++iit) {
        regions.push_back(*iit);
      }
      bitVariables.insert({assign, regions});
      continue;
    }

    //if (id != e_mov) continue; // FIXME: heuristic to only include direct moves ...

    bool predeIsBit = false;
    NodeIterator oBegin, oEnd;
    node->outs(oBegin, oEnd);
    for (NodeIterator it = oBegin; it != oEnd; ++it) {
      SliceNode::Ptr oNode = boost::static_pointer_cast<SliceNode>(*it);
      Assignment::Ptr oAssign = oNode->assign();
      if(DEBUG_SLICE) cout << "[slice] " << "Dataflow predecessor: ";
      if(DEBUG_SLICE) cout << "[slice] " << oAssign->format() << " ";
      if(DEBUG_SLICE) cout << "[slice] " << oAssign->insn().format() << endl;
      
      if (bitVariables.find(oAssign) != bitVariables.end()) {
        if(DEBUG_SLICE) cout << "[slice] " << "Assignment might involve a bit variable" << endl;
	std::vector<AbsRegion> regions = bitVariables[oAssign];
        if(DEBUG_SLICE) cout << "[slice] " << "Current out " << assign->out() << endl;
        if (std::find(regions.begin(), regions.end(), assign->out()) != regions.end()) {
          predeIsBit = true;
          if(DEBUG_SLICE) cout << "[slice] " << "Assignment involves a bit variable" << endl;
        }
      }
    }

    if (predeIsBit) {
      switch(id) {
        case e_mov: {
	    cout << "[slice] encountered mov instruction: " << assign->format() << " " << assign->insn().format() << endl;
	    std::vector<AbsRegion> regions;
            for(auto iit = assign->inputs().begin(); iit != assign->inputs().end(); ++iit) {
              regions.push_back(*iit);
            }
	    bitVariables.insert({assign, regions});
          }
	  break;
	case e_shr:
	case e_shl_sal: {
	    cout << "[slice] encountered shift instruction: " << assign->format() << " " << assign->insn().format() << endl;
	    std::vector<AbsRegion> regions;
	    if (assign->inputs().size() == 2) {
              regions.push_back(assign->inputs()[1]);
	    } else if (assign->inputs().size() == 1) {
              regions.push_back(assign->inputs()[0]);
	    } else {
	      cout << "[warn][slice] Unhandle number of inputs. " << endl;
	    }
	    bitVariables.insert({assign, regions});
	  }
	  break;
	default:
	  cout << "[warn][slice] Unhandled case: " << assign->format() << " " << assign->insn().format() << endl;
      }
    }
  }
  //for (auto it = bitVariables.begin(); it != bitVariables.end(); ++it) {
  //  cout << (*it)->format() << endl;
  //}
}

extern "C" {
  long unsigned int getImmedDom(char *progName, char *funcName, long unsigned int addr){
    if(DEBUG_C) cout << "[sa] ================================" << endl;
    if(DEBUG_C) cout << "[sa] Getting the immediate control flow dominator: " << endl;
    if(DEBUG_C) cout << "[sa] prog: " << progName << endl;
    if(DEBUG_C) cout << "[sa] func: " << funcName << endl;
    if(DEBUG_C) cout << "[sa] addr: " << addr << endl;
    if(DEBUG_C) cout << endl;
    Function *func = getFunction(progName, funcName);
    Block *immedDom = getImmediateDominator2(func, addr);
    //Instruction ifCond = getIfConditionAddr2(immedDom);
    if(DEBUG_C) cout << "[sa] immed dom: " << immedDom->last() << endl;
    return immedDom->last();

  }

  long unsigned int getFirstInstrInBB(char *progName, char *funcName, long unsigned int addr){
    if(DEBUG_C) cout << "[sa] ================================" << endl;
    if(DEBUG_C) cout << "[sa] Getting the first instruction of the basic block: " << endl; 
    if(DEBUG_C) cout << "[sa] prog: " << progName << endl;
    if(DEBUG_C) cout << "[sa] func: " << funcName << endl;
    if(DEBUG_C) cout << "[sa] addr: " << addr << endl;
    if(DEBUG_C) cout << endl;
    Function *func = getFunction(progName, funcName);
    Block *bb = getBasicBlock2(func, addr);
    //Instruction ifCond = getIfConditionAddr2(immedDom);
    if(DEBUG_C) cout << "[sa] first instr: " << bb->start() << endl;
    return bb->start();

  }

  long unsigned int getLastInstrInBB(char *progName, char *funcName, long unsigned int addr){
    if(DEBUG_C) cout << "[sa] ================================" << endl;
    if(DEBUG_C) cout << "[sa] Getting the last instruction of the basic block: " << endl; 
    if(DEBUG_C) cout << "[sa] prog: " << progName << endl;
    if(DEBUG_C) cout << "[sa] func: " << funcName << endl;
    if(DEBUG_C) cout << "[sa] addr: " << addr << endl;
    if(DEBUG_C) cout << endl;
    Function *func = getFunction(progName, funcName);
    Block *bb = getBasicBlock2(func, addr);
    //Instruction ifCond = getIfConditionAddr2(immedDom);
    if(DEBUG_C) cout << "[sa] last instr: " << bb->last() << endl;
    return bb->last();
  }

  long unsigned int getInstrAfter(char *progName, char *funcName, long unsigned int addr){
    if(DEBUG_C) cout << "[sa] ================================" << endl;
    if(DEBUG_C) cout << "[sa] Getting the instruction after: " << endl; 
    if(DEBUG_C) cout << "[sa] prog: " << progName << endl;
    if(DEBUG_C) cout << "[sa] func: " << funcName << endl;
    if(DEBUG_C) cout << "[sa] addr: " << addr << endl;
    if(DEBUG_C) cout << endl;
    Function *func = getFunction(progName, funcName);
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
    if(DEBUG_C) cout << "[sa] instr after: " << nextInsn << endl;
    return nextInsn;
  }

  void getImmedPred(char *progName, char *funcName, long unsigned int addr){
    if(DEBUG_C) cout << "[sa] ================================" << endl;
    if(DEBUG_C) cout << "[sa] Getting the immediate control flow predecessor: " << endl;
    if(DEBUG_C) cout << "[sa] prog: " << progName << endl;
    if(DEBUG_C) cout << "[sa] func: " << funcName << endl;
    if(DEBUG_C) cout << "[sa] addr: " << addr << endl;
    if(DEBUG_C) cout << endl;
    Function *func = getFunction(progName, funcName);
    Block *immedDom = getImmediateDominator2(func, addr);
    Instruction ifCond = getIfCondition2(immedDom);
    //TODO
  }

  void backwardSlice(char *progName, char *funcName, long unsigned int addr, char *regName){
    if(DEBUG_C) cout << "[sa] ================================" << endl;
    if(DEBUG_C) cout << "[sa] Making a backward slice: " << endl;
    if(DEBUG_C) cout << "[sa] prog: " << progName << endl;
    if(DEBUG_C) cout << "[sa] func: " << funcName << endl;
    if(DEBUG_C) cout << "[sa] addr: " << addr << endl;
    if(DEBUG_C) cout << "[sa] reg: " << regName << endl;
    if(DEBUG_C) cout << endl;

    Function *func = getFunction(progName, funcName);
    Block *bb = getBasicBlock2(func, addr);
    Instruction ifCond = bb->getInsn(addr);
    GraphPtr slice = buildBackwardSlice(func, bb, ifCond, regName);

    boost::unordered_map<Assignment::Ptr, std::vector<AbsRegion>> bitVariables;
    locateBitVariables(slice, bitVariables);

    // get all the leaf nodes.
    NodeIterator begin, end;
    slice->entryNodes(begin, end);
    //slice->allNodes(begin, end);
    //
    std::ofstream out("result");
    //std::stringstream ss;
    if(DEBUG_C) cout << endl;
    if(DEBUG_C) cout << "[sa] Result slice: " << endl;
    for(NodeIterator it = begin; it != end; ++it) {
      SliceNode::Ptr aNode = boost::static_pointer_cast<SliceNode>(*it);
      Assignment::Ptr assign = aNode->assign();
      //cout << assign->format() << " " << assign->insn().format() << " " << assign->insn().getOperation().getID() << " " << endl;
      if (assign->insn().readsMemory()) {
        if(DEBUG_C) cout << "[sa]" << assign->format() << " ";
        if(DEBUG_C) cout << "insn: " << assign->insn().format() << " ";
	bool isBitVar = bitVariables.find(assign) != bitVariables.end();
        if(DEBUG_C) cout << "is bit var: " << isBitVar  << " ";
        if(DEBUG_C) cout << endl;
	std::set<Expression::Ptr> memReads;
	assign->insn().getMemoryReadOperands(memReads);
	if(DEBUG_C) cout << "[sa] Memory read: " << (*memReads.begin())->format() << endl;
	std::string readStr = (*memReads.begin())->format();
	if (std::any_of(std::begin(readStr), std::end(readStr), ::isalpha)){
          out << "|" << assign->addr() << ",";
	  out << readStr;
	}
        //for (auto r = memReads.begin(); r != memReads.end(); ++r) {
	//	cout << (*r)->eval() << endl;
	//}
      }
    }
    //std::string tmp = ss.str(); 
    //if(DEBUG_C) cout << "[sa]" << tmp;
    //out << tmp;
    out.close();
    //const char* cstr = tmp.c_str();
    //return cstr;
    if(DEBUG_C) cout << endl;
  }
}

int main() {
  // Set up information about the program to be instrumented 
  char *progName = "909_ziptest_exe6";
  //const char *funcName = "scanblock";
  char *funcName = "sweep";

  //BPatch_image *appImage = getImage(progName);
  //printAddrToLineMappings(appImage, funcName);
  //BPatch_basicBlock *immedDom = getImmediateDominator(appImage, funcName, 0x40940c);
  //Instruction ifCond = getIfCondition(immedDom);
  /***************************************************************/
  char *regName = "";
  backwardSlice(progName, funcName, 0x409c55, regName);
  //Function *func = getFunction(progName, funcName);
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
