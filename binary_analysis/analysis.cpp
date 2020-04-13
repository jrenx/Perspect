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
#include <boost/heap/priority_queue.hpp>

using namespace std;
using namespace Dyninst;
using namespace InstructionAPI;
using namespace ParseAPI;
using namespace DataflowAPI;

/***************************************************************/
BPatch bpatch;

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

Instruction findIfCondition(BPatch_basicBlock *block) {
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

Instruction findIfCondition2(Block *b) {
  // Decode the instruction
  const unsigned char *buf = (const unsigned char *) b->obj()->cs()->getPtrToInstruction(b->last());
  InstructionDecoder dec(buf, InstructionDecoder::maxInstructionLength, b->obj()->cs()->getArch());
  Instruction ret = dec.decode();
  assert(ret.getCategory() == InsnCategory::c_BranchInsn);
  return ret;
}

class CustomSlicer : public Slicer::Predicates {
public:
  virtual bool endAtPoint(Assignment::Ptr ap) {
    //cout << ap->format();
    //cout << "  ";
    //cout << ap->insn().readsMemory();
    //cout << endl;
    return ap->insn().readsMemory();
  }

  virtual bool addPredecessor(AbsRegion reg) {
    //cout << reg.format() << endl;
    return true;
  }
};

GraphPtr buildSlice(Function *f, Block *b, Instruction insn) {

  // Convert the instruction to assignments
  AssignmentConverter ac(true, false);
  vector<Assignment::Ptr> assignments;
  ac.convert(insn, b->last(), f, b, assignments);

  // An instruction can corresponds to multiple assignments
  Assignment::Ptr assign; //TODO, how to handle multiple ones?
  for (auto ait = assignments.begin(); ait != assignments.end(); ++ait) {
    //cout << (*ait)->format() << endl;
    assign = *ait;
  }

  Slicer s(assign, b, f, true, false);
  CustomSlicer cs;
  GraphPtr slice = s.backwardSlice(cs);
  //cout << slice->size() << endl;
  string filePath("/home/anygroup/perf_debug_tool/binary_analysis/graph");
  slice->printDOT(filePath);
  return slice;
}

void locateBitVariables(GraphPtr slice, boost::unordered_set<Assignment::Ptr> &bitVariables) {
  boost::heap::priority_queue<Node::Ptr> q;

  NodeIterator begin, end;
  slice->exitNodes(begin, end);
  for (NodeIterator it = begin; it != end; ++it)
    q.push(*it);

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
    if (id == e_and) {
      cout << "FOUND an AND instruction: ";
      cout << assign->format() << " ";
      cout << assign->insn().format() << endl;
      bitVariables.insert(assign);
      continue;
    }

    cout << "CHECKING instruction: ";
    cout << assign->format() << " ";
    cout << assign->insn().format() << " ";
    cout << id << " ";
    cout << endl;

    if (id != e_mov) continue; // FIXME: heuristic to only include direct moves ...

    NodeIterator oBegin, oEnd;
    node->outs(oBegin, oEnd);
    for (NodeIterator it = oBegin; it != oEnd; ++it) {
      SliceNode::Ptr oNode = boost::static_pointer_cast<SliceNode>(*it);
      Assignment::Ptr oAssign = oNode->assign();
      cout << "Predecessor: ";
      cout << oAssign->format() << " ";
      cout << oAssign->insn().format() << endl;

      if (bitVariables.find(oAssign) != bitVariables.end()) {
        bitVariables.insert(assign);
        cout << "ADDING" << endl;
      }
    }
  }
  //for (auto it = bitVariables.begin(); it != bitVariables.end(); ++it) {
  //  cout << (*it)->format() << endl;
  //}
}

int main() {
  // Set up information about the program to be instrumented 
  const char *progName = "909_ziptest_exe";
  const char *funcName = "scanblock";

  //BPatch_image *appImage = getImage(progName);
  //printAddrToLineMappings(appImage, funcName);
  //BPatch_basicBlock *immedDom = getImmediateDominator(appImage, funcName, 0x40940c);
  //Instruction ifCond = findIfCondition(immedDom);
  /***************************************************************/

  Function *func = getFunction(progName, funcName);
  Block *immedDom = getImmediateDominator2(func, 0x40940c);
  Instruction ifCond = findIfCondition2(immedDom);
  GraphPtr slice = buildSlice(func, immedDom, ifCond);

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
}
