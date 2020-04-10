#include <stdio.h>
#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_point.h"
#include "BPatch_function.h"
#include "BPatch_flowGraph.h"

using namespace std;
using namespace Dyninst;

BPatch bpatch;

typedef enum {
  create,
  attach,
  open
} accessType_t;

// Attach, create, or open a file for rewriting
BPatch_addressSpace* startInstrumenting(accessType_t accessType, const char* name, int pid, const char* argv[]) {
  BPatch_addressSpace* handle = NULL;

  switch(accessType) {
    case create:
      handle = bpatch.processCreate(name, argv);
      if (!handle) { fprintf(stderr, "processCreate failed\n");}
      break;
    case attach:
      handle = bpatch.processAttach(name, pid);
      if (!handle) { fprintf(stderr, "processAttach failed\n");}
      break;
    case open:
      // Open the binary file and all dependencies
      handle = bpatch.openBinary(name, true);
      if (!handle) { fprintf(stderr, "openBinary failed\n");}
      break;
  }

  return handle;
}

void printLineInfo(BPatch_basicBlock *block) {
    fprintf(stdout, "start %lx end %lx\n", block->getStartAddress(), block->getEndAddress());
    BPatch_Vector<BPatch_sourceBlock*> sourceBlocks;
    block->getSourceBlocks(sourceBlocks);
    for (int i = 0; i < sourceBlocks.size(); i++) {
        BPatch_Vector<unsigned short> lines;
        sourceBlocks[i]->getSourceLines(lines);
        for (int j = 0; j < lines.size(); j++) {
            fprintf(stdout, "source line: %u.\n", lines[j]);
        }
    }
}

BPatch_basicBlock *getImmediateDominator(BPatch_image* appImage,  const char *func_name, long unsigned int addr) {

    vector<BPatch_function*> functions;
    appImage->findFunction(func_name, functions);
    if (functions.size() == 0) {
        fprintf(stderr, "Loading function %s failed.\n", func_name);
        return NULL;
    } else if (functions.size() > 1) {
        fprintf(stderr, "More than one function with name %s, using one.\n", func_name);
    }

    BPatch_flowGraph* fg = functions[0]->getCFG();

    set<BPatch_basicBlock*> blocks;
    fg->getAllBasicBlocks(blocks);

    BPatch_basicBlock *target = NULL;
    for (auto block_iter = blocks.begin();
         block_iter != blocks.end();
         ++block_iter) {
        BPatch_basicBlock *block = *block_iter;
        //printLineInfo(block);
        if (addr >= block->getStartAddress() && addr <= block->getEndAddress()) {
            target = block;
            break;
        }
    }

    if (target == NULL) {
        fprintf(stderr, "Failed to find basic block for function %s @ %lx.\n", func_name, addr);
        return NULL;
    }
    return target->getImmediateDominator();
}

InstructionAPI::Instruction findIfCondition(BPatch_basicBlock *block) {
  std::vector<InstructionAPI::Instruction> insns;
  block->getInstructions(insns);
  InstructionAPI::Instruction ret = *insns.rbegin();
  assert(ret.getCategory() == InstructionAPI::InsnCategory::c_BranchInsn);
  return ret;
}

int main() {
  // Set up information about the program to be instrumented 
  const char* progName = "909_ziptest_exe";
  int progPID = 42;
  const char* progArgv[] = {"test.zip"};
  accessType_t mode = open;

  // Just open the binary for analysis, doesn't actually instrument it!
  BPatch_addressSpace* app = startInstrumenting(mode, progName, progPID, progArgv);
  if (!app) {
  	fprintf(stderr, "opening the binary failed\n");
	exit(1);
  }

  BPatch_image* appImage = app->getImage();

  // TODO, find the right address for the starting line ....
  BPatch_basicBlock * immed_dom = getImmediateDominator(appImage, "scanblock", 0x4094ef);

  InstructionAPI::Instruction ifCond = findIfCondition(immed_dom);

  // find operands of an instruction, decide how to handle!
  // => find the operator type
  // => trace dataflow, find definition point?

  // how to handle when there are multiple variables used in an instruction?


}
