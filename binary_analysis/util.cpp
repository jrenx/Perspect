#include "util.hpp"
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

bool INFO = true;
bool DEBUG = false;
bool DEBUG_SLICE = false;
bool DEBUG_BIT = false;
bool DEBUG_STACK = false;
bool CRASH_ON_ERROR = false;
bool USE_X86_CALLING_CONVENTION = true;


boost::unordered_map<std::string, std::string> regMap =
    {{"al"  ,"rax"}, {"ah"  ,"rax"}, {"ax"  ,"rax"}, {"eax" ,"rax"}, {"rax","rax"},
     {"bl"  ,"rbx"}, {"bh"  ,"rbx"}, {"bx"  ,"rbx"}, {"ebx" ,"rbx"}, {"rbx","rbx"},
     {"cl"  ,"rcx"}, {"ch"  ,"rcx"}, {"cx"  ,"rcx"}, {"ecx" ,"rcx"}, {"rcx","rcx"},
     {"dl"  ,"rdx"}, {"dh"  ,"rdx"}, {"dx"  ,"rdx"}, {"edx" ,"rdx"}, {"rdx","rdx"},
     {"sil" ,"rsi"}, {"si"  ,"rsi"},                 {"esi" ,"rsi"}, {"rsi","rsi"},
     {"dil" ,"rdi"}, {"di"  ,"rdi"},                 {"edi" ,"rdi"}, {"rdi","rdi"},
     {"bpl" ,"rbp"}, {"bp"  ,"rbp"},                 {"ebp" ,"rbp"}, {"rbp","rbp"},
     {"spl" ,"rsp"}, {"sp"  ,"rsp"},                 {"esp" ,"rsp"}, {"rsp","rsp"},
     {"r8b" , "r8"}, {"r8w" , "r8"},                 {"r8d" , "r8"}, {"r8" , "r8"},
     {"r9b" , "r9"}, {"r9w" , "r9"},                 {"r9d" , "r9"}, {"r9" , "r9"},
     {"r10b","r10"}, {"r10w","r10"},                 {"r10d","r10"}, {"r10","r10"},
     {"r11b","r11"}, {"r11w","r11"},                 {"r11d","r11"}, {"r11","r11"},
     {"r12b","r12"}, {"r12w","r12"},                 {"r12d","r12"}, {"r12","r12"},
     {"r13b","r13"}, {"r13w","r13"},                 {"r13d","r13"}, {"r13","r13"},
     {"r14b","r14"}, {"r14w","r14"},                 {"r14d","r14"}, {"r14","r14"},
     {"r15b","r15"}, {"r15w","r15"},                 {"r15d","r15"}, {"r15","r15"}};

#ifdef USE_BPATCH
BPatch bpatch;
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

Instruction getIfCondition(BPatch_basicBlock *block) {
  vector <Instruction> insns;
  block->getInstructions(insns);
  Instruction ret = *insns.rbegin();
  assert(ret.getCategory() == InsnCategory::c_BranchInsn);
  return ret;
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
#endif

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

//TODO, in the future, get a batch get function
Function *getFunction2(vector<Function *> *allFuncs, const char *funcName) {
  string funcNameStr(funcName);
  if (allFuncs->size() == 0) {
    fprintf(stderr, "No function in file.\n");
    return NULL;
  }
  for (auto fit = allFuncs->begin(); fit != allFuncs->end(); ++fit) {
    Function *f = *fit;
    if (f->name().compare(funcNameStr) == 0) {
      return f;
    }
  }
  return NULL;
}

Function *getFunction2(vector<Function *> *allFuncs, const char *funcName, long unsigned int addr) {
  string funcNameStr(funcName);
  if (allFuncs->size() == 0) {
    fprintf(stderr, "No function in file.\n");
    return NULL;
  }
  for (auto fit = allFuncs->begin(); fit != allFuncs->end(); ++fit) {
    Function *f = *fit;
    if (f->name().compare(funcNameStr) != 0) {
      continue;
    }
    for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
      Block *block = *bit;
      if (addr >= block->start() && addr < block->end()) {
        return f;
      }
    }
  }
  return NULL;
}

Instruction getIfCondition2(Block *b) {
  // Decode the instruction
  const unsigned char *buf = (const unsigned char *) b->obj()->cs()->getPtrToInstruction(b->last());
  InstructionDecoder dec(buf, InstructionDecoder::maxInstructionLength, b->obj()->cs()->getArch());
  Instruction ret = dec.decode();
  assert(ret.getCategory() == InsnCategory::c_BranchInsn);
  return ret;
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

std::string getLoadRegName(Instruction insn) {
  std::string regStr("");
  std::vector<Operand> ops;
  insn.getOperands(ops);
  for (auto oit = ops.rbegin(); oit != ops.rend(); oit++) {
    bool isRegReadOnly = (*oit).isRead() && !(*oit).isWritten() && !(*oit).readsMemory() && !(*oit).writesMemory();
    if (!isRegReadOnly) continue;
    std::vector<MachRegister> regs;
    long off = 0;
    getRegAndOff((*oit).getValue(), regs, &off);
    if (off != 0) continue;
    if (regs.size() != 1) {
      cout << "[sa] Operand has multipl reg reads" << endl;
      continue;
    }
    if (regStr != "") {
      cout << "[sa] Instruction has multipl reg reads" << endl;
      return string("");
    }
    regStr = (*oit).getValue()->format();
    boost::algorithm::to_lower(regStr);
  }
  cout << regStr << endl;
  if (regStr != "")
    return "[x86_64::" + regMap[regStr] + "]";
  else
    return regStr;
}

#ifdef USE_BPATCH
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
                            boost::unordered_map<BPatch_basicBlock *, BPatch_Vector<BPatch_basicBlock *>> *backEdges) {
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
#else
cJSON *printBBIdsToJsonHelper(vector<Block *> &bbs, boost::unordered_map<Block *, int> &blockIds) {
  cJSON *json_bbs  = cJSON_CreateArray();
  for (int i=0; i<bbs.size(); i++) {
    Block *bb = bbs[i];
    cJSON *json_bb  = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_bb, "id", blockIds[bb]);
    cJSON_AddItemToArray(json_bbs, json_bb);
  }
  return json_bbs;
}

cJSON *printBBsToJsonHelper(vector<Block *> &bbs,
                            boost::unordered_map<Block *, vector<Block *>> &backEdges,
                            Function *f, SymtabAPI::Symtab *symTab) {
  cJSON *json_bbs = cJSON_CreateArray();
  boost::unordered_map<Block *, int> blockIds;
  int id = 1;
  for(auto it = bbs.begin(); it != bbs.end(); ++it) {
    Block *bb = *it;
    blockIds.insert({bb, id});
    id++;
  }
  for(auto it = bbs.begin(); it != bbs.end(); ++it) {
    Block *bb = *it;
    cJSON *json_bb  = cJSON_CreateObject();
    int id = blockIds[bb];
    cJSON_AddNumberToObject(json_bb, "id", id);
    cJSON_AddNumberToObject(json_bb, "start_insn", bb->start());
    cJSON_AddNumberToObject(json_bb, "end_insn", bb->last());

    Block::Insns insns;
    bb->getInsns(insns);
    if (insns.rbegin() == insns.rend()) {
      cout << "[sa/warn] BB is empty for function: " << f->name() << " skipping... " << endl;
      continue;
    }
    Instruction ret = insns.rbegin()->second;
    int isBranch = (ret.getCategory() == InsnCategory::c_BranchInsn) ? 1 : 0;
    cJSON_AddNumberToObject(json_bb, "ends_in_branch", isBranch);
    int isEntry = (bb == f->entry()) ? 1 : 0;
    cJSON_AddNumberToObject(json_bb, "is_entry", isEntry);

    vector<Block *> predes;
    Block::edgelist sources = bb->sources();
    for (auto eit = sources.begin(); eit != sources.end(); eit++) {
      //if ((*eit)->type() == CALL || (*eit)->type() == RET)
      //  continue;
      // Tryna imitate BPatch API behaviour LOL
      Block *src = (*eit)->src();
      if (blockIds.find(src) != blockIds.end()) {
        predes.push_back(src);
      }
    }
    cJSON_AddItemToObject(json_bb, "predes",  printBBIdsToJsonHelper(predes, blockIds));

    vector<Block *> succes;
    Block::edgelist targets = bb->targets();
    for (auto eit = targets.begin(); eit != targets.end(); eit++) {
      //if ((*eit)->type() == CALL || (*eit)->type() == RET)
      //  continue;
      Block *trg = (*eit)->trg();
      if (blockIds.find(trg) != blockIds.end()) {
        succes.push_back(trg);
      }
    }
    cJSON_AddItemToObject(json_bb, "succes",  printBBIdsToJsonHelper(succes, blockIds));

    Block * immedDom = f->getImmediateDominator(bb);
    if (immedDom != NULL)
      cJSON_AddNumberToObject(json_bb, "immed_dom",  blockIds[immedDom]);

    if (backEdges.size() > 0) {
      if (backEdges.find(bb) != backEdges.end()) {
        cJSON_AddItemToObject(json_bb, "backedge_targets",  printBBIdsToJsonHelper(backEdges[bb], blockIds));
      }
    }

    set<unsigned int> allLines;
    // TODO: optimize this by putting it into one string?
    cJSON *json_lines = cJSON_CreateArray();
    if (symTab != NULL) {
      for (auto iit = insns.begin(); iit != insns.end(); iit++) {
        Address addr = (*iit).first;
        vector<SymtabAPI::Statement::Ptr> lines;
        symTab->getSourceLines(lines, addr - symTab->getBaseOffset());
        for (auto lit = lines.begin(); lit != lines.end(); lit++) {
          allLines.insert((*lit)->getLine());
        }
      }
    }

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
#endif

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
