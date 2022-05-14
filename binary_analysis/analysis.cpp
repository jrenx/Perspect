#include "util.hpp"
#include "dataflow_analysis.hpp"
#include "stack_analysis.hpp"
#include "bitvar_analysis.hpp"
#include "static_df_analysis.hpp"

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

boost::unordered_map<Address, boost::unordered_map<Address, Function *>> *stackCache;

extern "C" {

#ifdef USE_BPATCH

void getAllPredes(char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting all control flow predecessors using bpatch: " << endl;
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


void getAllBBs(vector<Function *> *allFuncs, char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting all control flow predecessors using bpatch: " << endl;
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

#else

void getAllBBs2(SymtabAPI::Symtab *symTab, vector<Function *> *allFuncs, char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting all control flow predecessors: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr <<  std::dec << endl;
  if(DEBUG) cout << endl;

  Function *f = getFunction2(allFuncs, funcName, addr);
  if (f == NULL) {
    cout << "[sa/warn] Function not found: " << funcName << endl;
    std::ofstream out("getAllBBs_result");
    out << "{}";
    out.close();
    return;
  }

  vector<Block *> bbs;
  boost::unordered_map<Block *, vector<Block *>> backEdges;

  for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
    Block *block = *bit;
    if (addr >= block->start() && addr < block->end()) {
      bbs.insert(bbs.begin(), block);
    } else {
      bbs.push_back(block);
    }
  }

  vector<Loop *> loops;
  f->getLoops(loops);
  for (int i = 0; i < loops.size(); i++) {
    Loop *loop = loops[i];
    std::vector<ParseAPI::Edge*> edges;
    loop->getBackEdges(edges);
    for (auto it = edges.begin(); it != edges.end(); it++) {
      ParseAPI::Edge *edge = *it;
      Block *source = edge->src();
      Block *target = edge->trg();
      backEdges[source].push_back(target);
    }
  }

  std::ofstream out("getAllBBs_result");
	
  cJSON *json_bbs = printBBsToJsonHelper(bbs, backEdges, f, symTab);

  char *rendered = cJSON_Print(json_bbs);
  cJSON_Delete(json_bbs);
  out << rendered;
  out.close();
  if(DEBUG) cout << "[sa] all results saved to \"getAllPredes_result\"";
  if(DEBUG) cout << endl;
  return;
}

void getAllBBs(vector<Function *> *allFuncs, char *progName, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting all control flow predecessors: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr <<  std::dec << endl;
  if(DEBUG) cout << endl;

  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  if (isParsable == false) {
    fprintf(stderr, "File cannot be parsed.\n");
    SymtabAPI::Symtab::closeSymtab(symTab);
    return;
  }
  getAllBBs2(symTab, allFuncs, progName, funcName, addr);
  SymtabAPI::Symtab::closeSymtab(symTab);
}
#endif

long unsigned int getImmedDom(vector<Function *> *allFuncs, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the immediate control flow dominator: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr <<  std::dec << endl;
  if(DEBUG) cout << endl;

  Function *func = getFunction2(allFuncs, funcName);
  Block *immedDom = getImmediateDominator2(func, addr);
  //Instruction ifCond = getIfConditionAddr2(immedDom);
  if(DEBUG) cout << "[sa] immed dom: " << immedDom->last() << endl;
  Address last = immedDom->last();
  return last;

}

long unsigned int getFirstInstrInBB(vector<Function *> *allFuncs, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the first instruction of the basic block: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  Function *func = getFunction2(allFuncs, funcName);
  Block *bb = getBasicBlock2(func, addr);
  //Instruction ifCond = getIfConditionAddr2(immedDom);
  if(DEBUG) cout << "[sa] first instr: " << bb->start() << endl;

  Address start = bb->start();
  return start;

}

long unsigned int getLastInstrInBB(vector<Function *> *allFuncs, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the last instruction of the basic block: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  Function *func = getFunction2(allFuncs, funcName);
  Block *bb = getBasicBlock2(func, addr);
  if(DEBUG) cout << "[sa] last instr: " << bb->last() << endl;

  Address last = bb->last();
  return last;
}

long unsigned int getInstrAfter(vector<Function *> *allFuncs, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the instruction after: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  Function *func = getFunction2(allFuncs, funcName);
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

void getImmedPred(vector<Function *> *allFuncs, char *funcName, long unsigned int addr){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the immediate control flow predecessor: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  Function *func = getFunction2(allFuncs, funcName);
  Block *immedDom = getImmediateDominator2(func, addr);
  Instruction ifCond = getIfCondition2(immedDom);
  //TODO
}


void getAddrIndices(vector<Function *> *allFuncs, char *funcName, long unsigned int startAddr, long unsigned int endAddr, char *addrs_string){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the indexes for addrs: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] start addr:  0x" << std::hex << startAddr << std::dec << endl;
  if(DEBUG) cout << "[sa] end   addr:  0x" << std::hex << endAddr << std::dec << endl;
  if(DEBUG) cout << "[sa]      addrs:  " << addrs_string << endl;
  if(DEBUG) cout << endl;
  cJSON *json_addrs = cJSON_Parse(addrs_string);
  int size = cJSON_GetArraySize(json_addrs);
  if (DEBUG) cout << "[sa] num of addrs is:　" << size << endl;
  std::vector<long unsigned int> addrs;
  for (int i = 0; i < size; i++) {
    cJSON *json_addr = cJSON_GetArrayItem(json_addrs, i);
    long unsigned int addr = json_addr->valuedouble;
    addrs.push_back(addr);
  }

  std::unordered_map<long unsigned int, int> addrToIndex;
  Function *f = getFunction2(allFuncs, funcName, startAddr);
  if (f != NULL) {
    std::map<long unsigned int, Block *> bs;
    for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
      Block *b = *bit;

      Address last = b->last();
      Address start = b->start();
      //cout << "start " << hex << start << endl;
      //cout << "last " << last << dec << endl;

      if (startAddr <= start && start < endAddr ||
          startAddr <= last && last < endAddr) {
        assert(bs.find(start) == bs.end());
        bs[start] = b;
        //cout << "Added " << endl;
      }
    }

    int index = 0;
    for (auto bit = bs.begin(); bit != bs.end(); ++bit) {
      Block *bb = bit->second;
      Block::Insns insns;
      bb->getInsns(insns);
      for (auto it = insns.begin(); it != insns.end(); ++it) {
        Instruction insn = (*it).second;
        long unsigned int addr = (*it).first;
        if (addr < startAddr) continue;
        if (addr >= endAddr) continue;
        //cout << hex << addr << dec << endl;
        assert(addrToIndex.find(addr) == addrToIndex.end());
        addrToIndex[addr] = index;
        index ++;
      }
    }
  }
  //cout << addrToIndex.size() << endl;
  cJSON *json_indices = cJSON_CreateArray();
  //std::vector<int> indices;
  for (auto ait = addrs.begin(); ait != addrs.end(); ++ait) {
    //cout<< "addr" << *ait << endl;
    cJSON *json_indice;
    if (addrToIndex.find(*ait) == addrToIndex.end()) {
      json_indice = cJSON_CreateNumber(-1);
    } else {
      json_indice = cJSON_CreateNumber(addrToIndex.at(*ait));
    }
    cJSON_AddItemToArray(json_indices, json_indice);
    //indices.push_back(addrToIndex.at(*ait));
  }
  cJSON *json_indice = cJSON_CreateNumber(addrToIndex.size());
  cJSON_AddItemToArray(json_indices, json_indice);

  char *rendered = cJSON_Print(json_indices);
  cJSON_Delete(json_indices);
  std::ofstream out("getAddrIndices_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"getAddrIndices_result\"";
  if(DEBUG) cout << endl;
}

void getDynamicCallsites(vector<Function *> *allFuncs) {
  if (DEBUG) cout << "[sa] ================================" << endl;

  cJSON *json_writes  = cJSON_CreateArray();
  boost::unordered_map<Address, std::pair<Block*, Function*>> staticWriteInsns;
  cJSON *json_reads = cJSON_CreateArray();
  for (auto fit = allFuncs->begin(); fit != allFuncs->end(); ++fit) {
    Function *f = *fit;
    for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
      Block *b = *bit;
      Block::Insns insns;
      b->getInsns(insns);
      for (auto iit = insns.begin(); iit != insns.end(); iit++) {
        long unsigned int addr = (*iit).first;
        Instruction insn = (*iit).second;
	      entryID id = insn.getOperation().getID();
	      if (id != e_call && id != e_callq) continue;
        //cout << hex << addr << dec << " " << insn.format() << " ";
	//      cout << insn.readsMemory() << endl;

        std::vector<Operand> ops;
        insn.getOperands(ops);
	bool isStaticCall = false;
        for (auto oit = ops.rbegin(); oit != ops.rend(); oit++) {
          std::vector<MachRegister> regs;
          long off = 0;
          getRegAndOff((*oit).getValue(), regs, &off);
          if (off != 0) continue;
          if (regs.size() != 1) continue;
          MachRegister reg = regs[0];
          if (reg == x86_64::rip) {
	    isStaticCall = true;
	    break;
	  }
	}
	if (isStaticCall == true) continue;

        bool memReadFound = false, regFound = false;
        std::string readStr = getMemReadStrIfNotRegReadStr(insn, &memReadFound, &regFound);
        if (!memReadFound && !regFound) {
          //if (INFO) cout << "[sa] result is a constant load, ignore" << endl;
          continue;
        }

        char *funcName = (char *)f->name().c_str();
        //if (INFO) cout << "[sa] => Instruction addr: " << std::hex << addr << std::dec << endl;
        //if (INFO) cout << "[sa] => Function: " << funcName << endl;
        //if (INFO) cout << "[sa] => Read expr: " << readStr << endl;
        cJSON *json_read = cJSON_CreateObject();
        cJSON_AddNumberToObject(json_read, "insn_addr", addr);
        cJSON_AddStringToObject(json_read, "expr", readStr.c_str());
        cJSON_AddStringToObject(json_read, "func", funcName);
        cJSON_AddItemToArray(json_reads, json_read);
      }
    }
  }
  char *rendered = cJSON_Print(json_reads);
  cJSON_Delete(json_reads);
  std::ofstream out("getDynamicCallsites_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"getDynamicCallsites_result\"";
  if(DEBUG) cout << endl;
}


void getAddrIndices2(vector<Function *> *allFuncs, char *funcName, char *addrs_string){
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the indexes for addrs: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa]      addrs:  " << addrs_string << endl;
  if(DEBUG) cout << endl;
  cJSON *json_addrs = cJSON_Parse(addrs_string);
  int size = cJSON_GetArraySize(json_addrs);
  if (DEBUG) cout << "[sa] num of addrs is:　" << size << endl;
  std::vector<long unsigned int> addrs;
  for (int i = 0; i < size; i++) {
    cJSON *json_addr = cJSON_GetArrayItem(json_addrs, i);
    long unsigned int addr = json_addr->valuedouble;
    addrs.push_back(addr);
  }

  std::unordered_map<long unsigned int, int> addrToIndex;
  Function *f = getFunction2(allFuncs, funcName, *addrs.begin());
  if (f != NULL) {
    for (auto bit = f->blocks().begin(); bit != f->blocks().end(); ++bit) {
      Block *bb = *bit;
      Block::Insns insns;
      bb->getInsns(insns);
      int index = 1;
      for (auto it = insns.begin(); it != insns.end(); ++it) {
        Instruction insn = (*it).second;
        long unsigned int addr = (*it).first;
        //cout << hex << addr << dec << endl;
        assert(addrToIndex.find(addr) == addrToIndex.end());
        addrToIndex[addr] = index;
        index++;
      }
    }
  }

  //cout << addrToIndex.size() << endl;
  cJSON *json_indices = cJSON_CreateArray();
  //std::vector<int> indices;
  for (auto ait = addrs.begin(); ait != addrs.end(); ++ait) {
    //cout<< "addr" << *ait << endl;
    cJSON *json_indice;
    if (addrToIndex.find(*ait) == addrToIndex.end()) {
      json_indice = cJSON_CreateNumber(-1);
    } else {
      json_indice = cJSON_CreateNumber(addrToIndex.at(*ait));
    }
    cJSON_AddItemToArray(json_indices, json_indice);
    //indices.push_back(addrToIndex.at(*ait));
  }
  //cJSON *json_indice = cJSON_CreateNumber(addrToIndex.size());
  //cJSON_AddItemToArray(json_indices, json_indice);

  char *rendered = cJSON_Print(json_indices);
  cJSON_Delete(json_indices);
  std::ofstream out("getAddrIndices2_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"getAddrIndices2_result\"";
  if(DEBUG) cout << endl;
}

void getCalleeToCallsites(char * progName) {
  if (DEBUG) cout << "[sa] ================================" << endl;
  SymtabCodeSource *stcs = new SymtabCodeSource((char *) progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();
  const CodeObject::funclist &all = co->funcs();

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
  delete co;
  delete stcs;
  if(DEBUG) cout << "[sa] all results saved to \"functionToCallSites_result\"";
  if(DEBUG) cout << endl;
}

void getMemWrites(vector<Function *> *allFuncs, char *addrToFuncNames) {
  if (DEBUG) cout << "[sa] ================================" << endl;
  if (DEBUG) cout << "[sa] Getting memory writes for instructions: " << endl;
  if (DEBUG) cout << "[sa] addr to func: " << addrToFuncNames << endl;

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

    // parse string here, can the string be a json?
    if (INFO) cout << endl << "[sa] addr: 0x" << std::hex << addr << std::dec << endl;
    if (INFO) cout << "[sa] func: " << funcName << endl;

    Function *func = getFunction2(allFuncs, funcName, addr);
    if (func == NULL) {
      cout << "[sa] In getMemWrites, function name not found: " << funcName << endl;
      continue;
    }

    Block *bb = getBasicBlock2(func, addr);
    if (bb == NULL) {
      cout << "[sa] In getMemWrites, bb not found, function: " << funcName << " addr: " << addr << endl;
      continue;
    }

    cJSON *json_insn  = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_insn, "addr", addr);
    cJSON_AddStringToObject(json_insn, "func_name", funcName);

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
      if (insn.getOperation().getPrefixID() == prefix_rep ||
          insn.getOperation().getPrefixID() == prefix_repnz) {
        // Is a looped move
        if (INFO) cout << "[sa] special looped move: ID: "
                       << insn.getOperation().getID()  << " op: "
                       << insn.getOperation().format() << endl;
        isLoopInsn = 1;
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
    MachRegister reg;
    for (auto oit = ops.rbegin(); oit != ops.rend(); oit++) {
      bool isRegReadOnly = (*oit).isRead() && !(*oit).readsMemory() && !(*oit).writesMemory();
      if (!isRegReadOnly) continue;
      std::vector<MachRegister> regs;
      long off = 0;
      getRegAndOff((*oit).getValue(), regs, &off);
      if (off != 0) continue;
      if (regs.size() != 1) continue;
      reg = regs[0];
    }
    cJSON_AddStringToObject(json_insn, "src", reg != InvalidReg ? reg.name().c_str() : "");
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

//TODO: make it less hacky!
void getNestedMemWritesToStaticAddresses(
    boost::unordered_map<Address, std::pair<Block*, Function*>> staticWriteInsns) {
  if (DEBUG) cout << "[sa] ================================" << endl;
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
      if (found) {
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

void getMemWritesToStaticAddresses(vector<Function *> *allFuncs) {
  if (DEBUG) cout << "[sa] ================================" << endl;

  cJSON *json_writes  = cJSON_CreateArray();
  boost::unordered_map<Address, std::pair<Block*, Function*>> staticWriteInsns;
  for (auto fit = allFuncs->begin(); fit != allFuncs->end(); ++fit) {
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

  getNestedMemWritesToStaticAddresses(staticWriteInsns);
}

void getRegsReadOrWritten(vector<Function *> *allFuncs, char *addrToFuncNames, bool isRead) {
  if (DEBUG) cout << "[sa] ================================" << endl;
  if (DEBUG) cout << "[sa] Getting registers read or written by instructions: " << endl;
  if (DEBUG) cout << "[sa] addr to func: " << addrToFuncNames << endl;

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
    //cout << json_addr->valuestring << endl;
    long unsigned int addr = strtol(json_addr->valuestring, &end, 10);
    if (errno != 0)
      cout << " Encountered error " << errno << " while parsing " << json_addr->valuestring << endl;
    char *funcName = json_funcName->valuestring;

    cJSON *json_insn  = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_insn, "addr", addr);
    cJSON_AddStringToObject(json_insn, "func_name", funcName);

    if (INFO) cout << endl << "[sa] addr: 0x" << std::hex << addr << std::dec << endl;
    if (INFO) cout << "[sa] func: " << funcName << endl;

    Function *func = getFunction2(allFuncs, funcName, addr);
    Block *bb = getBasicBlock2(func, addr);
    Instruction insn = bb->getInsn(addr);

    std::vector<Operand> ops;
    insn.getOperands(ops);
    // TODO is this good enough?
    MachRegister reg;
    for (auto oit = ops.rbegin(); oit != ops.rend(); oit++) {
      //cout << "OP" << (*oit).format(insn.getArch()) << endl;
      if (isRead) {
        //bool isRegReadOnly = (*oit).isRead() && !(*oit).isWritten() && !(*oit).readsMemory() && !(*oit).writesMemory();
        bool isRegReadOnly = (*oit).isRead() && !(*oit).readsMemory() && !(*oit).writesMemory();
        if (!isRegReadOnly) continue;
        if ((*oit).isWritten()) {
          cout << "[sa][warn] register is both read and written: " << (*oit).format(insn.getArch()) << endl;
        }
      } else {
        bool isRegWrittenOnly = (*oit).isWritten() && !(*oit).readsMemory() && !(*oit).writesMemory();
        if (!isRegWrittenOnly) continue;
        if ((*oit).isRead()) {
          cout << "[sa][warn] register is both read and written: " << (*oit).format(insn.getArch()) << endl;
        }
      }
      std::vector<MachRegister> regs;
      long off = 0;
      getRegAndOff((*oit).getValue(), regs, &off);
      if (off != 0) continue;
      if (regs.size() != 1) continue;
      reg = regs[0];
    }
    cJSON_AddStringToObject(json_insn, "src", reg != InvalidReg ? reg.name().c_str() : "");
    cJSON_AddItemToArray(json_insns, json_insn);
    if (DEBUG) cout << endl;
  }
  char *rendered = cJSON_Print(json_insns);
  cJSON_Delete(json_insns);
  std::ofstream out("RegReadOrWrittenPerInsn_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"RegReadOrWrittenPerInsn_result\"";
  if(DEBUG) cout << endl;
}

void getRegsWritten(vector<Function *> *allFuncs, char *funcName, long unsigned int addr) {
  if(DEBUG) cout << "[sa] ================================" << endl;
  if(DEBUG) cout << "[sa] Getting the registers written to by the instruction: " << endl;
  if(DEBUG) cout << "[sa] func: " << funcName << endl;
  if(DEBUG) cout << "[sa] addr:  0x" << std::hex << addr << std::dec << endl;
  if(DEBUG) cout << endl;

  Function *func = getFunction2(allFuncs, funcName, addr);
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

void backwardSlices(vector<Function *> *allFuncs, char *addrToRegNames) {
  if (INFO) cout << "[sa] ================================" << endl;
  if (INFO) cout << "[sa] Making multiple backward slices: " << endl;
  if (INFO) cout << "[sa] addr to reg: " << addrToRegNames << endl; // FIXME: maybe change to insn to reg, addr is instruction addr

  boost::unordered_map<Address, boost::unordered_map<Address, Function *>> cache;
  stackCache = &cache;

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

    Function *func = getFunction2(allFuncs, funcName, addr);
    Block *bb = getBasicBlock2(func, addr);
    Instruction insn = bb->getInsn(addr);

    if (strcmp(regName, "[x86_64::special]") == 0) {
      regName = (char *) getLoadRegName(insn).c_str();
    }

    backwardSliceHelper(allFuncs, json_reads, visited, funcName, addr, regName, false, isKnownBitVar);
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

void backwardSlice(vector<Function *> *allFuncs, char *funcName, long unsigned int addr, char *regName) {

  boost::unordered_map<Address, boost::unordered_map<Address, Function *>> cache;
  stackCache = &cache;

  cJSON *json_reads = cJSON_CreateArray();
  boost::unordered_set<Address> visited;

  backwardSliceHelper(allFuncs, json_reads, visited, funcName, addr, regName, false);

  char *rendered = cJSON_Print(json_reads);
  cJSON_Delete(json_reads);
  std::ofstream out("backwardSlice_result");
  out << rendered;
  out.close();

  if(DEBUG) cout << "[sa] all results saved to \"backwardSlice_result\"";
  if(DEBUG) cout << endl;
}

vector<Function *> *setup(char *progName) {
  SymtabCodeSource *stcs = new SymtabCodeSource((char *) progName);
  CodeObject *co = new CodeObject(stcs);
  co->parse();

  const CodeObject::funclist &all = co->funcs();
  vector<Function *> *fs = new vector<Function *>;
  for (auto fit = all.begin(); fit != all.end(); ++fit) {
    Function *f = *fit;
    fs->push_back(f);
  }

  ofstream os;
  os.open("pointers");
  os << fs << endl;
  os.close();
  return fs;
}

SymtabAPI::Symtab *setup2(char *progName) {
  SymtabAPI::Symtab *symTab;
  string binaryPathStr(progName);
  bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
  if (isParsable == false) {
    fprintf(stderr, "File cannot be parsed.\n");
    SymtabAPI::Symtab::closeSymtab(symTab);
    return NULL;
  }
  
  ofstream os;
  os.open("pointers");
  os << symTab << endl;
  os.close();
  return symTab;
}
}

int main() {
  //const char *progName = "909_ziptest_exe9";
  //getMemWritesToStaticAddresses((char *)progName);
}
