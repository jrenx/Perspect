#ifndef DATAFLOW_ANALYSIS_HPP
#define DATAFLOW_ANALYSIS_HPP

#include "util.hpp"
#include "bitvar_analysis.hpp"

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
    if(DEBUG || DEBUG_SLICE) cout << "[slice] Should stop slicing the assignment?" << endl;
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
          cout << "[sa] Compare with constant do not load memory right? continue slicing." << endl;
          return false;
        }
      } else if (id == e_xchg || id == e_cmpxch) {
        cout << "[sa] Special case of atomic exchange instruction, continue slicing." << endl;
        return false;
      }

      std::string readStr = (*memReads.begin())->format();
      if (std::any_of(std::begin(readStr), std::end(readStr), ::isalpha)) { // TODO, does this make sense?
        if (DEBUG) cout << "[sa] is a true memory read, stop slicing." << endl;
        return true;
      }
      if (DEBUG) cout << "[sa] is not a true memory read, continue slicing." << endl;
      return false;
    } else {
      if (DEBUG) cout << "[sa] continue slicing." << endl;
      return false;
    }
  }

  //int i = 5;
  virtual bool addPredecessor(AbsRegion reg) {
    std:string regStr = reg.format();
    if (DEBUG || DEBUG_SLICE) cout << endl;
    if (DEBUG || DEBUG_SLICE) cout << "[slice] Should add the dataflow predecessor?" << endl;
    if (DEBUG_SLICE) cout << "[slice] should stop slicing because at end point? " << atEndPoint << endl;
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
            if (DEBUG || DEBUG_SLICE) cout << "[sa] register is a memory address, IGNORE..." << endl;
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

void backwardSliceHelper(vector<Function *> *allFuncs, cJSON *json_reads, boost::unordered_set<Address> &visited,
                         char *funcName,
                         long unsigned int addr, char *regName, bool reversedOnce,
                         bool isKnownBitVar=false, bool atEndPoint=false);

GraphPtr buildBackwardSlice(Function *f, Block *b, Instruction insn, long unsigned int addr, char *regName, bool *madeProgress,
                            bool atEndPoint = false);

void handlePassByReference(AbsRegion targetReg, Address startAddr,
                           Block *startBb, Function *startFunc,
                           boost::unordered_map<Address, Function*> &ret,
                           boost::unordered_set<Address> &visitedAddrs);

std::string findMatchingOpExprStr(Assignment::Ptr assign, AbsRegion region);

std::string getMemReadStrIfNotRegReadStr(Instruction insn, bool *memReadFound, bool *regFound);
#endif