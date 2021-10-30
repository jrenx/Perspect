#include <iostream>     // std::cout
#include <fstream>      // std::ifstream
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "cJSON.h"
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>
#include <chrono>
#include <bitset>
#include <thread>
#include <mutex>
#include <condition_variable>

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#include "parser.cpp"

using namespace std;
using namespace boost;
//TODO: fix all the weird casings in this file.

int main(int argc, char *argv[]) {

  int pa_id = -1;
  if (argc >= 2) {
    char *pa_str = (char *) argv[1];
    pa_id = atoi(pa_str);
  }
  cout << pa_id << endl;

  Parser p = Parser();
  p.initData(pa_id);

  unsigned long length;
  std::chrono::steady_clock::time_point t2 = std::chrono::steady_clock::now();
  char *buffer = Parser::readFile(p.traceFile, length);
  cout << "Read " << length << " characters... " << endl;
  std::chrono::steady_clock::time_point t3 = std::chrono::steady_clock::now();
  std::cout << "Reading file took = " << std::chrono::duration_cast<std::chrono::seconds>(t3 - t2).count() << "[s]" << std::endl;

<<<<<<< HEAD
  string outTraceFile(traceFile);
  outTraceFile += ".parsed";
  if (pa_id >= 0) {
    outTraceFile += "_";
    outTraceFile += std::to_string(pa_id);
  }
  ofstream os;
  os.open(outTraceFile.c_str(), ios::out);

  //long j = 0;
  bool found = false;
  int pendingRegCount = 0;
  std::vector<long> pendingRegValues;
  long offRegValue = 0;

  bool hasPrevValues = false;
  int pendingAccessCount = 0;
  long prevRegValue = 0;
  long prevOffRegValue = 0;

  int nodeCount = 0;
  long uid = -1;
  // Note: the same instruction executed will have multiple UIDs if multiple regs are printed at the instrustion
  unsigned short code;
  long regValue;
  u_int8_t threadId;
  StaticNode *sn;
  bool loadsMemory;
  int regCount2;

  short *bitOps;
  bool otherRegsParsed = false;
  for (unsigned long i = length; i > 0;) {
    regValue = 0;
    uid ++;
    i-=2;
    std::memcpy(&code, buffer+i, sizeof(unsigned short));
    assert(code <= CodeCount);
    assert(code >= 0);
    if (code == 0) {
      i -= 1;	    
      std::memcpy(&threadId, buffer + i, sizeof(u_int8_t));
      continue;
    }

    //if (code == 2 || code == 3) {
    //  cout << "HERE " <<uid << endl;
    //}

    bool parse = false;
    if (CodeOfStartInsns[code] || PendingCodes[code]) {
    //if ((code > 0 && code <= MaxStartCode) || PendingCodes[code]) {
      parse = true;
    }
    if (OccurrencesPerCode[code] > 50000) parse = false;

    bool isBitOp = isBitOpCode[code];
    bool containsReg = CodesWithRegs[code];
    if (containsReg || isBitOp) {
      i-=8;
      if (parse || isBitOp) {
        std::memcpy(&regValue, buffer + i, sizeof(long));
      }
      //cout << "contains reg" << code << endl;
    }

    // TODO, if other regs are not parsed, won't parse the bit var at all
    // could this be a problem?
    if (isBitOp && (!containsReg || otherRegsParsed)) {
      // The use of the "otherRegsParsed" variable is to ensure that
      // if an instruction has an addr load and store or both (so parse is true), and a bit op
      // we parse the bit op last, after any load or store has been parsed
      // and not confuse it with a load and store
      otherRegsParsed = false;

      short *parentOfBitOps = LaterBitOpCodeToCodes[code];
      if (parentOfBitOps != NULL) {
        // The associated instruction is supposed to happen before the bit operations
        // in the reversed trace, and it should have been a store instruction
        // if the store associated instruction was included in the parsed result
        // we include the bit ops into the parsed result right away
        int count = LaterBitOpCodeToCodeCount[code];
        for (int j = 0; j < count; j++) {
          if (CodeWithLaterBitOpsExecuted[parentOfBitOps[j]]) {
            if (DEBUG) cout << "[store]  " << code << " " << parentOfBitOps[j] << " " << std::bitset<64>(regValue) << endl;
            os.write((char *) &code, sizeof(unsigned short));
            os.write((char *) &uid, sizeof(long));
            os.write((char *) &regValue, sizeof(long));
            //CodeWithLaterBitOpsExecuted[parentOfBitOps[j]] = false;
          }
        }
      } else {
        // The associated instruction is supposed to happen after the bit operations
        // in the reversed trace, and it should have been a load instruction
        // we cache the bit operations for now and wait for the
        // associated load instruction to be included in the parsed result
        // then include the cached bit operations as well
        codeToBitOperand[code] = regValue;
        codeToBitOperandIsValid[code] = true;
      }
      continue;
    }

    if (!parse) {
      goto DONT_PARSE;
    }
    //cout << code << endl;

    // A bit hacky, but essentially if an instruction both loads and stores
    // treat the load and store expressions as two separate things so old logic can be reused
    regCount2 =  CodeToRegCount2[code];
    if (!hasPrevValues && regCount2 > 0) {
      if (regCount2 > 1) {
        if (pendingRegCount == 0) {
          pendingRegCount = 1;
          offRegValue = regValue;
          goto DONT_PARSE;
        }
        pendingRegCount = 0;
      } else {
        offRegValue = 0;
      }
      prevRegValue = regValue;
      prevOffRegValue = offRegValue;
      hasPrevValues = true;
      goto DONT_PARSE;
    } else {
      int regCount1 =  CodeToRegCount[code];
      if (regCount1 > 1) { // large than zero only if has more than one reg!
        if (pendingRegCount == 0) {
          pendingRegCount = 1;
          offRegValue = regValue;
          goto DONT_PARSE;
        }
        pendingRegCount = 0;
      } else {
        offRegValue = 0;
      }
    }
    if (isBitOp) otherRegsParsed = true;
    sn = CodeToStaticNode[code];
    if (PendingRemoteDefCodes[code]) {
      long addr = 0;
      if (sn->mem_store == NULL) {
        //cout << "[warn] " << sn->id << " does not store to memory? " << endl;
        hasPrevValues = false;
      } else {
        //assert(sn->mem_store != NULL);
        if (hasPrevValues) {
          addr = sn->mem_store->calc_addr(prevRegValue, prevOffRegValue);
          hasPrevValues = false;
        } else {
          addr = sn->mem_store->calc_addr(regValue, offRegValue);
        }
      }
      assert(hasPrevValues == false);
      //long addr = sn->mem_store->calc_addr(regValue, offRegValue);
      //if (PendingAddrs.find(addr) == PendingAddrs.end() && (code > 0 && code > MaxStartCode)) {
      if (PendingAddrs.find(addr) == PendingAddrs.end() && !CodeOfStartInsns[code]) {
        if (!PendingLocalDefCodes[code]) goto DONT_PARSE; // FIXME: unfortuanately, could be a local def dep too, need to make logic less messy if have more time ...
      } else {
        //cout << "  mem addr matched " << endl;
        // Approximation

        if (sn->src_reg_size == 8 && !containsBitOpCode[code])
          PendingAddrs.erase(addr);
      }
    } else {
      hasPrevValues = false;
      assert(hasPrevValues == false);
    }

    bitOps = CodeToPriorBitOpCodes[code];
    if (bitOps != NULL) {
      int count = CodeToPriorBitOpCodeCount[code];
      for (int j = 0; j < count; j++) {
        short bitOpCode = bitOps[j];
        if (codeToBitOperandIsValid[bitOpCode]) {
          if (DEBUG) cout << "[load] " << bitOpCode << " " << count << " " << std::bitset<64>(codeToBitOperand[bitOpCode]) << endl;
          os.write((char *) &bitOpCode, sizeof(unsigned short));
          os.write((char *) &uid, sizeof(long));
          os.write((char *) &codeToBitOperand[bitOpCode], sizeof(long));
          codeToBitOperandIsValid[bitOpCode] = false;
        }
      }
    }

    if (regCount2 > 1) {
      if (DEBUG) cout << "Persisting1 " << code << endl;
      os.write((char*)&code, sizeof(unsigned short));
      os.write((char*)&uid, sizeof(long));
      os.write((char*)&prevOffRegValue, sizeof(long));
    }
    if (regCount2 > 0) {
      if (DEBUG) cout << "Persisting2 " << code << endl;
      os.write((char*)&code, sizeof(unsigned short));
      os.write((char*)&uid, sizeof(long));
      os.write((char*)&prevRegValue, sizeof(long));
    }

    if (CodeToRegCount[code] > 1) {
      if (DEBUG) cout << "Persisting3 " << code << endl;
      os.write((char*)&code, sizeof(unsigned short));
      os.write((char*)&uid, sizeof(long));
      os.write((char*)&offRegValue, sizeof(long));
    }

    if (DEBUG) cout << "Persisting4 " << code << endl;
    os.write((char*)&code, sizeof(unsigned short));
    os.write((char*)&uid, sizeof(long));
    if (CodesWithRegs[code]) {
      if (DEBUG) cout << "Persisting5 " << code << endl;
      os.write((char*)&regValue, sizeof(long));
    }

    //cout << "====" << nodeCount << "\n";
    //cout << "curr code" << code << " index: "<< i <<endl;
    //cout << std::hex << CodeToInsn[code] << std::dec << "\n";
    OccurrencesPerCode[code] = OccurrencesPerCode[code] + 1;

    nodeCount ++;
    
    if (PendingCfPredeCodes[code]) {
      std::vector<unsigned short> toRemove;
      for(auto it = CfPredeCodeToSucceNodes[code].begin(); it != CfPredeCodeToSucceNodes[code].end(); it++) {
        StaticNode * succeNode = *it;
        for (auto iit = succeNode->cf_prede_codes.begin();
                  iit != succeNode->cf_prede_codes.end(); iit ++) {
          toRemove.push_back(*iit);
        }
      }
      for(auto it = toRemove.begin(); it != toRemove.end(); it++) {
        unsigned short removeCode = *it;
        CfPredeCodeToSucceNodes[removeCode].clear();
        PendingCfPredeCodes[removeCode] = false;
        if (!PendingLocalDefCodes[removeCode]) PendingCodes[removeCode] = false;
      }
    }

    if (PendingLocalDefCodes[code]) {//} && !CodesOfMemStoreNodes[code]) {
      std::vector<unsigned short> toRemove;
      for(auto it = DfPredeCodeToSucceNodes[code].begin(); it != DfPredeCodeToSucceNodes[code].end(); it++) {
        StaticNode * succeNode = *it;
        assert (succeNode->mem_load == NULL);
        for (auto iit = succeNode->df_prede_codes.begin();
             iit != succeNode->df_prede_codes.end(); iit++) {
          toRemove.push_back(*iit);
        }
      }
      for(auto it = toRemove.begin(); it != toRemove.end(); it++) {
        unsigned short removeCode = *it;
        DfPredeCodeToSucceNodes[removeCode].clear();
        PendingLocalDefCodes[removeCode] = false;
        if (!PendingCfPredeCodes[removeCode]) PendingCodes[removeCode] = false;
      }
    }

    loadsMemory = sn->mem_load != NULL;
    if (sn->df_prede_codes.size() > 0) {
      for (auto it = sn->df_prede_codes.begin(); it != sn->df_prede_codes.end(); it++) {
        unsigned short currCode = *it;
        if (!CodesOfCFNodes[currCode] && !CodesOfDFNodes[currCode]) {
          continue;
        }
        // technically, for remote nodes, can remove when the list is empty!
        // but need to match on address... too complicated for now
        if (!loadsMemory) {
          PendingLocalDefCodes[currCode] = true;
          PendingCodes[currCode] = true;
          DfPredeCodeToSucceNodes[currCode].push_back(sn);
        } else {
          PendingRemoteDefCodes[currCode] = true;
          PendingCodes[currCode] = true;
        }
      }
      if (loadsMemory) {
        long addr = sn->mem_load->calc_addr(regValue, offRegValue);
        PendingAddrs.insert(addr);
      }
    } else {
      if (loadsMemory && sn->mem_load->read_same_as_write) {
        long addr = sn->mem_load->calc_addr(regValue, offRegValue);
        PendingAddrs.insert(addr);
      }
    }
    if (sn->cf_prede_codes.size() > 0) {
      for (auto it = sn->cf_prede_codes.begin(); it != sn->cf_prede_codes.end(); it++) {
        unsigned short currCode = *it;
        if (!CodesOfCFNodes[currCode] && !CodesOfDFNodes[currCode]) {
          continue;
        }
        CfPredeCodeToSucceNodes[currCode].push_back(sn);
        PendingCfPredeCodes[currCode] = true;
        PendingCodes[currCode] = true;
      }
    }
    CodeWithLaterBitOpsExecuted[code] = true;
    continue;

    DONT_PARSE:
    if (LaterBitOpCodeToCodes[code] != NULL) {
      CodeWithLaterBitOpsExecuted[code] = false;
    }

    bitOps = CodeToPriorBitOpCodes[code];
    if (bitOps != NULL) {
      int count = CodeToPriorBitOpCodeCount[code];
      for (int j = 0; j < count; j++) {
        short bitOpCode = bitOps[j];
        codeToBitOperandIsValid[bitOpCode] = false;
      }
    }
  }
  os.close();
  std::chrono::steady_clock::time_point t4 = std::chrono::steady_clock::now();
  std::cout << "Parsing took = " << std::chrono::duration_cast<std::chrono::seconds>(t4 - t3).count() << "[s]" << std::endl;

  string outLargeFile(traceFile);
  outLargeFile += ".large";
  if (pa_id >= 0) {
    outLargeFile += "_";
    outLargeFile += std::to_string(pa_id);
  }
  ofstream osl;
  osl.open(outLargeFile.c_str());
  for (int i = 1; i < CodeCount; i++) {
    long count = OccurrencesPerCode[i];
    if (count <= 50000) continue;
    //cout << "LARGE " << i << "\n";
    osl << std::hex << CodeToInsn[i] << std::dec << " " << i << " occurrences: " << count << "\n";
  }
  osl.close();
  cout << "total nodes: " << nodeCount << endl;
=======
  p.parse(pa_id, length, buffer);
>>>>>>> 0532e85... [preprocess] Make both parallel and serial version use the same parsing logic.
}
