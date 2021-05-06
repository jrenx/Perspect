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
using namespace std;
using namespace boost;
//TODO: fix all the weird casings in this file.

class MemAccess {
public:
  string reg;  //change to bool
  bool has_reg;
  long shift;
  long offset;
  string off_reg;  //change to bool
  bool has_off_reg;
  bool read_same_as_write;
  // TODO bit var too

  long inline calc_addr(long regValue, long offRegValue) {
    long addr = 0;
    if (has_reg) addr = regValue;
    if (shift != 0) addr = addr * shift;
    if (has_off_reg) {
      addr += offRegValue * offset;
    } else {
      addr += offset;
    }
    /*
    cout << "reg: "      << reg     << " " << std::hex << regValue    << std::dec;
    cout << " off reg: " << off_reg << " " << std::hex << offRegValue << std::dec;
    cout << " offset: " << offset << " shift: " << shift;
    cout << " addr: " << std::hex << addr << std::dec << "\n";
    */
    return addr;
  }
};

class StaticNode {
public:
  int id;
  long insn;
  std::vector<int> cf_prede_ids;
  std::vector<int> cf_succe_ids;
  std::vector<int> df_prede_ids;
  std::vector<int> df_succe_ids;

  std::vector<long> cf_prede_codes;
  std::vector<long> cf_succe_codes;
  std::vector<long> df_prede_codes;
  std::vector<long> df_succe_codes;
  MemAccess *mem_load;
  MemAccess *mem_store;
};

long *CodeToInsn;
unordered_map<long, unsigned short> InsnToCode;

unordered_map<long, int> InsnToRegCount;
int *CodeToRegCount;
int *CodeToRegCount2;

unordered_set<long> StartInsns;
bool *CodeOfStartInsns;

unordered_set<long> InsnsWithRegs;
bool *CodesWithRegs;

unordered_set<long> InsnOfCFNodes;
bool * CodesOfCFNodes;

unordered_set<long> InsnOfDFNodes;
bool * CodesOfDFNodes;

unordered_set<long> InsnOfLocalDFNodes;
bool * CodesOfMemLoadNodes;

unordered_set<long> InsnOfRemoteDFNodes;
bool * CodesOfMemStoreNodes;

long StartInsn;
unsigned short StartInsnCode;

std::vector<StaticNode*> *CfPredeCodeToSucceNodes;
bool *PendingCfPredeCodes;
std::vector<StaticNode*> *DfPredeCodeToSucceNodes;
bool * PendingLocalDefCodes;
bool *PendingRemoteDefCodes;
bool *PendingCodes;

unordered_set<long> PendingAddrs;

StaticNode **CodeToStaticNode;
unordered_map<int, long> StaticNodeIdToInsn;

char *traceFile;

long GetFileSize(std::string filename)
{
  struct stat stat_buf;
  int rc = stat(filename.c_str(), &stat_buf);
  return rc == 0 ? stat_buf.st_size : -1;
}

void parseJsonMap(cJSON *json_Map, unordered_map<long, long> &map) {
  int size = cJSON_GetArraySize(json_Map);
  for (int i = 0; i < size; i++) {
    cJSON *ele = cJSON_GetArrayItem(json_Map, i);
    long key = atol (ele->string);
    //cout << key << endl;
    //cout << ele->valueint << endl;
    map.insert({key, (long)ele->valueint}); //TODO long?? save as string??
  }
}

void parseJsonList(cJSON *json_List, unordered_set<long> &set) {
  int size = cJSON_GetArraySize(json_List);
  for (int i = 0; i < size; i++) {
    cJSON *ele = cJSON_GetArrayItem(json_List, i);
    set.insert((long)ele->valueint); //TODO long?? save as string??
  }
}

char *readFile(char *filename, long &length) {
  ifstream is;
  is.open(filename, ios::in);
  is.seekg (0, is.end);
  length = is.tellg();
  is.seekg (0, is.beg);
  char *buffer = new char[length];
  is.read(buffer, length);
  is.close();
  return buffer;
}

MemAccess *parseMemoryAccess(cJSON *json_memAccess) {
  MemAccess *memAccess = new MemAccess();
  cJSON *json_reg = cJSON_GetObjectItem(json_memAccess, "reg");
  if (json_reg->valuestring == NULL) {
    memAccess->reg = "";
  } else {
    char *reg = json_reg->valuestring;
    memAccess->reg = string(reg);
  }

  if (memAccess->reg == "") memAccess->has_reg = false;
  else memAccess->has_reg = true;

  memAccess->shift = cJSON_GetObjectItem(json_memAccess, "shift")->valueint;
  memAccess->offset = cJSON_GetObjectItem(json_memAccess, "off")->valueint;
  cJSON *json_offReg = cJSON_GetObjectItem(json_memAccess, "off_reg");

  if (json_offReg->valuestring == NULL) {
    memAccess->off_reg = "";
  } else {
    memAccess->off_reg = string(json_offReg->valuestring);
  }

  if (memAccess->off_reg == "") memAccess->has_off_reg = false;
  else if (memAccess->off_reg == "ES"){// || memAccess->off_reg == "DS") {
    //cout << "Ignore ES" << endl;
    memAccess->has_off_reg = false;
    memAccess->offset = 0;
  }
  else memAccess->has_off_reg = true;
  cJSON *json_readSameAsWrite = cJSON_GetObjectItem(json_memAccess, "read_same_as_write");
  memAccess->read_same_as_write = json_readSameAsWrite->valueint == 1;
  return memAccess;
}

void parseStaticNode(char *filename, int CodeCount) {
  long length;
  char *buffer = readFile(filename, length);
  cJSON *data = cJSON_Parse(buffer);
  delete[] buffer;

  CodeToStaticNode = new StaticNode*[CodeCount];
  cJSON *json_staticGraphs = cJSON_GetObjectItem(data, "out_result");
  int numGraphs = cJSON_GetArraySize(json_staticGraphs);
  for (int i = 0; i < numGraphs; i++) {
    cJSON *json_staticGraph = cJSON_GetArrayItem(json_staticGraphs, i);
    cJSON *json_staticNodes = cJSON_GetObjectItem(json_staticGraph, "id_to_node");
    int numNodes = cJSON_GetArraySize(json_staticNodes);
    for (int j = 0; j < numNodes; j++) {
      cJSON *json_staticNode = cJSON_GetArrayItem(json_staticNodes, j);
      int id = cJSON_GetObjectItem(json_staticNode, "id")->valueint;
      long insn = cJSON_GetObjectItem(json_staticNode, "insn")->valueint;
      StaticNodeIdToInsn.insert({id, insn});
      if (InsnToCode.find(insn) == InsnToCode.end()) continue;
      unsigned short currCode =  InsnToCode[insn];
      //cout << "Parsing code: " << currCode << endl;
      CodeToStaticNode[currCode] = new StaticNode();
      CodeToStaticNode[currCode]->insn = insn;
      CodeToStaticNode[currCode]->id = id;
      //cout << "id " << id << endl;

      //int numAccess = 0;
      cJSON *json_memLoad = cJSON_GetObjectItem(json_staticNode, "mem_load");
      if (json_memLoad->child == NULL) {
        CodeToStaticNode[currCode]->mem_load = NULL;
      } else {
        CodeToStaticNode[currCode]->mem_load = parseMemoryAccess(json_memLoad);
        //numAccess ++;
      }

      cJSON *json_memStore = cJSON_GetObjectItem(json_staticNode, "mem_store");
      if (json_memStore->child == NULL) {
        CodeToStaticNode[currCode]->mem_store = NULL;
      } else {
        CodeToStaticNode[currCode]->mem_store = parseMemoryAccess(json_memStore);
        //numAccess ++;
      }
      //cout << " code: " << currCode << " accesses " << numAccess <<  " reg count " << CodeToRegCount[currCode] << endl;

      cJSON *json_cfPredes = cJSON_GetObjectItem(json_staticNode, "cf_predes");
      int count = cJSON_GetArraySize(json_cfPredes);
      for (int k = 0; k < count; k++){
        cJSON *json_Id = cJSON_GetArrayItem(json_cfPredes, k);
        CodeToStaticNode[currCode]->cf_prede_ids.push_back(json_Id->valueint);
      }

      cJSON *json_cfSucces = cJSON_GetObjectItem(json_staticNode, "cf_succes");
      count = cJSON_GetArraySize(json_cfSucces);
      for (int k = 0; k < count; k++){
        cJSON *json_Id = cJSON_GetArrayItem(json_cfSucces, k);
        CodeToStaticNode[currCode]->cf_succe_ids.push_back(json_Id->valueint);
      }

      cJSON *json_dfPredes = cJSON_GetObjectItem(json_staticNode, "df_predes");
      count = cJSON_GetArraySize(json_dfPredes);
      for (int k = 0; k < count; k++){
        cJSON *json_Id = cJSON_GetArrayItem(json_dfPredes, k);
        CodeToStaticNode[currCode]->df_prede_ids.push_back(json_Id->valueint);
      }

      cJSON *json_dfSucces = cJSON_GetObjectItem(json_staticNode, "df_succes");
      count = cJSON_GetArraySize(json_dfSucces);
      for (int k = 0; k < count; k++){
        cJSON *json_Id = cJSON_GetArrayItem(json_dfSucces, k);
        CodeToStaticNode[currCode]->df_succe_ids.push_back(json_Id->valueint);
      }
    }
  }

  for (int i = 1; i < CodeCount; i++) {
    for (int j = 0; j < CodeToStaticNode[i]->cf_prede_ids.size(); j++) {
      int id = CodeToStaticNode[i]->cf_prede_ids[j];
      if (StaticNodeIdToInsn.find(id) != StaticNodeIdToInsn.end()) {
        CodeToStaticNode[i]->cf_prede_codes.push_back(InsnToCode[StaticNodeIdToInsn[id]]);
      }
    }
    for (int j = 0; j < CodeToStaticNode[i]->cf_succe_ids.size(); j++) {
      int id = CodeToStaticNode[i]->cf_succe_ids[j];
      if (StaticNodeIdToInsn.find(id) != StaticNodeIdToInsn.end()) {
        CodeToStaticNode[i]->cf_succe_codes.push_back(InsnToCode[StaticNodeIdToInsn[id]]);
      }
    }
    for (int j = 0; j < CodeToStaticNode[i]->df_prede_ids.size(); j++) {
      int id = CodeToStaticNode[i]->df_prede_ids[j];
      if (StaticNodeIdToInsn.find(id) != StaticNodeIdToInsn.end()) {
        CodeToStaticNode[i]->df_prede_codes.push_back(InsnToCode[StaticNodeIdToInsn[id]]);
      }
    }
    for (int j = 0; j < CodeToStaticNode[i]->df_succe_ids.size(); j++) {
      int id = CodeToStaticNode[i]->df_succe_ids[j];
      if (StaticNodeIdToInsn.find(id) != StaticNodeIdToInsn.end()) {
        CodeToStaticNode[i]->df_succe_codes.push_back(InsnToCode[StaticNodeIdToInsn[id]]);
      }
    }
  }
}

void initData() {
  long length;
  char *buffer = readFile("preprocess_data", length);//TODO delete
  int CodeCount;

  cJSON *data = cJSON_Parse(buffer);
  delete[] buffer;
  StartInsn = (long)cJSON_GetObjectItem(data, "start_insn")->valueint;

  cJSON *json_codeToInsn = cJSON_GetObjectItem(data, "code_to_insn");
  unordered_map<long, long> map1;
  parseJsonMap(json_codeToInsn, map1);
  CodeCount = map1.size() + 1;
  CodeToInsn = new long[CodeCount];
  for (auto it = map1.begin(); it != map1.end(); it++) {
    CodeToInsn[(*it).first] = (*it).second;
    InsnToCode.insert({(*it).second, (unsigned short)(*it).first});
  }
  StartInsnCode = InsnToCode[StartInsn];

  cJSON *json_startInsns = cJSON_GetObjectItem(data, "start_insns");
  if (json_startInsns != NULL) {
    parseJsonList(json_startInsns, StartInsns);
    CodeOfStartInsns = new bool[CodeCount];
    for (int i = 0; i < CodeCount; i++) CodeOfStartInsns[i] = false;
    for (auto it = StartInsns.begin(); it != StartInsns.end(); it++) {
      CodeOfStartInsns[InsnToCode[(*it)]] = true;
      cout << InsnToCode[(*it)] << " is start code " << endl;
    }
  }

  cJSON *json_insnsWithRegs = cJSON_GetObjectItem(data, "insns_with_regs");
  parseJsonList(json_insnsWithRegs, InsnsWithRegs);
  CodesWithRegs = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesWithRegs[i] = false;
  for (auto it = InsnsWithRegs.begin(); it != InsnsWithRegs.end(); it++) {
    CodesWithRegs[InsnToCode[(*it)]] = true;
  }

  cJSON *json_insnOfCFNodes = cJSON_GetObjectItem(data, "insn_of_cf_nodes");
  parseJsonList(json_insnOfCFNodes, InsnOfCFNodes);
  CodesOfCFNodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesOfCFNodes[i] = false;
  for (auto it = InsnOfCFNodes.begin(); it != InsnOfCFNodes.end(); it++) {
    unsigned short code = InsnToCode[(*it)];
    CodesOfCFNodes[code] = true;
  }

  cJSON *json_insnOfDFNodes = cJSON_GetObjectItem(data, "insn_of_df_nodes");
  parseJsonList(json_insnOfDFNodes, InsnOfDFNodes);
  CodesOfDFNodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesOfDFNodes[i] = false;
  for (auto it = InsnOfDFNodes.begin(); it != InsnOfDFNodes.end(); it++) {
    unsigned short code = InsnToCode[(*it)];
    CodesOfDFNodes[code] = true;
  }

  cJSON *json_insnOfLocalDFNodes = cJSON_GetObjectItem(data, "insn_of_local_df_nodes");
  parseJsonList(json_insnOfLocalDFNodes, InsnOfLocalDFNodes);
  CodesOfMemLoadNodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesOfMemLoadNodes[i] = false;
  for (auto it = InsnOfLocalDFNodes.begin(); it != InsnOfLocalDFNodes.end(); it++) {
    unsigned short code = InsnToCode[(*it)];
    CodesOfMemLoadNodes[code] = true;
  }

  cJSON *json_insnOfRemoteDFNodes = cJSON_GetObjectItem(data, "insn_of_remote_df_nodes");
  parseJsonList(json_insnOfRemoteDFNodes, InsnOfRemoteDFNodes);
  CodesOfMemStoreNodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesOfMemStoreNodes[i] = false;
  for (auto it = InsnOfRemoteDFNodes.begin(); it != InsnOfRemoteDFNodes.end(); it++) {
    CodesOfMemStoreNodes[InsnToCode[(*it)]] = true;
  }

  cJSON *json_insnToRegCount = cJSON_GetObjectItem(data, "insn_to_reg_count");
  unordered_map<long, long> map2;
  parseJsonMap(json_insnToRegCount, map2);
  CodeToRegCount = new int[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodeToRegCount[i] = 0;
  for (auto it = map2.begin(); it != map2.end(); it++) {
    //InsnToRegCount.insert({(long)(*it).first, (int)(*it).second});
    CodeToRegCount[InsnToCode[(long)(*it).first]] = (int)(*it).second;
  }

  cJSON *json_insnToRegCount2 = cJSON_GetObjectItem(data, "insn_to_reg_count2");
  unordered_map<long, long> map3;
  parseJsonMap(json_insnToRegCount2, map3);
  CodeToRegCount2 = new int[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodeToRegCount2[i] = 0;
  for (auto it = map3.begin(); it != map3.end(); it++) {
    //InsnToRegCount.insert({(long)(*it).first, (int)(*it).second});
    CodeToRegCount2[InsnToCode[(long)(*it).first]] = (int)(*it).second;
  }

  PendingCodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) PendingCodes[i] = false;

  CfPredeCodeToSucceNodes = new std::vector<StaticNode*>[CodeCount];

  PendingCfPredeCodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) PendingCfPredeCodes[i] = false;

  DfPredeCodeToSucceNodes = new std::vector<StaticNode*>[CodeCount];

  PendingLocalDefCodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) PendingLocalDefCodes[i] = false;
  PendingRemoteDefCodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) PendingRemoteDefCodes[i] = false;


  cJSON *json_traceFile = cJSON_GetObjectItem(data, "trace_file");
  traceFile = json_traceFile->valuestring;

  cJSON *json_staticGraphFile = cJSON_GetObjectItem(data, "static_graph_file");
  parseStaticNode(json_staticGraphFile->valuestring, CodeCount);
  // TODO free json data lol
}

int main()
{
  std::chrono::steady_clock::time_point t1 = std::chrono::steady_clock::now();
  initData();
  std::chrono::steady_clock::time_point t2 = std::chrono::steady_clock::now();
  std::cout << "Init data took = " << std::chrono::duration_cast<std::chrono::seconds>(t2 - t1).count() << "[s]" << std::endl;

  long length;
  char *buffer = readFile(traceFile, length);
  cout << "Reading " << length << " characters... " << endl;
  std::chrono::steady_clock::time_point t3 = std::chrono::steady_clock::now();
  std::cout << "Reading file took = " << std::chrono::duration_cast<std::chrono::seconds>(t3 - t2).count() << "[s]" << std::endl;

  string outTraceFile(traceFile);
  outTraceFile += ".parsed";
  ofstream os;
  os.open(outTraceFile.c_str(), ios::out);

  cout << "Starting insn is: 0x" << std::hex << StartInsn << std::dec << " code is: " << StartInsnCode << endl;
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
  for (long i = length; i >= 0;) {
    unsigned short code;
    long regValue = 0;
    i-=2;
    std::memcpy(&code, buffer+i, sizeof(unsigned short));

    bool parse = false;
    if (code == StartInsnCode || CodeOfStartInsns[code] || PendingCodes[code]) {
      parse = true;
    }
    if (CodesWithRegs[code]) {
      i-=8;
      if (parse) {
        std::memcpy(&regValue, buffer + i, sizeof(long));
      }
      //cout << "contains reg" << code << endl;
    }
    if (!parse) continue;

    /*
    if (code == 3252) {
      cout << "HERE" << endl;
    }*/

    int regCount2 =  CodeToRegCount2[code];
    if (!hasPrevValues && regCount2 > 0) {
      if (regCount2 > 1) {
        if (pendingRegCount == 0) {
          pendingRegCount = 1;
          offRegValue = regValue;
          continue;
        }
        pendingRegCount = 0;
      } else {
        offRegValue = 0;
      }
      prevRegValue = regValue;
      prevOffRegValue = offRegValue;
      hasPrevValues = true;
      continue;
    } else {
      int regCount1 =  CodeToRegCount[code];
      if (regCount1 > 1) { // large than zero only if has more than one reg!
        if (pendingRegCount == 0) {
          pendingRegCount = 1;
          offRegValue = regValue;
          continue;
        }
        pendingRegCount = 0;
      } else {
        offRegValue = 0;
      }
    }

    StaticNode *sn = CodeToStaticNode[code];
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
      //long addr = sn->mem_store->calc_addr(regValue, offRegValue);
      if (PendingAddrs.find(addr) == PendingAddrs.end() && code != StartInsnCode) {
        if (!PendingLocalDefCodes[code]) continue; // FIXME: unfortuanately, could be a local def dep too, need to make logic less messy if have more time ...
      } else {
        //cout << "  mem addr matched " << endl;
        PendingAddrs.erase(addr);
      }
    }
    if (regCount2 > 1) {
      os.write((char*)&code, sizeof(unsigned short));
      os.write((char*)&prevOffRegValue, sizeof(long));
    }
    if (regCount2 > 0) {
      os.write((char*)&code, sizeof(unsigned short));
      os.write((char*)&prevRegValue, sizeof(long));
    }

    if (CodeToRegCount[code] > 1) {
      os.write((char*)&code, sizeof(unsigned short));
      os.write((char*)&offRegValue, sizeof(long));
    }

    os.write((char*)&code, sizeof(unsigned short));
    if (CodesWithRegs[code]) {
      os.write((char*)&regValue, sizeof(long));
    }

    //cout << "====" << nodeCount << "\n";
    //cout << "curr code" << code << " index: "<< i <<endl;
    //cout << std::hex << CodeToInsn[code] << std::dec << "\n";

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

    bool loadsMemory = sn->mem_load != NULL;
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
  }
  os.close();
  std::chrono::steady_clock::time_point t4 = std::chrono::steady_clock::now();
  std::cout << "Parsing took = " << std::chrono::duration_cast<std::chrono::seconds>(t4 - t3).count() << "[s]" << std::endl;

  cout << "total nodes: " << nodeCount << endl;
}
