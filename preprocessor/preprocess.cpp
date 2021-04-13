#include <iostream>     // std::cout
#include <fstream>      // std::ifstream
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "cJSON.h"
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>
using namespace std;
using namespace boost;
//TODO: fix all the weird casings in this file.
class MemAccess {
public:
  string reg;
  long shift;
  long offset;
  string off_reg;
  // TODO bit var too

  long calc_addr(long regValue, long offRegValue) {
    long addr = 0;
    if (reg != "") addr = regValue;
    if (shift != 0) addr = addr << shift;
    if (off_reg != "") {
      addr += offRegValue * offset;
    } else {
      addr += offset;
    }
    return addr;
  }
};

class StaticNode {
public:
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

unordered_set<long> InsnsWithRegs;
bool *CodesWithRegs;

unordered_set<long> InsnOfCFNodes;
bool * CodesOfCFNodes;

unordered_set<long> InsnOfDFNodes;
bool * CodesOfDFNodes;

unordered_set<long> InsnOfLocalDFNodes;
bool * CodesOfLocalDFNodes;

unordered_set<long> InsnOfRemoteDFNodes;
bool * CodesOfRemoteDFNodes;

long StartInsn;
unsigned short StartInsnCode;

std::vector<StaticNode*> *CfPredeCodeToSucceNodes;
bool *PendingCfPredeCodes;
std::vector<StaticNode*> *DfPredeCodeToSucceNodes;
bool *PendingDfPredeCodes;

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
    //cout << "HERE" << ele->valueint << endl;
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
  char *reg = json_reg->valuestring;
  memAccess->reg = string(reg);
  memAccess->shift = cJSON_GetObjectItem(json_memAccess, "shift")->valueint;
  memAccess->offset = cJSON_GetObjectItem(json_memAccess, "off")->valueint;
  cJSON *json_offReg = cJSON_GetObjectItem(json_memAccess, "off_reg");
  if (json_offReg->valuestring == NULL) {
    memAccess->off_reg = "";
  } else {
    memAccess->off_reg = string(json_offReg->valuestring);
  }
  return memAccess;
}

void parseStaticNode(char *filename, int CodeCount) {
  long length;
  char *buffer = readFile(filename, length);
  cJSON *data = cJSON_Parse(buffer);
  delete[] buffer;

  CodeToStaticNode = new StaticNode*[CodeCount];
  cJSON *json_statiGraphs = cJSON_GetObjectItem(data, "out_result");
  int numGraphs = cJSON_GetArraySize(json_statiGraphs);
  for (int i = 0; i < numGraphs; i++) {
    cJSON *json_staticGraph = cJSON_GetArrayItem(json_statiGraphs, i);
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

      cJSON *json_memLoad = cJSON_GetObjectItem(json_staticNode, "mem_load");
      if (json_memLoad->child == NULL) {
        CodeToStaticNode[currCode]->mem_load = NULL;
      } else {
        CodeToStaticNode[currCode]->mem_load = parseMemoryAccess(json_memLoad);
      }

      cJSON *json_memStore = cJSON_GetObjectItem(json_staticNode, "mem_store");
      if (json_memStore->child == NULL) {
        CodeToStaticNode[currCode]->mem_store = NULL;
      } else {
        CodeToStaticNode[currCode]->mem_store = parseMemoryAccess(json_memStore);
      }

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

  for (int i = 1; i < CodeCount + 1; i++) {
    for (int j = 0; j < CodeToStaticNode[i]->cf_prede_ids.size(); j++) {
      int id = CodeToStaticNode[i]->cf_prede_ids[j];
      if (StaticNodeIdToInsn.find(id) != StaticNodeIdToInsn.end()) {
        CodeToStaticNode[i]->cf_prede_codes.push_back(InsnToRegCount[StaticNodeIdToInsn[id]]);
      }
    }
    for (int j = 0; j < CodeToStaticNode[i]->cf_succe_ids.size(); j++) {
      int id = CodeToStaticNode[i]->cf_succe_ids[j];
      if (StaticNodeIdToInsn.find(id) != StaticNodeIdToInsn.end()) {
        CodeToStaticNode[i]->cf_succe_codes.push_back(InsnToRegCount[StaticNodeIdToInsn[id]]);
      }
    }
    for (int j = 0; j < CodeToStaticNode[i]->df_prede_ids.size(); j++) {
      int id = CodeToStaticNode[i]->df_prede_ids[j];
      if (StaticNodeIdToInsn.find(id) != StaticNodeIdToInsn.end()) {
        CodeToStaticNode[i]->df_prede_codes.push_back(InsnToRegCount[StaticNodeIdToInsn[id]]);
      }
    }
    for (int j = 0; j < CodeToStaticNode[i]->df_succe_ids.size(); j++) {
      int id = CodeToStaticNode[i]->df_succe_ids[j];
      if (StaticNodeIdToInsn.find(id) != StaticNodeIdToInsn.end()) {
        CodeToStaticNode[i]->df_succe_codes.push_back(InsnToRegCount[StaticNodeIdToInsn[id]]);
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
  CodeCount = map1.size();
  CodeToInsn = new long[CodeCount];
  for (auto it = map1.begin(); it != map1.end(); it++) {
    CodeToInsn[(*it).first] = (*it).second;
    InsnToCode.insert({(*it).second, (unsigned short)(*it).first});
  }
  StartInsnCode = InsnToCode[StartInsn];

  cJSON *json_insnsWithRegs = cJSON_GetObjectItem(data, "insns_with_regs");
  parseJsonList(json_insnsWithRegs, InsnsWithRegs);
  CodesWithRegs = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesWithRegs[i] = false;
  for (auto it = InsnsWithRegs.begin(); it != InsnsWithRegs.end(); it++) {
    CodesWithRegs[InsnToCode[(*it)]] = true;
  }

  cJSON *json_insnOfCFNodes = cJSON_GetObjectItem(data, "insn_of_cf_nodes");
  parseJsonList(json_insnsWithRegs, InsnOfCFNodes);
  CodesOfCFNodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesOfCFNodes[i] = false;
  for (auto it = InsnOfCFNodes.begin(); it != InsnOfCFNodes.end(); it++) {
    CodesOfCFNodes[InsnToCode[(*it)]] = true;
  }

  cJSON *json_insnOfDFNodes = cJSON_GetObjectItem(data, "insn_of_df_nodes");
  parseJsonList(json_insnsWithRegs, InsnOfDFNodes);
  CodesOfDFNodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesOfDFNodes[i] = false;
  for (auto it = InsnOfDFNodes.begin(); it != InsnOfDFNodes.end(); it++) {
    CodesOfDFNodes[InsnToCode[(*it)]] = true;
  }

  cJSON *json_insnOfLocalDFNodes = cJSON_GetObjectItem(data, "insn_of_local_df_nodes");
  parseJsonList(json_insnsWithRegs, InsnOfLocalDFNodes);
  CodesOfLocalDFNodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesOfLocalDFNodes[i] = false;
  for (auto it = InsnOfLocalDFNodes.begin(); it != InsnOfLocalDFNodes.end(); it++) {
    CodesOfLocalDFNodes[InsnToCode[(*it)]] = true;
  }

  cJSON *json_insnOfRemoteDFNodes = cJSON_GetObjectItem(data, "insn_of_remote_df_nodes");
  parseJsonList(json_insnsWithRegs, InsnOfRemoteDFNodes);
  CodesOfRemoteDFNodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) CodesOfRemoteDFNodes[i] = false;
  for (auto it = InsnOfRemoteDFNodes.begin(); it != InsnOfRemoteDFNodes.end(); it++) {
    CodesOfRemoteDFNodes[InsnToCode[(*it)]] = true;
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

  CfPredeCodeToSucceNodes = new std::vector<StaticNode*>[CodeCount];
  PendingCfPredeCodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) PendingCfPredeCodes[i] = false;
  DfPredeCodeToSucceNodes = new std::vector<StaticNode*>[CodeCount];
  PendingDfPredeCodes = new bool[CodeCount];
  for (int i = 0; i < CodeCount; i++) PendingDfPredeCodes[i] = false;

  cJSON *json_traceFile = cJSON_GetObjectItem(data, "trace_file");
  traceFile = json_traceFile->valuestring;

  cJSON *json_staticGraphFile = cJSON_GetObjectItem(data, "static_graph_file");
  parseStaticNode(json_staticGraphFile->valuestring, CodeCount);
  // TODO free json data lol
}

int main()
{
  initData();
  //cout << "Reading " << length << " characters... " << endl;
  long length;
  char *buffer = readFile(traceFile, length);

  cout << "Starting insn is: 0x" << std::hex << StartInsn << std::dec << " code is: " << StartInsnCode << endl;
  //long j = 0;
  bool found = false;
  int pendingRegCount = 0;
  std::vector<long> pendingRegValues;
  for (long i = length - 2; i >= 0;) {
    unsigned short code;
    long regValue = 0;
    std::memcpy(&code, buffer+i, sizeof(unsigned short));
    i-=2;
    //cout << "curr code" << code << endl;

    bool parse = false;
    if (code == StartInsnCode || PendingCfPredeCodes[code] || PendingDfPredeCodes[code]) {
      parse = true;
    }
    if (CodesWithRegs[code] == true) {
      if (parse) std::memcpy(&regValue, buffer+i, sizeof(long));
      i-=8;
    }
    if (!parse) continue;

    long offRegValue = 0;
    if (CodeToRegCount[code] > 0) {
      if (pendingRegCount == 0) {
        pendingRegCount = CodeToRegCount[code];
        pendingRegValues.clear();
      }
      if (pendingRegValues.size() + 1 < pendingRegCount) {
        pendingRegValues.push_back(regValue);
        continue;
      } else {
        pendingRegCount = 0;
        offRegValue = pendingRegValues.back();
      }
    }

    StaticNode *sn = CodeToStaticNode[code];
    if (CodesOfRemoteDFNodes[code] == true) {
      long addr = sn->mem_store->calc_addr(regValue, offRegValue);
      if (PendingAddrs.find(addr) != PendingAddrs.end() && code == StartInsnCode) {
        continue;
      } else {
        PendingAddrs.erase(addr);
      }
    }
    // save the node
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
      }
    }

    if (PendingDfPredeCodes[code] && CodesOfRemoteDFNodes[code] == false) {
      std::vector<unsigned short> toRemove;
      for(auto it = DfPredeCodeToSucceNodes[code].begin(); it != DfPredeCodeToSucceNodes[code].end(); it++) {
        StaticNode * succeNode = *it;
        for (auto iit = succeNode->cf_prede_codes.begin();
             iit != succeNode->cf_prede_codes.end(); iit ++) {
          toRemove.push_back(*iit);
        }
      }
      for(auto it = toRemove.begin(); it != toRemove.end(); it++) {
        unsigned short removeCode = *it;
        DfPredeCodeToSucceNodes[removeCode].clear();
        PendingDfPredeCodes[removeCode] = false;
      }
    }

    if (sn->df_prede_codes.size() != 0) {
      for (auto it = sn->df_prede_codes.begin(); it != sn->df_prede_codes.end(); it++) {
        unsigned short currCode = *it;
        if (CodesOfCFNodes[currCode] == false && CodesOfDFNodes[currCode] == false) {
          continue;
        }
        DfPredeCodeToSucceNodes[currCode].push_back(sn);
        PendingDfPredeCodes[currCode] = true;
      }
      if (sn->mem_load != NULL) {
        long addr = sn->mem_load->calc_addr(regValue, offRegValue);
        PendingAddrs.insert(addr);
      }
    }
    if (sn->cf_prede_codes.size() != 0) {
      for (auto it = sn->cf_prede_codes.begin(); it != sn->cf_prede_codes.end(); it++) {
        unsigned short currCode = *it;
        if (CodesOfCFNodes[currCode] == false && CodesOfDFNodes[currCode] == false) {
          continue;
        }
        CfPredeCodeToSucceNodes[currCode].push_back(sn);
        PendingCfPredeCodes[currCode] = true;
      }
    }
  }
}