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

#define SAMPLE
#define SAMPLE_THRESHOLD 500
#define LARGE_THRESOLD  100000
#define CHECK_ALL_COUNTS

using namespace std;
using namespace boost;
//TODO: fix all the weird casings in this file.

boost::unordered_map<std::string, int> regSizeMap =
    {{"al"   ,1}, {"ah"   ,1}, {"ax"   ,2}, {"eax" ,4},  {"rax" ,8},
     {"bl"   ,1}, {"bh"   ,1}, {"bx"   ,2}, {"ebx" ,4},  {"rbx" ,8},
     {"cl"   ,1}, {"ch"   ,1}, {"cx"   ,2}, {"ecx" ,4},  {"rcx" ,8},
     {"dl"   ,1}, {"dh"   ,1}, {"dx"   ,2}, {"edx" ,4},  {"rdx" ,8},
     {"sil"  ,1},              {"si"   ,2}, {"esi"  ,4}, {"rsi" ,8},
     {"dil"  ,1},              {"di"   ,2}, {"edi"  ,4}, {"rdi" ,8},
     {"bpl"  ,1},              {"bp"   ,2}, {"ebp"  ,4}, {"rbp" ,8},
     {"spl"  ,1},              {"sp"   ,2}, {"esp"  ,4}, {"rsp" ,8},
     {"r8b"  ,1},              {"r8w"  ,2}, {"r8d"  ,4}, {"r8"  ,8},
     {"r9b"  ,1},              {"r9w"  ,2}, {"r9d"  ,4}, {"r9"  ,8},
     {"r10b" ,1},              {"r10w" ,2}, {"r10d" ,4}, {"r10" ,8},
     {"r11b" ,1},              {"r11w" ,2}, {"r11d" ,4}, {"r11" ,8},
     {"r12b" ,1},              {"r12w" ,2}, {"r12d" ,4}, {"r12" ,8},
     {"r13b" ,1},              {"r13w" ,2}, {"r13d" ,4}, {"r13" ,8},
     {"r14b" ,1},              {"r14w" ,2}, {"r14d" ,4}, {"r14" ,8},
     {"r15b" ,1},              {"r15w" ,2}, {"r15d" ,4}, {"r15" ,8}};

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
  int src_reg_size;
  int dst_reg_size;
};

class Context {
public:
  int pendingRegCount = 0;
  std::vector<long> pendingRegValues; // not used
  long offRegValue = 0;

  bool hasPrevValues = false;
  int pendingAccessCount = 0; // not used
  long prevRegValue = 0;
  long prevOffRegValue = 0;

  bool *PendingCodes = NULL;
  bool otherRegsParsed = false;
  bool *CodeWithLaterBitOpsExecuted = NULL;
  long *codeToBitOperand;
  bool *codeToBitOperandIsValid;
  bool * PendingLocalDefCodes;
  bool *PendingCfPredeCodes;
  std::vector<StaticNode*> *CfPredeCodeToSucceNodes;
  std::vector<StaticNode*> *DfPredeCodeToSucceNodes;

  Context(int CodeCount) {
    PendingCodes = new bool[CodeCount];
    for (int i = 0; i < CodeCount; i++) PendingCodes[i] = false;
    CodeWithLaterBitOpsExecuted = new bool[CodeCount];
    for (int i = 0; i < CodeCount; i++) CodeWithLaterBitOpsExecuted[i] = false;
    codeToBitOperand = new long[CodeCount];
    codeToBitOperandIsValid = new bool[CodeCount];
    for (int i = 0; i < CodeCount; i++) codeToBitOperandIsValid[i] = false;
    PendingLocalDefCodes = new bool[CodeCount];
    for (int i = 0; i < CodeCount; i++) PendingLocalDefCodes[i] = false;
    PendingCfPredeCodes = new bool[CodeCount];
    for (int i = 0; i < CodeCount; i++) PendingCfPredeCodes[i] = false;
    CfPredeCodeToSucceNodes = new std::vector<StaticNode*>[CodeCount];
    DfPredeCodeToSucceNodes = new std::vector<StaticNode*>[CodeCount];
  };
};

class Parser {
public:
  char *traceFile;
  bool DEBUG = false;
  int CodeCount = -1;
  int CodeCountWithStaticNode = -1;
  long *CodeToInsn;
  unordered_map<long, unsigned short> InsnToCode;

  unordered_map<long, int> InsnToRegCount;
  int *CodeToRegCount;
  int *CodeToRegCount2;

  bool *isBitOpCode;
  bool *containsBitOpCode;

  short **CodeToPriorBitOpCodes;
  int *CodeToPriorBitOpCodeCount;

  short **LaterBitOpCodeToCodes;
  int *LaterBitOpCodeToCodeCount;

  unordered_set<long> StartInsns;
  bool *CodeOfStartInsns;
  int MaxStartCode = 0;

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

  bool *PendingRemoteDefCodes;

  unordered_set<long> PendingAddrs;

  StaticNode **CodeToStaticNode;
  unordered_map<int, long> StaticNodeIdToInsn;

  long *OccurrencesPerCode;
  long *OccurrencesPerStartingCode;
#ifdef COUNT_ONLY
  unsigned long *AverageTimeStampPerCode;
#endif 

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

  void parseJsonMapOfLists(cJSON *json_Map, unordered_map<long, unordered_set<long>*> &map) {
    int size = cJSON_GetArraySize(json_Map);
    for (int i = 0; i < size; i++) {
      cJSON *ele = cJSON_GetArrayItem(json_Map, i);
      long key = atol(ele->string);
      unordered_set<long> *set = new unordered_set<long>; //TODO, properly clean up, right now ignored LOL
      parseJsonList(ele, *set);
      //cout << key << endl;
      //cout << ele->valueint << endl;
      map.insert({key, set});
    }
  }

  static char *readFile(char *filename, unsigned long &length) {
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

  void parseStaticNode(char *filename) {
    unsigned long length;
    char *buffer = Parser::readFile(filename, length);
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
        //cout << "Parsing insn: " << std::hex << insn << std::dec <<endl;
        if (InsnToCode.find(insn) == InsnToCode.end()) continue;
        unsigned short currCode =  InsnToCode[insn];
        //cout << "Parsing code: " << currCode << endl;
        // FIXME: reduce array accesses here :p
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

        cJSON *json_regLoad = cJSON_GetObjectItem(json_staticNode, "reg_load");
        if (json_regLoad->valuestring == NULL) {
          CodeToStaticNode[currCode]->src_reg_size = 8;
        } else if (regSizeMap.find(json_regLoad->valuestring) == regSizeMap.end()) {
          CodeToStaticNode[currCode]->src_reg_size = 8;
        } else {
          CodeToStaticNode[currCode]->src_reg_size = regSizeMap[json_regLoad->valuestring];
        }

        cJSON *json_regStore = cJSON_GetObjectItem(json_staticNode, "reg_store");
        if (json_regStore->valuestring == NULL) {
          CodeToStaticNode[currCode]->dst_reg_size = 8;
        } else if (regSizeMap.find(json_regStore->valuestring) == regSizeMap.end()) {
          CodeToStaticNode[currCode]->dst_reg_size = 8;
        } else {
          CodeToStaticNode[currCode]->dst_reg_size = regSizeMap[json_regStore->valuestring];
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

    for (int i = 1; i <= CodeCountWithStaticNode; i++) {
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

  void initData(int pa_id) {
    std::chrono::steady_clock::time_point t1 = std::chrono::steady_clock::now();
    unsigned long length;
    string preprocessDataFile((char *)"preprocess_data");
    if (pa_id >= 0) {
      preprocessDataFile += "_";
      preprocessDataFile += std::to_string(pa_id);
    }
    char *buffer = Parser::readFile((char *)preprocessDataFile.c_str(), length);//TODO delete

    cJSON *data = cJSON_Parse(buffer);
    delete[] buffer;

    CodeCountWithStaticNode = cJSON_GetObjectItem(data, "max_code_with_static_node")->valueint;

    cJSON *json_codeToInsn = cJSON_GetObjectItem(data, "code_to_insn");
    unordered_map<long, long> map1;
    parseJsonMap(json_codeToInsn, map1);
    CodeCount = map1.size() + 1;
    CodeToInsn = new long[CodeCount];
    for (auto it = map1.begin(); it != map1.end(); it++) {
      CodeToInsn[(*it).first] = (*it).second;
      InsnToCode.insert({(*it).second, (unsigned short)(*it).first});
    }
    OccurrencesPerCode = new long[CodeCount];
    for (int i = 0; i < CodeCount; i++) OccurrencesPerCode[i] = 0;
 
#ifdef COUNT_ONLY
    AverageTimeStampPerCode = new unsigned long[CodeCount];
    for (int i = 0; i < CodeCount; i++) AverageTimeStampPerCode[i] = 0;
#endif

    cJSON *json_startInsns = cJSON_GetObjectItem(data, "starting_insns");
    if (json_startInsns != NULL) {
      parseJsonList(json_startInsns, StartInsns);
      CodeOfStartInsns = new bool[CodeCount];
      for (int i = 0; i < CodeCount; i++) CodeOfStartInsns[i] = false;
      for (auto it = StartInsns.begin(); it != StartInsns.end(); it++) {
        short code = InsnToCode[(*it)];
        if (code > MaxStartCode) MaxStartCode = code;
        CodeOfStartInsns[code] = true;
        cout << InsnToCode[(*it)] << " is start code " << endl;
      }
      cout << "Max start code is " << MaxStartCode << endl;
    }

    OccurrencesPerStartingCode = new long[MaxStartCode + 1];
    for (int i = 0; i < MaxStartCode + 1; i++) OccurrencesPerStartingCode[i] = 0;

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
      CodeToRegCount[InsnToCode[(long)(*it).first]] = (int)(*it).second;
    }

    cJSON *json_insnToRegCount2 = cJSON_GetObjectItem(data, "insn_to_reg_count2");
    unordered_map<long, long> map3;
    parseJsonMap(json_insnToRegCount2, map3);
    CodeToRegCount2 = new int[CodeCount];
    for (int i = 0; i < CodeCount; i++) CodeToRegCount2[i] = 0;
    for (auto it = map3.begin(); it != map3.end(); it++) {
      CodeToRegCount2[InsnToCode[(long)(*it).first]] = (int)(*it).second;
    }

    isBitOpCode = new bool[CodeCount];
    for (int i = 0; i < CodeCount; i++) isBitOpCode[i] = false;

    containsBitOpCode = new bool[CodeCount];
    for (int i = 0; i < CodeCount; i++) containsBitOpCode[i] = false;

    cJSON *json_loadInsnToBitOps = cJSON_GetObjectItem(data, "load_insn_to_bit_ops");
    unordered_map<long, unordered_set<long>*> map4;
    parseJsonMapOfLists(json_loadInsnToBitOps, map4);
    CodeToPriorBitOpCodes = new short*[CodeCount];
    CodeToPriorBitOpCodeCount = new int[CodeCount];
    for (int i = 0; i < CodeCount; i++) CodeToPriorBitOpCodes[i] = NULL;
    for (int i = 0; i < CodeCount; i++) CodeToPriorBitOpCodeCount[i] = -1;
    for (auto it = map4.begin(); it != map4.end(); it++) {
      short key = InsnToCode[(long)(*it).first];
      unordered_set<long> *set = (*it).second;
      containsBitOpCode[key] = true;
      CodeToPriorBitOpCodes[key] = new short[set->size()];
      CodeToPriorBitOpCodeCount[key] = set->size();
      int i = 0;
      for (auto sit = set->begin(); sit != set->end(); sit++) {
        short c = InsnToCode[*sit];
        CodeToPriorBitOpCodes[key][i] = c;
        isBitOpCode[c] = true;
        i++;
      }
    }

    cJSON *json_bitOpToStoreInsns = cJSON_GetObjectItem(data, "bit_op_to_store_insns");
    unordered_map<long, unordered_set<long>*> map5;
    parseJsonMapOfLists(json_bitOpToStoreInsns, map5);
    LaterBitOpCodeToCodes = new short*[CodeCount];
    LaterBitOpCodeToCodeCount = new int[CodeCount];
    for (int i = 0; i < CodeCount; i++) LaterBitOpCodeToCodes[i] = NULL;
    for (int i = 0; i < CodeCount; i++) LaterBitOpCodeToCodeCount[i] = -1;
    for (auto it = map5.begin(); it != map5.end(); it++) {
      short key = InsnToCode[(long)(*it).first];
      unordered_set<long> *set = (*it).second;
      containsBitOpCode[key] = true;
      LaterBitOpCodeToCodes[key] = new short[set->size()];
      LaterBitOpCodeToCodeCount[key] = set->size();
      isBitOpCode[key] = true;
      int i = 0;
      for (auto sit = set->begin(); sit != set->end(); sit++) {
        short c = InsnToCode[*sit];
        LaterBitOpCodeToCodes[key][i] = c;
        i++;
      }
    }

    PendingRemoteDefCodes = new bool[CodeCount];
    for (int i = 0; i < CodeCount; i++) PendingRemoteDefCodes[i] = false;


    cJSON *json_traceFile = cJSON_GetObjectItem(data, "trace_file");
    traceFile = json_traceFile->valuestring;

    cJSON *json_staticGraphFile = cJSON_GetObjectItem(data, "static_graph_file");
    parseStaticNode(json_staticGraphFile->valuestring);
    // TODO free json data lol
    std::chrono::steady_clock::time_point t2 = std::chrono::steady_clock::now();
    std::cout << "Init data took = " << std::chrono::duration_cast<std::chrono::seconds>(t2 - t1).count() << "[s]" << std::endl;
  }

  int parse(int pa_id, unsigned long length, char *buffer)
  {
    cout << pa_id << endl;
    std::chrono::steady_clock::time_point t3 = std::chrono::steady_clock::now();
#ifndef COUNT_ONLY    
    string outTraceFile(traceFile);
    outTraceFile += ".parsed";
    if (pa_id >= 0) {
      outTraceFile += "_";
      outTraceFile += std::to_string(pa_id);
    }
    ofstream os;
    os.open(outTraceFile.c_str(), ios::out);

    string outTraceThreadIdFile(traceFile);
    outTraceThreadIdFile += ".parsed_thread_ids";
    if (pa_id >= 0) {
      outTraceThreadIdFile += "_";
      outTraceThreadIdFile += std::to_string(pa_id);
    }
    ofstream osti;
    osti.open(outTraceThreadIdFile.c_str(), ios::out);
#endif
    long nodeCount = 0;
    long prevNodeCount = 0;
    unsigned long occurrences;
    long uid = -1;
    // Note: the same instruction executed will have multiple UIDs if multiple regs are printed at the instrustion
    unsigned short code = 0;
    long regValue;
    u_int8_t threadId = 0;
    StaticNode *sn;
    bool loadsMemory;
    int regCount2;

    short *bitOps;
    boost::unordered_map<u_int8_t, Context *> ctxtMap;
#ifndef COUNT_ONLY
    // Because the parse is read in reverse by the python logic, make sure to always print a place holder of thread first.
    os.write((char*)&code, sizeof(unsigned short));
#endif
    Context *ctxt = new Context(CodeCount); // In order to be backward-compatible with single threaded traces.
    unsigned long i = length;
    for (; i > 0;) {
      regValue = 0;
      uid ++;
      i -= sizeof(unsigned short);
      std::memcpy(&code, buffer+i, sizeof(unsigned short));
      assert(code <= CodeCount);
      assert(code >= 0);
      if (code == 0) {
        i -= sizeof(u_int8_t);
        if (prevNodeCount == nodeCount) continue;
        prevNodeCount = nodeCount;
        u_int8_t prevThreadId = threadId;
        std::memcpy(&threadId, buffer + i, sizeof(u_int8_t));

#ifndef COUNT_ONLY    
        os.write((char*)&code, sizeof(unsigned short));
        osti.write((char*)&threadId, sizeof(u_int8_t));
#endif

        // In order to be backward-compatible with single threaded traces,
        // always make a context by default in the first place,
        // only save the context to the map when we get to a new thread.
        if (prevThreadId == 0) continue; // first thread seen
        ctxtMap[prevThreadId] = ctxt;
        if (ctxtMap.find(threadId) == ctxtMap.end()) {
          ctxt = new Context(CodeCount);
        } else {
          ctxt = ctxtMap[threadId];
        }
        continue;
      }

      //if (code == 2 || code == 3) {
      //  cout << "HERE " <<uid << endl;
      //}

#ifndef COUNT_ONLY
      bool parse = false;
      if (CodeOfStartInsns[code] || PendingRemoteDefCodes[code] || ctxt->PendingCodes[code]) {
        parse = true;
#ifdef SAMPLE
        if(CodeOfStartInsns[code]) {
          long startingCodeOcurrences = OccurrencesPerStartingCode[code];
          if (startingCodeOcurrences % SAMPLE_THRESHOLD != 0) {
            parse = false;
	        }
	        OccurrencesPerStartingCode[code] = startingCodeOcurrences + 1;
	      }
#endif	
      }
      if (OccurrencesPerCode[code] > LARGE_THRESOLD) parse = false;
#else
      bool parse = true;
#endif

      bool isBitOp = isBitOpCode[code];
      bool containsReg = CodesWithRegs[code];
      if (containsReg || isBitOp) {
        i -= sizeof(long);
        if (parse || isBitOp) {
          std::memcpy(&regValue, buffer + i, sizeof(long));
        }
        //cout << "contains reg" << code << endl;
      }

      // TODO, if other regs are not parsed, won't parse the bit var at all
      // could this be a problem?
      if (isBitOp && (!containsReg || ctxt->otherRegsParsed)) {
        // The use of the "otherRegsParsed" variable is to ensure that
        // if an instruction has an addr load and store or both (so parse is true), and a bit op
        // we parse the bit op last, after any load or store has been parsed
        // and not confuse it with a load and store
        ctxt->otherRegsParsed = false;

        short *parentOfBitOps = LaterBitOpCodeToCodes[code];
        if (parentOfBitOps != NULL) {
          // The associated instruction is supposed to happen before the bit operations
          // in the reversed trace, and it should have been a store instruction
          // if the store associated instruction was included in the parsed result
          // we include the bit ops into the parsed result right away
          int count = LaterBitOpCodeToCodeCount[code];
          for (int j = 0; j < count; j++) {
            if (ctxt->CodeWithLaterBitOpsExecuted[parentOfBitOps[j]]) {
              if (DEBUG) cout << "[store]  " << code << " " << parentOfBitOps[j] << " " << std::bitset<64>(regValue) << endl;
#ifndef COUNT_ONLY 
              os.write((char *) &code, sizeof(unsigned short));
              os.write((char *) &uid, sizeof(long));
              os.write((char *) &regValue, sizeof(long));
#endif
              //ctxt->CodeWithLaterBitOpsExecuted[parentOfBitOps[j]] = false;
            }
          }
        } else {
          // The associated instruction is supposed to happen after the bit operations
          // in the reversed trace, and it should have been a load instruction
          // we cache the bit operations for now and wait for the
          // associated load instruction to be included in the parsed result
          // then include the cached bit operations as well
          ctxt->codeToBitOperand[code] = regValue;
          ctxt->codeToBitOperandIsValid[code] = true;
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
      if (!ctxt->hasPrevValues && regCount2 > 0) {
        if (regCount2 > 1) {
          if (ctxt->pendingRegCount == 0) {
            ctxt->pendingRegCount = 1;
            ctxt->offRegValue = regValue;
            goto DONT_PARSE;
          }
          ctxt->pendingRegCount = 0;
        } else {
          ctxt->offRegValue = 0;
        }
        ctxt->prevRegValue = regValue;
        ctxt->prevOffRegValue = ctxt->offRegValue;
        ctxt->hasPrevValues = true;
        goto DONT_PARSE;
      } else {
        int regCount1 =  CodeToRegCount[code];
        if (regCount1 > 1) { // large than zero only if has more than one reg!
          if (ctxt->pendingRegCount == 0) {
            ctxt->pendingRegCount = 1;
            ctxt->offRegValue = regValue;
            goto DONT_PARSE;
          }
          ctxt->pendingRegCount = 0;
        } else {
          ctxt->offRegValue = 0;
        }
      }
      if (isBitOp) ctxt->otherRegsParsed = true;
      sn = CodeToStaticNode[code];
      if (PendingRemoteDefCodes[code]) {
        long addr = 0;
        if (sn->mem_store == NULL) {
          //cout << "[warn] " << sn->id << " does not store to memory? " << endl;
          ctxt->hasPrevValues = false;
        } else {
          //assert(sn->mem_store != NULL);
          if (ctxt->hasPrevValues) {
            addr = sn->mem_store->calc_addr(ctxt->prevRegValue, ctxt->prevOffRegValue);
            ctxt->hasPrevValues = false;
          } else {
            addr = sn->mem_store->calc_addr(regValue, ctxt->offRegValue);
          }
        }
        assert(ctxt->hasPrevValues == false);
        //long addr = sn->mem_store->calc_addr(regValue, ctxt->offRegValue);
        //if (PendingAddrs.find(addr) == PendingAddrs.end() && (code > 0 && code > MaxStartCode)) {
        if (PendingAddrs.find(addr) == PendingAddrs.end() && !CodeOfStartInsns[code]) {
          if (!ctxt->PendingLocalDefCodes[code]) goto DONT_PARSE; // FIXME: unfortuanately, could be a local def dep too, need to make logic less messy if have more time ...
        } else {
          //cout << "  mem addr matched " << endl;
          // Approximation

          if (sn->src_reg_size == 8 && !containsBitOpCode[code])
            PendingAddrs.erase(addr);
        }
      } else {
        ctxt->hasPrevValues = false;
        assert(ctxt->hasPrevValues == false);
      }

      bitOps = CodeToPriorBitOpCodes[code];
      if (bitOps != NULL) {
        int count = CodeToPriorBitOpCodeCount[code];
        for (int j = 0; j < count; j++) {
          short bitOpCode = bitOps[j];
          if (ctxt->codeToBitOperandIsValid[bitOpCode]) {
            if (DEBUG) cout << "[load] " << bitOpCode << " " << count << " " << std::bitset<64>(ctxt->codeToBitOperand[bitOpCode]) << endl;
#ifndef COUNT_ONLY
            os.write((char *) &bitOpCode, sizeof(unsigned short));
            os.write((char *) &uid, sizeof(long));
            os.write((char *) &ctxt->codeToBitOperand[bitOpCode], sizeof(long));
#endif
            ctxt->codeToBitOperandIsValid[bitOpCode] = false;
          }
        }
      }

#ifndef COUNT_ONLY
      if (regCount2 > 1) {
        if (DEBUG) cout << "Persisting1 " << code << endl;
        os.write((char*)&code, sizeof(unsigned short));
        os.write((char*)&uid, sizeof(long));
        os.write((char*)&ctxt->prevOffRegValue, sizeof(long));
      }
      if (regCount2 > 0) {
        if (DEBUG) cout << "Persisting2 " << code << endl;
        os.write((char*)&code, sizeof(unsigned short));
        os.write((char*)&uid, sizeof(long));
        os.write((char*)&ctxt->prevRegValue, sizeof(long));
      }

      if (CodeToRegCount[code] > 1) {
        if (DEBUG) cout << "Persisting3 " << code << endl;
        os.write((char*)&code, sizeof(unsigned short));
        os.write((char*)&uid, sizeof(long));
        os.write((char*)&ctxt->offRegValue, sizeof(long));
      }

      if (DEBUG) cout << "Persisting4 " << code << endl;
      os.write((char*)&code, sizeof(unsigned short));
      os.write((char*)&uid, sizeof(long));
      if (CodesWithRegs[code]) {
        if (DEBUG) cout << "Persisting5 " << code << endl;
        os.write((char*)&regValue, sizeof(long));
      }
#endif
      //cout << "====" << nodeCount << "\n";
      //cout << "curr code" << code << " index: "<< i <<endl;
      //cout << std::hex << CodeToInsn[code] << std::dec << "\n";
      occurrences = OccurrencesPerCode[code] + 1;
      OccurrencesPerCode[code] = occurrences;
#ifdef COUNT_ONLY
      if (occurrences == 1) AverageTimeStampPerCode[code] = uid;
      else {
        unsigned long avg = AverageTimeStampPerCode[code];
        avg += (uid - avg)/occurrences;
        AverageTimeStampPerCode[code] = avg;
      }
#endif
      
      nodeCount ++;
#ifndef COUNT_ONLY

      if (ctxt->PendingCfPredeCodes[code]) {
        std::vector<unsigned short> toRemove;
        for(auto it = ctxt->CfPredeCodeToSucceNodes[code].begin(); it != ctxt->CfPredeCodeToSucceNodes[code].end(); it++) {
          StaticNode * succeNode = *it;
          for (auto iit = succeNode->cf_prede_codes.begin();
               iit != succeNode->cf_prede_codes.end(); iit ++) {
            toRemove.push_back(*iit);
          }
        }
        for(auto it = toRemove.begin(); it != toRemove.end(); it++) {
          unsigned short removeCode = *it;
          ctxt->CfPredeCodeToSucceNodes[removeCode].clear();
          ctxt->PendingCfPredeCodes[removeCode] = false;
          if (!ctxt->PendingLocalDefCodes[removeCode]) ctxt->PendingCodes[removeCode] = false;
        }
      }

      if (ctxt->PendingLocalDefCodes[code]) {//} && !CodesOfMemStoreNodes[code]) {
        std::vector<unsigned short> toRemove;
        for(auto it = ctxt->DfPredeCodeToSucceNodes[code].begin(); it != ctxt->DfPredeCodeToSucceNodes[code].end(); it++) {
          StaticNode * succeNode = *it;
          assert (succeNode->mem_load == NULL);
          for (auto iit = succeNode->df_prede_codes.begin();
               iit != succeNode->df_prede_codes.end(); iit++) {
            toRemove.push_back(*iit);
          }
        }
        for(auto it = toRemove.begin(); it != toRemove.end(); it++) {
          unsigned short removeCode = *it;
          ctxt->DfPredeCodeToSucceNodes[removeCode].clear();
          ctxt->PendingLocalDefCodes[removeCode] = false;
          if (!ctxt->PendingCfPredeCodes[removeCode]) ctxt->PendingCodes[removeCode] = false;
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
            ctxt->PendingLocalDefCodes[currCode] = true;
            ctxt->PendingCodes[currCode] = true;
            ctxt->DfPredeCodeToSucceNodes[currCode].push_back(sn);
          } else {
            PendingRemoteDefCodes[currCode] = true;
          }
        }
        if (loadsMemory) {
          long addr = sn->mem_load->calc_addr(regValue, ctxt->offRegValue);
          PendingAddrs.insert(addr);
        }
      } else {
        if (loadsMemory && sn->mem_load->read_same_as_write) { // TODO, shouldnt insert itself?
          long addr = sn->mem_load->calc_addr(regValue, ctxt->offRegValue);
          PendingAddrs.insert(addr);
        }
      }
      if (sn->cf_prede_codes.size() > 0) {
        for (auto it = sn->cf_prede_codes.begin(); it != sn->cf_prede_codes.end(); it++) {
          unsigned short currCode = *it;
          if (!CodesOfCFNodes[currCode] && !CodesOfDFNodes[currCode]) {
            continue;
          }
          ctxt->CfPredeCodeToSucceNodes[currCode].push_back(sn);
          ctxt->PendingCfPredeCodes[currCode] = true;
          ctxt->PendingCodes[currCode] = true;
        }
      }
#endif
      ctxt->CodeWithLaterBitOpsExecuted[code] = true;
      continue;

      DONT_PARSE:
      if (LaterBitOpCodeToCodes[code] != NULL) {
        ctxt->CodeWithLaterBitOpsExecuted[code] = false;
      }

      bitOps = CodeToPriorBitOpCodes[code];
      if (bitOps != NULL) {
        int count = CodeToPriorBitOpCodeCount[code];
        for (int j = 0; j < count; j++) {
          short bitOpCode = bitOps[j];
          ctxt->codeToBitOperandIsValid[bitOpCode] = false;
        }
      }
    }
#ifndef COUNT_ONLY
    // print a placeholder thread id in the end
    // the smallest legal thread id is 1 (determined by my PIN logic)
    threadId = 0;
    osti.write((char*)&threadId, sizeof(u_int8_t));
    os.close();
    osti.close();
#endif
    std::chrono::steady_clock::time_point t4 = std::chrono::steady_clock::now();
    std::cout << "Parsing took = " << std::chrono::duration_cast<std::chrono::seconds>(t4 - t3).count() << "[s]" << std::endl;

#ifndef COUNT_ONLY    
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
      if (count <= LARGE_THRESOLD) continue;
      //cout << "LARGE_THRESOLD " << i << "\n";
      osl << std::hex << CodeToInsn[i] << std::dec << " " << i << " occurrences: " << count << "\n";
      nodeCount -= count;
    }
    osl.close();
#ifdef CHECK_ALL_COUNTS
    string outDebugFile(traceFile);
    outDebugFile += ".debug";
    if (pa_id >= 0) {
      outDebugFile += "_";
      outDebugFile += std::to_string(pa_id);
    }
    ofstream osd;
    osd.open(outDebugFile.c_str());
    for (int i = 1; i < CodeCount; i++) {
      long count = OccurrencesPerCode[i];
      osd << std::hex << CodeToInsn[i] << std::dec << " " << i << " occurrences: " << count << "\n";
    }
    osd.close();
#endif
#else
    string outCountFile(traceFile);
    outCountFile += ".count";
    ofstream osc;
    osc.open(outCountFile.c_str());
    for (int i = 1; i < CodeCount; i++) {
      unsigned long count = OccurrencesPerCode[i];
#ifdef SAMPLE
      if (count == 0) count = 0;
      else count = (count / SAMPLE_THRESHOLD) + 1;
#endif
      osc << std::hex << CodeToInsn[i] << std::dec << " " << count << "\n";
    }
    osc.close();
#endif

    cout << "total nodes: " << nodeCount << endl;
 
#ifdef COUNT_ONLY
    string outAvgTimeStampFile(traceFile);
    outAvgTimeStampFile += ".avg_timestamp";
    ofstream osa;
    osa.open(outAvgTimeStampFile.c_str());
    for (int i = 1; i < CodeCount; i++) {
      unsigned long avg = AverageTimeStampPerCode[i];
      osa << std::hex << CodeToInsn[i] << std::dec << " " << avg << "\n";
    }
    osa.close();
#endif
  }
};
