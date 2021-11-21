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

class Context {
public:
  int pendingRegCount = 0;
  std::vector<long> pendingRegValues; // not used
  long offRegValue = 0;
  bool otherRegsParsed = false;

  Context(int CodeCount) { };
};

class Parser {
public:
  char *traceFile;
  bool DEBUG = false;
  int CodeCount = -1;
  long *CodeToInsn;
  unordered_map<long, unsigned short> InsnToCode;
  int *CodeToRegCount;
  MemAccess **CodeToMemAccess;
  unordered_set<long>** codeToCalltargets;

  long GetFileSize(std::string filename) {
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
  }

  void parseJsonMap(cJSON *json_Map, unordered_map<long, long> &map) {
    int size = cJSON_GetArraySize(json_Map);
    for (int i = 0; i < size; i++) {
      cJSON *ele = cJSON_GetArrayItem(json_Map, i);
      long key = atol(ele->string);
      //cout << key << endl;
      //cout << ele->valueint << endl;
      map.insert({key, (long) ele->valueint}); //TODO long?? save as string??
    }
  }

  void parseJsonList(cJSON *json_List, unordered_set<long> &set) {
    int size = cJSON_GetArraySize(json_List);
    for (int i = 0; i < size; i++) {
      cJSON *ele = cJSON_GetArrayItem(json_List, i);
      set.insert((long) ele->valueint); //TODO long?? save as string??
    }
  }

  void parseJsonMapOfLists(cJSON *json_Map, unordered_map<long, unordered_set < long> *

  > &map) {
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
    is.seekg(0, is.end);
    length = is.tellg();
    is.seekg(0, is.beg);
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
    else if (memAccess->off_reg == "ES") {// || memAccess->off_reg == "DS") {
      //cout << "Ignore ES" << endl;
      memAccess->has_off_reg = false;
      memAccess->offset = 0;
    } else memAccess->has_off_reg = true;
    cJSON *json_readSameAsWrite = cJSON_GetObjectItem(json_memAccess, "read_same_as_write");
    memAccess->read_same_as_write = json_readSameAsWrite->valueint == 1;
    return memAccess;
  }

  void initData(int pa_id) {
    std::chrono::steady_clock::time_point t1 = std::chrono::steady_clock::now();
    unsigned long length;
    string preprocessDataFile((char *) "preprocess_data");
    if (pa_id >= 0) {
      preprocessDataFile += "_";
      preprocessDataFile += std::to_string(pa_id);
    }
    char *buffer = Parser::readFile((char *) preprocessDataFile.c_str(), length);//TODO delete

    cJSON *data = cJSON_Parse(buffer);
    delete[] buffer;

    cJSON *json_traceFile = cJSON_GetObjectItem(data, "trace_file");
    traceFile = json_traceFile->valuestring;

    cJSON *json_codeToInsn = cJSON_GetObjectItem(data, "code_to_insn");
    unordered_map<long, long> map1;
    parseJsonMap(json_codeToInsn, map1);
    CodeCount = map1.size() + 1;
    CodeToInsn = new long[CodeCount];
    for (auto it = map1.begin(); it != map1.end(); it++) {
      CodeToInsn[(*it).first] = (*it).second;
      InsnToCode.insert({(*it).second, (unsigned short) (*it).first});
    }

    cJSON *json_insnToRegCount = cJSON_GetObjectItem(data, "insn_to_reg_count");
    unordered_map<long, long> map2;
    parseJsonMap(json_insnToRegCount, map2);
    CodeToRegCount = new int[CodeCount];
    for (int i = 0; i < CodeCount; i++) CodeToRegCount[i] = 0;
    codeToCalltargets = new unordered_set<long>*[CodeCount];
    for (int i = 0; i < CodeCount; i++) codeToCalltargets[i] = new unordered_set<long>;
    for (auto it = map2.begin(); it != map2.end(); it++) {
      CodeToRegCount[InsnToCode[(long) (*it).first]] = (int) (*it).second;
    }
    /*
    CodeToMemAccess = new MemAccess*[CodeCount];
    cJSON *json_memLoads = cJSON_GetObjectItem(data, "mem_accesses");
    int num = cJSON_GetArraySize(json_memLoads);
    for (int i = 0; i < num; i++) {
      cJSON *json_memLoad = cJSON_GetArrayItem(json_memLoads, i);
      MemAccess *mem_load = parseMemoryAccess(json_memLoad);
      CodeToMemAccess[i+1] = mem_load;
    }*/
  }

  int parse(int pa_id, unsigned long length, char *buffer) {
    cout << pa_id << endl;
    std::chrono::steady_clock::time_point t3 = std::chrono::steady_clock::now();

    long nodeCount = 0;
    long prevNodeCount = 0;
    unsigned short code = 0;
    long regValue;
    u_int8_t threadId = 0;
    boost::unordered_map<u_int8_t, Context *> ctxtMap;
    Context *ctxt = new Context(CodeCount); // In order to be backward-compatible with single threaded traces.
    unsigned long i = length;
    cout << CodeCount << endl;
    for (; i > 0;) {
      regValue = 0;
      //cout << "index: " << i << endl;
      i -= sizeof(unsigned short);
      std::memcpy(&code, buffer + i, sizeof(unsigned short));
      //cout << "code: " << code << endl;
      assert(code <= CodeCount);
      assert(code >= 0);
      if (code == 0) {
        i -= sizeof(u_int8_t);
        if (prevNodeCount == nodeCount) continue;
        prevNodeCount = nodeCount;
        u_int8_t prevThreadId = threadId;
        std::memcpy(&threadId, buffer + i, sizeof(u_int8_t));
        //cout << "thread id: " << threadId << endl;
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

      i -= sizeof(long);
      std::memcpy(&regValue, buffer + i, sizeof(long));
      //cout << "reg: "  << std::hex << regValue << std::dec << endl;
      /*
      if (CodeToRegCount[code] > 1) { // large than zero only if has more than one reg!
        if (ctxt->pendingRegCount == 0) {
          ctxt->pendingRegCount = 1;
          ctxt->offRegValue = regValue;
          continue;
        }
        ctxt->pendingRegCount = 0;
      } else {
        ctxt->offRegValue = 0;
      }
      nodeCount ++;
      MemAccess *mem_load = CodeToMemAccess[code];
      long addr = mem_load->calc_addr(regValue, ctxt->offRegValue);
      cout << "addr: " << std::hex << addr << std::dec << endl;
      */
      unordered_set<long>* callTargets = codeToCalltargets[code];
      callTargets->insert(regValue);
    }

    string outFile(traceFile);
    outFile += ".parsed";
    ofstream os;
    os.open(outFile.c_str());
    os << std::hex;
    for (unsigned short i = 1; i < CodeCount; i++) {
      unordered_set<long>* callTargets = codeToCalltargets[i];
      if (callTargets->size() == 0) continue;
      os << CodeToInsn[i] << "|";
      for (auto it = callTargets->begin(); it != callTargets->end(); it ++) {
        os << " " << *(it);
      }
      os << "\n";
    }
    os.close();
  }
};

int main()
{
  Parser p = Parser();
  p.initData(-1);

  unsigned long length;
  std::chrono::steady_clock::time_point t2 = std::chrono::steady_clock::now();
  char *buffer = Parser::readFile(p.traceFile, length);
  cout << "Read " << length << " characters... " << endl;
  std::chrono::steady_clock::time_point t3 = std::chrono::steady_clock::now();
  std::cout << "Reading file took = " << std::chrono::duration_cast<std::chrono::seconds>(t3 - t2).count() << "[s]" << std::endl;

  p.parse(-1, length, buffer);
}
