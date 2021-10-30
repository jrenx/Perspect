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

  p.parse(pa_id, length, buffer);
}
