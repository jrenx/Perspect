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
#define PORT 8999

using namespace std;
using namespace boost;
//TODO: fix all the weird casings in this file.


int num_processor = 16;
condition_variable* cvs;
bool *conditions;
mutex *ms;
int *open_sockets;
char *OK =  (char *)"OK";
void reparse_worker(int pa_id, unsigned long length, char *buffer) {
  while (true) {
    unique_lock<mutex> lk(ms[pa_id]);
    while(!conditions[pa_id]) cvs[pa_id].wait(lk);

    Parser p = Parser();
    p.initData(pa_id);
    p.parse(pa_id, length, buffer);
    send(open_sockets[pa_id], OK, strlen(OK), 0);
    cout<< "[" << pa_id << "]OK message sent" << endl;
    conditions[pa_id] = false;
    lk.unlock();
  }
}

int main(int argc, char *argv[]) {

  assert (argc >= 2);
  char *inputFile = (char *) argv[1];
  cout << inputFile << endl;

  unsigned long length;
  std::chrono::steady_clock::time_point t2 = std::chrono::steady_clock::now();
  char *buffer = Parser::readFile(inputFile, length);
  cout << "Read " << length << " characters... " << endl;
  std::chrono::steady_clock::time_point t3 = std::chrono::steady_clock::now();
  std::cout << "Reading file took = " << std::chrono::duration_cast<std::chrono::seconds>(t3 - t2).count() << "[s]"
            << std::endl;

  open_sockets = new int[num_processor];
  cvs = new condition_variable[num_processor];
  ms = new mutex[num_processor];
  thread* threads[num_processor];
  conditions = new bool[num_processor];
  for (int i = 0; i < num_processor; i++) {
    thread* t = new thread(reparse_worker, i, length, buffer);
    threads[i] = t;
    conditions[i] = false;
  }

  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
  {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // Forcefully attaching socket to the port 8999
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                 &opt, sizeof(opt)))
  {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons( PORT );

  // Forcefully attaching socket to the port 8999
  if (bind(server_fd, (struct sockaddr *)&address,
           sizeof(address))<0)
  {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }
  if (listen(server_fd, num_processor) < 0)
  {
    perror("listen");
    exit(EXIT_FAILURE);
  }
  cout << "waiting for new connection" << endl;
  while (true) {
    if ((new_socket = accept(server_fd, (struct sockaddr *) &address,
                             (socklen_t * ) & addrlen)) < 0) {
      perror("accept");
      exit(EXIT_FAILURE);
    }
    cout << "accepting new connection" << endl;
    char receive_buffer[1024] = {0};
    int valread = read(new_socket, receive_buffer, 1024);
    cout << " bytes read " << valread << endl;
    //printf("%s\n",receive_buffer);
    int pa_id = 0;
    std::memcpy(&pa_id, receive_buffer, sizeof(char));

    cout << "parallel id is:" << pa_id << endl;

    {
      lock_guard<mutex> lk(ms[pa_id]);
      conditions[pa_id] = true;
      open_sockets[pa_id] = new_socket;
      cvs[pa_id].notify_one();
    }
  }

  for (int i = 0; i < num_processor; i++) {
    threads[0]->join();
  }
}
