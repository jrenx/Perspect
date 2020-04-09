#include <stdio.h>
#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_process.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_point.h"
#include "BPatch_function.h"
#include "BPatch_flowGraph.h"

using namespace std;
using namespace Dyninst;

BPatch bpatch;

typedef enum {
  create,
  attach,
  open
} accessType_t;

// Attach, create, or open a file for rewriting
BPatch_addressSpace* startInstrumenting(accessType_t accessType, const char* name, int pid, const char* argv[]) {
  BPatch_addressSpace* handle = NULL;

  switch(accessType) {
    case create:
      handle = bpatch.processCreate(name, argv);
      if (!handle) { fprintf(stderr, "processCreate failed\n");}
      break;
    case attach:
      handle = bpatch.processAttach(name, pid);
      if (!handle) { fprintf(stderr, "processAttach failed\n");}
      break;
    case open:
      // Open the binary file and all dependencies
      handle = bpatch.openBinary(name, true);
      if (!handle) { fprintf(stderr, "openBinary failed\n");}
      break;
  }

  return handle;
}

int main() {
  // Set up information about the program to be instrumented 
  const char* progName = "909_ziptest_exe";
  int progPID = 42;
  const char* progArgv[] = {"test.zip"};
  accessType_t mode = open;

  // Create/attach/open a binary
  BPatch_addressSpace* app = startInstrumenting(mode, progName, progPID, progArgv);
  if (!app) {
  	fprintf(stderr, "startInstrumenting failed\n");
	exit(1);
  }
}
