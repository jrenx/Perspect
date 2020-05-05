#include <pin.H>
#include <iostream>
#include <fstream>
#include <vector>
using std::hex;
using std::cerr;
using std::string;
using std::ios;
using std::endl;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;
std::vector<ADDRINT> addresses;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "ftrace.out", "specify trace file name");
KNOB<ADDRINT> KnobInstructionArgs(KNOB_MODE_APPEND, "pintool", "i", 0x0, "specify instructions to trace");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool produces a trace for specific instructions." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */

VOID start_log()
{
    TraceFile << "start" << endl;
}

/* ===================================================================== */

VOID record_pc(ADDRINT pc)
{
    TraceFile << pc << endl;
}

/* ===================================================================== */

bool is_ins_traced(ADDRINT pc)
{
    for (auto addr: addresses)
    {
        if (addr == pc) return true;
    }
    return false;
}

/* ===================================================================== */

VOID ImageLoad(IMG img, VOID *v)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            RTN_Open(rtn);
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                if (is_ins_traced(INS_ADDRESS(ins)))
                {
                    INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(record_pc), IARG_INST_PTR, IARG_END);
                }
            }
            RTN_Close(rtn);
        }
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    TraceFile << "# eof" << endl;

    TraceFile.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main (INT32 argc, CHAR *argv[])
{
    // Initialize pin
    //
    if (PIN_Init(argc, argv)) return 0;

    //Initialize global variables
    for (auto i = 0; i < KnobInstructionArgs.NumberOfValues(); ++i) {
        addresses.push_back(KnobInstructionArgs.Value(i));
    }

    TraceFile.open(KnobOutputFile.Value().c_str());

    TraceFile << hex;
    TraceFile.setf(ios::showbase);

    // Register ImageLoad to be called when an image is loaded
    //
    IMG_AddInstrumentFunction(ImageLoad, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    //
    PIN_StartProgram();

    return 0;
}

