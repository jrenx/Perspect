#include "pin.H"
#include <iostream>
#include <fstream>
using std::hex;
using std::cerr;
using std::string;
using std::ios;
using std::endl;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;
string rtn_name;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "ftrace.out", "specify trace file name");
KNOB<string> KnobFunctionArgs(KNOB_MODE_WRITEONCE, "pintool", "f", "main", "specify function to trace");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool produces an instruction trace for specific function." << endl << endl;
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

VOID ImageLoad(IMG img, VOID *v)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            if (RTN_Name(rtn).compare(rtn_name) == 0 ||
                RTN_Name(rtn).compare("__" + rtn_name) == 0)
            {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(start_log), IARG_END);
                for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
                {
                    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_pc), IARG_INST_PTR, IARG_END);
                }
                RTN_Close(rtn);
            }
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

    // Initialize symbol processing
    //
    PIN_InitSymbolsAlt(IFUNC_SYMBOLS);

    //Initialize global variables
    rtn_name = KnobFunctionArgs.Value();

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
