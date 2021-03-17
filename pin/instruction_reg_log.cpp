#include <pin.H>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
using std::hex;
using std::cerr;
using std::string;
using std::ios;
using std::endl;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;
std::vector<unsigned long> addresses;
std::vector<string> registers;

std::map<string, REG> reg_map;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "pin/ftrace.out", "specify trace file name");
KNOB<string> KnobInstructionArgs(KNOB_MODE_APPEND, "pintool", "i", "0x0", "specify instructions to trace");
KNOB<string> KnobRegisterArgs(KNOB_MODE_APPEND, "pintool", "r", "pc", "specify register for instruction");

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

VOID record_reg(ADDRINT pc, ADDRINT reg)
{
    TraceFile << pc << ": " << reg << endl;
}

/* ===================================================================== */

int get_ins_index(ADDRINT pc)
{
    for (std::vector<unsigned long>::iterator it = addresses.begin(); it != addresses.end(); ++it)
    {
        if (*it == pc) return std::distance(addresses.begin(), it);
    }
    return -1;
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
                int index = get_ins_index(INS_Address(ins));
                if (index != -1)
                {
                    string reg = registers[index];
                    if (reg == "pc") {
                        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_reg), IARG_INST_PTR, IARG_INST_PTR, IARG_END);
                    } else {
                        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_reg), IARG_INST_PTR, IARG_REG_VALUE, reg_map[reg], IARG_END);
                    }
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
    for (UINT32 i = 0; i < KnobInstructionArgs.NumberOfValues(); ++i) {
        unsigned long addr;
        std::istringstream iss(KnobInstructionArgs.Value(i));
        iss >> std::hex >> addr;
        addresses.push_back(addr);
    }

    for (UINT32 i = 0; i < KnobRegisterArgs.NumberOfValues(); ++ i) {
        registers.push_back(KnobRegisterArgs.Value(i));
    }

    TraceFile.open(KnobOutputFile.Value().c_str());

    TraceFile << hex;
    TraceFile.setf(ios::showbase);

    // Initialize reg_map
    reg_map["rbp"] = REG_RBP;
    reg_map["rsp"] = REG_RSP;
    reg_map["rdx"] = REG_RDX;
    reg_map["rbx"] = REG_RBX;
    reg_map["rsi"] = REG_RSI;
    reg_map["rdi"] = REG_RDI;
    reg_map["rcx"] = REG_RCX;
    reg_map["cl"] = REG_CL;
    //reg_map["r1"] = REG_R1;
    //reg_map["r2"] = REG_R2;
    //reg_map["r3"] = REG_R3;
    //reg_map["r4"] = REG_R4;
    //reg_map["r5"] = REG_R5;
    //reg_map["r6"] = REG_R6;
    //reg_map["r7"] = REG_R7;
    reg_map["r8"] = REG_R8;
    reg_map["r9"] = REG_R9;
    reg_map["r10"] = REG_R10;
    reg_map["r11"] = REG_R11;
    reg_map["r12"] = REG_R12;
    reg_map["r13"] = REG_R13;
    reg_map["r14"] = REG_R14;
    reg_map["r15"] = REG_R15;

    // Register ImageLoad to be called when an image is loaded
    //
    IMG_AddInstrumentFunction(ImageLoad, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    //
    PIN_StartProgram();

    return 0;
}

