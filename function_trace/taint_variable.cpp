#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <map>

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "taint.out", "specify trace file name");

std::ofstream TraceFile;
std::map<UINT64, UINT64> addressTainted;
std::map<REG, UINT64> regsTainted;

INT32 Usage()
{
    std::cerr << "This tool taint the memory read and write" << std::endl;
    return -1;
}

bool checkAlreadyRegTainted(REG reg)
{
    std::map<REG, UINT64>::iterator it = regsTainted.find(reg);
    return it != regsTainted.end();
}

VOID removeMemTainted(UINT64 addr)
{
    std::map<UINT64, UINT64>::iterator it = addressTainted.find(addr);
    UINT64 origin = it->second;
    addressTainted.erase(it);
    TraceFile << std::hex << "\t\t\t" << addr << ": " << origin << " is now freed" << std::endl;
}

VOID addMemTainted(UINT64 addr, UINT64 origin)
{
    addressTainted[addr] = origin;
    TraceFile << std::hex << "\t\t\t" << addr << ": " << origin << " is now tainted" << std::endl;
}

bool taintReg(REG reg, UINT64 origin)
{
    if (checkAlreadyRegTainted(reg) == true){
        TraceFile << "\t\t\t" << REG_StringShort(reg) << ": " << std::hex << origin << " is already tainted" << std::endl;
        return false;
    }

    regsTainted[reg] = origin;

    TraceFile << "\t\t\t" << REG_StringShort(reg) << ": " << std:: hex<< origin << " is now tainted" << std::endl;
    return true;
}

bool removeRegTainted(REG reg)
{
    std::map<REG, UINT64>::iterator it = regsTainted.find(reg);
    UINT64 origin = it->second;
    regsTainted.erase(it);
    TraceFile << "\t\t\t" << REG_StringShort(reg) << ": " << std::hex << origin << " is now freed" << std::endl;
    return true;
}

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
    UINT64 addr = memOp;

    if (opCount != 2)
        return;

    std::map<UINT64, UINT64>::iterator it = addressTainted.find(addr);

    if (it != addressTainted.end()) {
        TraceFile << std::hex << "[READ in " << addr << ": " << it->second << "]\t" << insAddr << ": " << insDis << std::endl;
        taintReg(reg_r, it->second);
        return;
    }

    /* if mem != tained and reg == taint => free the reg */
    if (checkAlreadyRegTainted(reg_r)){
        UINT64 origin = regsTainted.find(reg_r)->second;
        TraceFile << std::hex << "[READ in " << addr << ": " << origin << "]\t" << insAddr << ": " << insDis << std::endl;
        removeRegTainted(reg_r);
    }
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
    UINT64 addr = memOp;

    if (opCount != 2)
        return;

    std::map<UINT64, UINT64>::iterator it = addressTainted.find(addr);
    if (it != addressTainted.end()) {
        TraceFile << std::hex << "[WRITE in " << addr << ": " << it->second << "]\t" << insAddr << ": " << insDis << std::endl;
        if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
            removeMemTainted(addr);
        return;
    }

    if (checkAlreadyRegTainted(reg_r)){
        UINT64 origin = regsTainted.find(reg_r)->second;
        TraceFile << std::hex << "[WRITE in " << addr << ": " << origin << "]\t" << insAddr << ": " << insDis << std::endl;
        addMemTainted(addr, reg_r);
    }
}

VOID spreadRegTaint(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w)
{
    if (opCount != 2)
        return;

    if (REG_valid(reg_w)){
        if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))){
            TraceFile << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
            UINT64 origin = regsTainted.find(reg_w)->second;
            TraceFile << "\t\t\toutput: "<< REG_StringShort(reg_w) << ": " << std::hex << origin << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
            removeRegTainted(reg_w);
        }
        else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
            TraceFile << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
            UINT64 origin = regsTainted.find(reg_r)->second;
            TraceFile << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r) << ": " << std::hex << origin << std::endl;
            taintReg(reg_w, origin);
        }
    }
}


VOID Instruction(INS ins, VOID *v)
{
    if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, 0),
                IARG_MEMORYOP_EA, 0,
                IARG_END);
    }
    else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, 1),
                IARG_MEMORYOP_EA, 0,
                IARG_END);
    }
    else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_RegR(ins, 0),
                IARG_UINT32, INS_RegW(ins, 0),
                IARG_END);
    }
}

UINT64 mallocSize;

VOID SetSize(ADDRINT size) {
    mallocSize = static_cast<UINT64>(size);
}

VOID MarkRegion(ADDRINT start) {
    UINT64 startAddr = static_cast<UINT64>(start);

    for (unsigned  int i = 0; i < mallocSize; i++) {
        addressTainted[startAddr + i] = startAddr;
    }

    TraceFile << "[TAINT]\t\t\tbytes tainted from " << std::hex <<  startAddr << " to " << startAddr + mallocSize << " (via mallocgc)"<< std::endl;
    mallocSize = 0;
}

VOID ImageLoad(IMG img, VOID *v)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            if (RTN_Name(rtn).compare("runtime.mallocgc") == 0)
            {
                RTN_Open(rtn);

                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetSize,
                               IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                               IARG_END);
                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MarkRegion,
                               IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

                RTN_Close(rtn);
            }
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
    TraceFile << "# eof" << std::endl;

    TraceFile.close();
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    PIN_InitSymbolsAlt(IFUNC_SYMBOLS);

    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile.setf(std::ios::showbase);

    PIN_SetSyntaxIntel();
    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();

    return 0;
}

