#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <map>


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
    addressTainted.remove(it);
    std::cout << std::hex << "\t\t\t" << addr << ": " << origin << " is now freed" << std::endl;
}

VOID addMemTainted(UINT64 addr, UINT64 origin)
{
    addressTainted[addr] = origin;
    std::cout << std::hex << "\t\t\t" << addr << ": " << origin << " is now tainted" << std::endl;
}

bool taintReg(REG reg, UINT64 origin)
{
    if (checkAlreadyRegTainted(reg) == true){
        std::cout << "\t\t\t" << REG_StringShort(reg) << ": " << std::hex << origin << " is already tainted" << std::endl;
        return false;
    }

    regsTainted[reg] = origin;

    std::cout << "\t\t\t" << REG_StringShort(reg) << ": " << origin << " is now tainted" << std::endl;
    return true;
}

bool removeRegTainted(REG reg)
{
    std::map<REG, UINT64>::iterator it = regsTainted.find(reg);
    UINT64 origin = it->second;
    regsTainted.remove(reg);
    std::cout << "\t\t\t" << REG_StringShort(reg) << ": " << std::hex << origin << " is now freed" << std::endl;
    return true;
}

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
    UINT64 addr = memOp;

    if (opCount != 2)
        return;

    std::map<UINT64, UINT64>::iterator it = addressTainted.find(addr);

    if (it != addressTainted.end()) {
        std::cout << std::hex << "[READ in " << addr << ": " << it->second << "]\t" << insAddr << ": " << insDis << std::endl;
        taintReg(reg_r, it->second);
        return;
    }

    /* if mem != tained and reg == taint => free the reg */
    if (checkAlreadyRegTainted(reg_r)){
        UINT64 origin = regsTainted.find(reg_r)->second;
        std::cout << std::hex << "[READ in " << addr << ": " << origin << "]\t" << insAddr << ": " << insDis << std::endl;
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
        std::cout << std::hex << "[WRITE in " << addr << ": " << it->second << "]\t" << insAddr << ": " << insDis << std::endl;
        if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
            removeMemTainted(addr);
        return;
    }

    if (checkAlreadyRegTainted(reg_r)){
        std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
        addMemTainted(addr);
    }
}

VOID spreadRegTaint(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w)
{
    if (opCount != 2)
        return;

    if (REG_valid(reg_w)){
        if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))){
            std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
            UINT64 origin = regsTainted.find(reg_w)->second;
            std::cout << "\t\t\toutput: "<< REG_StringShort(reg_w) <<": " << std::hex << origin << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
            removeRegTainted(reg_w);
        }
        else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
            std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
            UINT64 origin = regsTainted.find(reg_r)->second;
            std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r <<": " << std::hex << origin) << std::endl;
            taintReg(reg_w);
        }
    }
}


VOID Instruction(INS ins, VOID *v)
{
    if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, 0),
                IARG_MEMORYOP_EA, 0,
                IARG_END);
    }
    else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, 1),
                IARG_MEMORYOP_EA, 0,
                IARG_END);
    }
    else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
                IARG_ADDRINT, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_RegR(ins, 0),
                IARG_UINT32, INS_RegW(ins, 0),
                IARG_END);
    }
}

static unsigned int tryksOpen;

#define TRICKS(){if (tryksOpen++ == 0)return;}

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
    unsigned int i;
    UINT64 start, size;

    if (PIN_GetSyscallNumber(ctx, std) == __NR_read){

        TRICKS(); /* tricks to ignore the first open */

        start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
        size  = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

        for (i = 0; i < size; i++)
            addressTainted[start+i] = start;

        std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start+size << " (via read)"<< std::endl;
    }
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    PIN_SetSyntaxIntel();
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();

    return 0;
}

