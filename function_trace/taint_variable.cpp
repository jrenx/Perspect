
typedef VOID(* LEVEL_PINCLIENT::INS_INSTRUMENT_CALLBACK)(INS ins, VOID *v);
VOID LEVEL_PINCLIENT::INS_AddInstrumentFunction(INS_INSTRUMENT_CALLBACK fun, VOID *val);


VOID Instruction(INS ins, VOID *v) {
	if (INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
	INS_InsertCall(
		ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
		IARG_ADDRINT, INS_Address(ins),
		IARG_PTR, new string(INS_Disassemble(ins)),
		IARG_MEMORYOP_EA, 0,
		IARG_END);
	}
	else if (INS_MemoryOperandIsWritten(ins, 0)){
	INS_InsertCall(
		ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
		IARG_ADDRINT, INS_Address(ins),
		IARG_PTR, new string(INS_Disassemble(ins)),
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

std::list<UINT64> addressTainted; // might need to add ID to this 
std::list<REG> regsTainted; // might need to add ID to this 

VOID spreadRegTaint(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w)
{
  if (opCount != 2)
    return;

  if (REG_valid(reg_w)){
    if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) 
        || !checkAlreadyRegTainted(reg_r))){
      std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
      std::cout << "\t\t\toutput: "<< REG_StringShort(reg_w) << " | input: " 
        << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
      removeRegTainted(reg_w);
    }
    else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
      std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
      std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: " 
        << REG_StringShort(reg_r) << std::endl;
      taintReg(reg_w);
    }
  }
}

// Probably don't need to taint smaller sized registers because we are all tracking pointers ...
// As you can see above, when the program loads a value from the tainted area, we check if this memory location is tainted. If it is true, we taint the destination register. Otherwise, the memory is not tainted, so we check if the destination register is tainted. If not, we remove the register because we can't control the memory location.
VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
  list<UINT64>::iterator i;
  UINT64 addr = memOp;

  if (opCount != 2)
    return;

  for(i = addressTainted.begin(); i != addressTainted.end(); i++){
      if (addr == *i){
        std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " 
          << insDis << std::endl;
        taintReg(reg_r);
        return ;
      }
  }
  /* if mem != tained and reg == taint => free the reg */
  if (checkAlreadyRegTainted(reg_r)){
    std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " 
      << insDis << std::endl;
    removeRegTainted(reg_r);
  }
}

// For the STORE instruction is the same thing. If the destination location is tainted, we check if the register is tainted. If it is false, we need to free the location memory. Otherwise if the register is tainted, we taint the memory destination.
VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
  list<UINT64>::iterator i;
  UINT64 addr = memOp;

  if (opCount != 2)
    return;

  for(i = addressTainted.begin(); i != addressTainted.end(); i++){
      if (addr == *i){
        std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr 
          << ": " << insDis << std::endl;
        if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
          removeMemTainted(addr);
        return ;
      }
  }
  if (checkAlreadyRegTainted(reg_r)){
    std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr 
      << ": " << insDis << std::endl;
    addMemTainted(addr);
  }
}



int main(int argc, char *argv[])
{
    /* Init Pin arguments */
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    /* Add the syscall handler */
    //PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    INS_AddInstrumentFunction(Instruction, 0);
	
    /* Start the program */
    PIN_StartProgram();

    return 0;
}
