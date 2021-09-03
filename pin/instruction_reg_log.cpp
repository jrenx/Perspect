#include <pin.H>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <sstream>
#include <string>
//#include <boost/iostreams/filtering_stream.hpp>
//#include <boost/iostreams/filtering_streambuf.hpp>
//#include <boost/iostreams/copy.hpp>
//#include <boost/iostreams/filter/gzip.hpp>

using std::hex;
using std::cerr;
using std::string;
using std::ios;
using std::endl;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;
//boost::iostreams::filtering_ostream out;
std::vector<unsigned long> addresses;
std::vector<string> registers;
std::map<unsigned long, std::vector<string> > addr_to_regs;
std::map<string, REG> reg_map;
std::map<unsigned long, unsigned long> no_reg_list;
std::map<unsigned long, u_int16_t> insn_to_code;
char delim = ':';
long curr_count = 0;
long file_count = 0;

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
    //TraceFile << "start" << endl;
    //out << "start" << endl;

}

/* ===================================================================== */

VOID record_reg(ADDRINT pc, ADDRINT reg)
{
    //TraceFile.write((char*)&delim, sizeof(char));
    short code = insn_to_code[pc];
    if (no_reg_list.find(pc) == no_reg_list.end()) {
      TraceFile.write((char*)&reg, sizeof(ADDRINT));

      //std::cout << sizeof(u_int16_t) << endl;
      //std::cout << sizeof(short) << endl;
      //TraceFile.write((char*)&code, sizeof(short));
      //curr_count += 2;
      //TraceFile << pc << ":" << reg << "\n";
    } /*else {
      //TraceFile << pc << ":" << "\n";
      TraceFile.write((char*)&code, sizeof(short));
      //curr_count += 1;
    }*/
    TraceFile.write((char*)&code, sizeof(u_int16_t));
    //out << pc << ": " << reg << endl;
    /*
    if (curr_count < 0) {
      curr_count = 0;
      TraceFile.close();
      std::stringstream s("tar -zcvf log");
      s << file_count;
      file_count += 1;
      s << ".tar.gz ";
      s << KnobOutputFile.Value();
      std::string cmd = s.str();
      std::cout << "__" << cmd << "__" << endl;
      system(cmd.c_str());

      std::stringstream s1("rm ");
      s1 << KnobOutputFile.Value();
      std::string cmd1 = s1.str();
      std::cout << "__" << cmd1 << "__" << endl;
      system(cmd1.c_str());

      TraceFile.open(KnobOutputFile.Value().c_str());
      TraceFile.setf(ios::out | ios::binary);
    }*/
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
                /*
                int index = get_ins_index(INS_Address(ins));
                if (index != -1)
                {
                    string reg = registers[index];
                    if (reg == "pc") {
                        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_reg), IARG_INST_PTR, IARG_INST_PTR, IARG_END);
                    } else {
                        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_reg), IARG_INST_PTR, IARG_REG_VALUE, reg_map[reg], IARG_END);
                    }
                }*/
                unsigned long addr = (unsigned long)INS_Address(ins);
                std::vector<string> regs = addr_to_regs[addr];
                for (std::vector<string>::iterator it = regs.begin(); it != regs.end(); it++) {
                  string reg = *it;
                  if (reg == "pc") {
                    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(record_reg), IARG_INST_PTR, IARG_INST_PTR, IARG_END);
                    no_reg_list[addr] = addr;
                  } else {
		    //std::cout << reg << endl;
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
    //TraceFile << "# eof" << endl;
    //out << "# eof" << endl;
    TraceFile.close();
    //out.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int main (INT32 argc, CHAR *argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return 0;

    std::ifstream infile("instruction_reg_log_arg"); // TODO change the file name
    std::string line;
    std::vector<string> addrs;
    std::vector<string> regs;
    std::vector<string> counts;
    std::string addr_flag = "-i";
    std::string reg_flag = "-r";
    std::string count_flag = "-c";
    bool expecting_addr = false;
    bool expecting_reg = false;
    bool expecting_count = false;
    while (std::getline(infile, line))
    {
      if (line == addr_flag) {
        expecting_addr = true;
        expecting_reg = false;
        expecting_count = false;
        continue;
      }
      if (line == reg_flag) {
        expecting_reg = true;
        expecting_addr = false;
        expecting_count = false;
        continue;
      }
      if (line == count_flag) {
        expecting_count = true;
        expecting_addr = false;
        expecting_reg = false;
        continue;
      }

      assert(!expecting_addr || !expecting_reg || !expecting_count); //TODO better assert?

      if (expecting_addr) {
        addrs.push_back(line);
      } else if (expecting_reg) {
        regs.push_back(line);
      } else if (expecting_count) {
        counts.push_back(line);
      }
    }

    std::vector<std::pair<unsigned long, string> > inputs;
    //Initialize global variables

    for (u_int i = 0; i < addrs.size(); ++i) {
        unsigned long addr;
        std::istringstream iss(addrs[i]);
        iss >> std::hex >> addr;
        addresses.push_back(addr);
        std::pair<unsigned long, string> pair;
        pair.first = addr;
        inputs.push_back(pair);

        int count;
        std::istringstream iss2(counts[i]);
        iss2 >> count;
        u_int16_t short_count = (u_int16_t)count;
        insn_to_code[addr] = short_count;

        std::cout << "TEST insn " << addr << " " << short_count << endl;
    }

  for (u_int i = 0; i < regs.size(); ++i) {
        string reg = regs[i];
        registers.push_back(reg);
        inputs[i].second = reg;
        std::cout << "TEST reg " << reg << endl;
    }

    for (std::vector<std::pair<unsigned long, string> >::iterator it = inputs.begin(); it != inputs.end(); it++) {
        unsigned long addr = (*it).first;
        addr_to_regs[addr].push_back((*it).second);
    }

    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile.setf(ios::out | ios::binary);

    //TraceFile << hex;
    //TraceFile.setf(ios::showbase);
    //out.push(boost::iostreams::gzip_compressor());
    //out.push(TraceFile);

    // Initialize reg_map
    reg_map["rax"] = REG_RAX;
    reg_map["eax"] = REG_EAX;
    reg_map["rbp"] = REG_RBP;
    reg_map["ebp"] = REG_EBP;
    reg_map["rsp"] = REG_RSP;
    reg_map["esp"] = REG_ESP;
    reg_map["rdx"] = REG_RDX;
    reg_map["edx"] = REG_EDX;
    reg_map["rbx"] = REG_RBX;
    reg_map["ebx"] = REG_EBX;
    reg_map["rsi"] = REG_RSI;
    reg_map["esi"] = REG_ESI;
    reg_map["rdi"] = REG_RDI;
    reg_map["edi"] = REG_EDI;
    reg_map["rcx"] = REG_RCX;
    reg_map["ecx"] = REG_ECX;
    reg_map["cl"] = REG_CL;
    //https://www.eecg.utoronto.ca/~amza/www.mindsec.com/files/x86regs.html
    //DS:ESI EDI SI
    //ES:EDI EDI DI
    reg_map["es"] = REG_ESI;
    //reg_map["ds"] = REG_DS;
    //reg_map["es"] = REG_DI;
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

