#include "util.hpp"

#include <vector>
#include <boost/unordered_set.hpp>
#include <boost/unordered_map.hpp>
#include <boost/algorithm/string.hpp>

#include "Instruction.h"
#include "InstructionDecoder.h"
#include "CodeObject.h"
#include "CFG.h"
#include "Graph.h"
#include "slicing.h"

namespace boost {
  class StackStore {
  private:
    MachRegister machReg_;
    long offset_;
    long stackheight_;
  public:
    bool isSpecial; // TODO, a bit ugly
    std::size_t hash;
    std::string str;

    StackStore(MachRegister machReg, long offset, long stackheight) :
        machReg_(machReg), offset_(offset), stackheight_(stackheight) {
      isSpecial = false;
      std::stringstream hash_ss;
      hash_ss << machReg_.name() << " + " << (offset_ + stackheight_);
      std::string hash_str = hash_ss.str();

      hash = std::hash<std::string>{}(hash_str);

      std::stringstream retVal;
      retVal << machReg_.name() << " + " << std::hex << offset_ << " @ " << std::dec << stackheight_;
      str = retVal.str();
    }

    bool operator==(const StackStore &rhs) const {
      return machReg_ == rhs.machReg_ &&
             (offset_ + stackheight_) == (rhs.offset_ + rhs.stackheight_);
    }

    bool operator!=(const StackStore &rhs) const {
      return !(*this == rhs);
    }

    std::string format() const {
      return str;
    }

    friend std::ostream& operator<<(std::ostream& stream, const StackStore& s)
    {
      stream << s.format() << std::endl;
      return stream;
    }
  };

  std::size_t hash_value(const StackStore &ss) {
    // Compute individual hash values for first,
    // second and third and combine them using XOR
    // and bit shifting:

    return ss.hash;
  }
}

extern boost::unordered_map<Address, boost::unordered_map<Address, Function *>> *stackCache;

boost::unordered_map<Address, Function *> checkAndGetStackWrites(Function *f, Instruction readInsn, Address readAddr,
                                                                 MachRegister readReg, long readOff, int initHeight, int level=0);
boost::unordered_map<Address, Function *> checkAndGetStackWritesHelper(bool *resultIntractable, Function *f,
                                                                       std::vector<Block *> &list,
                                                                       boost::unordered_map<Address, long> &insnToStackHeight,
                                                                       boost::unordered_set<Address> &readAddrs,
                                                                       StackStore &stackRead, int level);
void get_indirect_write_to_stack(Instruction insn, Address addr, Block *b, Function *f,
                                 int stackHeight, StackStore &stackRead,
                                 boost::unordered_map<Address, StackStore> &indirectWrites);
bool readsFromStack(Instruction insn, Address addr, MachRegister *reg, long *off);
bool writesToStack(Operand op, Instruction insn, Address addr);
void getStackHeights(Function *f, std::vector<Block *> &list, boost::unordered_map<Address, long> &insnToStackHeight, int initHeight);

void printReachableStores(boost::unordered_map<StackStore, boost::unordered_map<Address, Function *>> &reachableStores);

void getAllRets(Function *f, boost::unordered_set<Address> &rets);
void getAllRets(Function *f, boost::unordered_set<std::pair<Address, Block *>> &rets);
void getAllInvokes(Function *f, Function *callee, boost::unordered_set<Address> &rets);
Function *getFunction(std::vector<Function *> &funcs);