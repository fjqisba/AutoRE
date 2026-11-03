#include "local_validation.h"
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/ValueTracking.h>

#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/ValueSymbolTable.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <remill/Arch/Arch.h>

#include <cstring>
#include <array>
#include <memory>
#include <random>
#include <vector>

namespace {
struct Memory {
  std::vector<uint8_t> bytes;
  bool out_of_range = false;
  uint64_t exit_pc = 0;
};

template <typename T> T Read(Memory *memory, uint64_t address) {
  T value = 0;
  if (address > memory->bytes.size() || sizeof(T) > memory->bytes.size() - address) {
    memory->out_of_range = true; return 0;
  }
  std::memcpy(&value, memory->bytes.data() + address, sizeof(T));
  return value;
}
template <typename T> Memory *Write(Memory *memory, uint64_t address, T value) {
  if (address > memory->bytes.size() || sizeof(T) > memory->bytes.size() - address) {
    memory->out_of_range = true; return memory;
  }
  std::memcpy(memory->bytes.data() + address, &value, sizeof(T));
  return memory;
}
bool Identity(bool result, ...) { return result; }
Memory *Exit(void *, uint64_t pc, Memory *memory) { memory->exit_pc = pc; return memory; }

using Entry = Memory *(*)(void *, uint64_t, Memory *);
struct Program {
  // Context 的生命周期必须长于其 Module/JIT。
  llvm::LLVMContext context;
  std::unique_ptr<llvm::ExecutionEngine> engine;
  Entry entry = nullptr;
  uint64_t state_size = 0;
  uint64_t rsp_offset = UINT64_MAX;
  uint64_t flags_offset = 0;
};

std::unique_ptr<Program> Compile(llvm::StringRef path, llvm::StringRef name, std::string &error) {
  auto program = std::make_unique<Program>();
  llvm::SMDiagnostic diagnostic;
  auto module = llvm::parseIRFile(path, diagnostic, program->context);
  if (!module) { error = "cannot read validation module"; return nullptr; }
  auto *state = llvm::StructType::getTypeByName(program->context, "struct.State");
  auto *x86 = llvm::StructType::getTypeByName(program->context, "struct.X86State");
  if (!state || !x86 || !module->getFunction(name)) { error = "missing State/entry"; return nullptr; }
  program->state_size = module->getDataLayout().getTypeAllocSize(state);
  program->flags_offset = module->getDataLayout().getStructLayout(x86)->getElementOffset(2);
  auto *rsp = module->getFunction(name)->getValueSymbolTable()->lookup("RSP");
  int64_t rsp_offset = 0;
  if (rsp) {
    if (llvm::GetPointerBaseWithConstantOffset(rsp, rsp_offset, module->getDataLayout()) != module->getFunction(name)->getArg(0)) {
      error = "RSP layout mapping unavailable"; return nullptr;
    }
    program->rsp_offset = uint64_t(rsp_offset);
  } else if (auto *layout = module->getFunction(name)->getMetadata("nereus.rsp.layout")) {
    if (layout->getNumOperands() != 1) { error = "invalid RSP layout metadata"; return nullptr; }
    auto *constant = llvm::mdconst::dyn_extract<llvm::ConstantInt>(layout->getOperand(0));
    if (!constant || constant->getZExtValue() + 8 > program->state_size) { error = "invalid RSP offset"; return nullptr; }
    program->rsp_offset = constant->getZExtValue();
  }
  // 只执行受控 State/guest-memory 回调，不加载和执行目标 DLL。
  std::vector<std::pair<std::string, void *>> callbacks = {
      {"__remill_read_memory_8", reinterpret_cast<void *>(&Read<uint8_t>)},
      {"__remill_read_memory_16", reinterpret_cast<void *>(&Read<uint16_t>)},
      {"__remill_read_memory_32", reinterpret_cast<void *>(&Read<uint32_t>)},
      {"__remill_read_memory_64", reinterpret_cast<void *>(&Read<uint64_t>)},
      {"__remill_write_memory_8", reinterpret_cast<void *>(&Write<uint8_t>)},
      {"__remill_write_memory_16", reinterpret_cast<void *>(&Write<uint16_t>)},
      {"__remill_write_memory_32", reinterpret_cast<void *>(&Write<uint32_t>)},
      {"__remill_write_memory_64", reinterpret_cast<void *>(&Write<uint64_t>)},
      {"__remill_flag_computation_zero", reinterpret_cast<void *>(&Identity)},
      {"__remill_flag_computation_sign", reinterpret_cast<void *>(&Identity)},
      {"__remill_flag_computation_carry", reinterpret_cast<void *>(&Identity)},
      {"__remill_flag_computation_overflow", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_eq", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_neq", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_sle", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_slt", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_sge", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_sgt", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_ule", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_ult", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_uge", reinterpret_cast<void *>(&Identity)},
      {"__remill_compare_ugt", reinterpret_cast<void *>(&Identity)},
      {"__remill_jump", reinterpret_cast<void *>(&Exit)},
      {"__remill_function_call", reinterpret_cast<void *>(&Exit)},
      {"__remill_function_return", reinterpret_cast<void *>(&Exit)}};
  // 不解析任意外部符号：未知环境/系统 helper 直接拒绝差分执行。
  for (auto &function : *module) {
    if (!function.isDeclaration() || function.isIntrinsic() || function.use_empty()) continue;
    bool known = false;
    for (auto &callback : callbacks) known |= function.getName() == callback.first;
    if (!known) { error = "unsupported validation helper: " + function.getName().str(); return nullptr; }
  }
  module->setTargetTriple(llvm::sys::getDefaultTargetTriple());
  llvm::EngineBuilder builder(std::move(module));
  builder.setEngineKind(llvm::EngineKind::JIT).setErrorStr(&error);
  builder.setMCJITMemoryManager(std::make_unique<llvm::SectionMemoryManager>());
  program->engine.reset(builder.create());
  if (!program->engine) return nullptr;
  for (auto &callback : callbacks)
    program->engine->addGlobalMapping(callback.first, reinterpret_cast<uint64_t>(callback.second));
  program->engine->finalizeObject();
  program->entry = reinterpret_cast<Entry>(program->engine->getFunctionAddress(name.str()));
  if (!program->entry) { error = "entry JIT address missing"; return nullptr; }
  return program;
}
}  // namespace

llvm::json::Object ValidateLocalBlock(const llvm::json::Object &request) {
  auto raw = request.getString("reference_bitcode");
  auto optimized = request.getString("optimized_bitcode");
  auto name = request.getString("function_name");
  const auto cases = request.getInteger("cases").value_or(256);
  auto error = [](llvm::StringRef reason) { return llvm::json::Object{
      {"protocol_version", 1}, {"ok", false}, {"code", "VALIDATION_FAILED"}, {"message", reason}}; };
  if (!raw || !optimized || !name || cases < 1 || cases > 4096) return error("invalid validation request");
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetAsmPrinter();
  std::string message;
  auto reference = Compile(*raw, *name, message);
  if (!reference) return error(message);
  auto candidate = Compile(*optimized, *name, message);
  if (!candidate) return error(message);
  if (reference->state_size != candidate->state_size) return error("State layout mismatch");
  if (reference->state_size > 4096) return error("State exceeds validation storage");
  std::mt19937_64 random(0x4e6552455553);
  for (int64_t index = 0; index < cases; ++index) {
    // 16 字节对齐符合 Remill 对 State 的 load/store 对齐要求。
    alignas(16) std::array<uint8_t, 4096> left{};
    for (auto &byte : left) byte = static_cast<uint8_t>(random());
    auto *state_bytes = left.data();
    // 同时检查架构规范的 0/1 flags 和非规范高位字节，避免用常量化掩盖恢复错误。
    if (index % 2 == 0)
      for (unsigned offset : {1, 3, 5, 7, 9, 11, 13}) state_bytes[reference->flags_offset + offset] &= 1;
    uint64_t rsp = 0x10000 + (random() % 1024) * 8;
    if (reference->rsp_offset != UINT64_MAX) std::memcpy(state_bytes + reference->rsp_offset, &rsp, 8);
    alignas(16) auto right = left;
    Memory memory_left, memory_right;
    memory_left.bytes.resize(0x20000);
    for (auto &byte : memory_left.bytes) byte = static_cast<uint8_t>(random());
    memory_right = memory_left;
    reference->entry(left.data(), 0, &memory_left);
    candidate->entry(right.data(), 0, &memory_right);
    if (memory_left.out_of_range || memory_right.out_of_range) return error("guest address out of test range");
    if (left != right || memory_left.bytes != memory_right.bytes || memory_left.exit_pc != memory_right.exit_pc) {
      size_t state_difference = 0;
      auto *l = reinterpret_cast<uint8_t *>(left.data());
      auto *r = reinterpret_cast<uint8_t *>(right.data());
      while (state_difference < reference->state_size && l[state_difference] == r[state_difference]) ++state_difference;
      return llvm::json::Object{{"protocol_version", 1}, {"ok", false}, {"code", "VALIDATION_MISMATCH"},
          {"case", index}, {"first_state_difference", int64_t(state_difference)},
          {"memory_equal", memory_left.bytes == memory_right.bytes},
          {"reference_exit_pc", "0x" + llvm::utohexstr(memory_left.exit_pc)},
          {"optimized_exit_pc", "0x" + llvm::utohexstr(memory_right.exit_pc)}};
    }
  }
  return llvm::json::Object{{"protocol_version", 1}, {"ok", true}, {"cases", cases},
      {"seed", "0x4e6552455553"}, {"state_bytes_compared", int64_t(reference->state_size)},
      {"guest_memory_bytes_compared", 0x20000}, {"exit_pc_compared", true},
      {"reference", "unoptimized-local-Remill-IR"}, {"scope", "optimizer-differential-normal-completion"},
      {"original_DLL_executed", false}, {"full_equivalence_proved", false}};
}
