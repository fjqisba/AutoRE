#include "local_optimizer.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/ValueSymbolTable.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/ModRef.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>

#include <filesystem>
#include <optional>
#include <map>
#include <set>

namespace {
llvm::json::Object Error(llvm::StringRef code, llvm::StringRef message) {
  return llvm::json::Object{{"protocol_version", 1}, {"ok", false},
                           {"code", code}, {"message", message}};
}

bool IsIdentity(llvm::StringRef name) {
  return name == "__remill_flag_computation_zero" ||
         name == "__remill_flag_computation_sign" ||
         name == "__remill_flag_computation_carry" ||
         name == "__remill_flag_computation_overflow" ||
         name == "__remill_compare_eq" || name == "__remill_compare_neq" ||
         name == "__remill_compare_sle" || name == "__remill_compare_slt" ||
         name == "__remill_compare_sge" || name == "__remill_compare_sgt" ||
         name == "__remill_compare_ule" || name == "__remill_compare_ult" ||
         name == "__remill_compare_uge" || name == "__remill_compare_ugt";
}

unsigned MemoryWidth(llvm::StringRef name, bool write) {
  const auto prefix = write ? "__remill_write_memory_" : "__remill_read_memory_";
  if (!name.consume_front(prefix)) return 0;
  unsigned width = 0;
  if (name.getAsInteger(10, width)) return 0;
  return (width == 8 || width == 16 || width == 32 || width == 64) ? width : 0;
}

struct AffineAddress {
  llvm::Value *base;
  uint64_t offset;
};

AffineAddress Address(llvm::Value *value) {
  if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(value))
    return {nullptr, constant->getZExtValue()};
  if (auto *binary = llvm::dyn_cast<llvm::BinaryOperator>(value)) {
    if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(binary->getOperand(1))) {
      if (binary->getOpcode() == llvm::Instruction::Add ||
          binary->getOpcode() == llvm::Instruction::Sub) {
        auto inner = Address(binary->getOperand(0));
        const auto amount = constant->getZExtValue();
        inner.offset += binary->getOpcode() == llvm::Instruction::Add ? amount : -amount;
        return inner;
      }
    }
  }
  return {value, 0};
}

bool IsHarmless(llvm::CallBase *call) {
  const auto *callee = call->getCalledFunction();
  return callee && callee->isIntrinsic() && !call->mayWriteToMemory();
}

llvm::Value *Assemble(llvm::IRBuilder<> &builder, llvm::Type *type,
    llvm::ArrayRef<std::pair<llvm::Value *, unsigned>> bytes) {
  llvm::Value *result = llvm::ConstantInt::get(type, 0);
  for (unsigned index = 0; index < bytes.size();) {
    const unsigned begin = index++;
    while (index < bytes.size() && bytes[index].first == bytes[begin].first &&
           bytes[index].second == bytes[begin].second + (index - begin) * 8) ++index;
    auto *part = bytes[begin].first;
    if (bytes[begin].second) part = builder.CreateLShr(part, bytes[begin].second);
    part = builder.CreateTruncOrBitCast(part, builder.getIntNTy((index - begin) * 8));
    part = builder.CreateZExtOrBitCast(part, type);
    if (begin) part = builder.CreateShl(part, begin * 8);
    result = builder.CreateOr(result, part);
  }
  return result;
}

bool RunPipeline(llvm::Module &module, llvm::StringRef pipeline, std::string &error) {
  llvm::LoopAnalysisManager loops;
  llvm::FunctionAnalysisManager functions;
  llvm::CGSCCAnalysisManager sccs;
  llvm::ModuleAnalysisManager modules;
  llvm::PassBuilder builder;
  builder.registerModuleAnalyses(modules);
  builder.registerCGSCCAnalyses(sccs);
  builder.registerFunctionAnalyses(functions);
  builder.registerLoopAnalyses(loops);
  builder.crossRegisterProxies(loops, functions, sccs, modules);
  llvm::ModulePassManager manager;
  if (auto parse_error = builder.parsePassPipeline(manager, pipeline)) {
    error = llvm::toString(std::move(parse_error));
    return false;
  }
  manager.run(module, modules);
  llvm::raw_string_ostream diagnostics(error);
  return !llvm::verifyModule(module, &diagnostics);
}

// State 的不同宽度字段可能重叠（例如 flags 的 32 位写/64 位读）。
// 按实际 DataLayout 追踪字节，避免只靠同类型 LLVM load/store 转发遗漏这些关系。
unsigned ForwardState(llvm::Function &function) {
  if (function.empty()) return 0;
  auto *state = function.getArg(0);
  const auto &layout = function.getParent()->getDataLayout();
  unsigned changed = 0;
  for (auto &block : function) {
    std::map<int64_t, std::pair<llvm::Value *, unsigned>> values;
    llvm::SmallVector<llvm::Instruction *> original;
    for (auto &instruction : block) original.push_back(&instruction);
    for (auto *instruction : original) {
      auto *load = llvm::dyn_cast<llvm::LoadInst>(instruction);
      auto *store = llvm::dyn_cast<llvm::StoreInst>(instruction);
      if (!load && !store) {
        if (auto *call = llvm::dyn_cast<llvm::CallBase>(instruction)) {
          auto *callee = call->getCalledFunction();
          if (!callee || (!MemoryWidth(callee->getName(), false) &&
                          !MemoryWidth(callee->getName(), true) && !IsHarmless(call))) values.clear();
        } else if (instruction->mayWriteToMemory()) values.clear();
        continue;
      }
      auto *pointer = load ? load->getPointerOperand() : store->getPointerOperand();
      int64_t offset = 0;
      auto *base = llvm::GetPointerBaseWithConstantOffset(pointer, offset, layout);
      auto *type = load ? load->getType() : store->getValueOperand()->getType();
      if (base != state || !type->isIntegerTy() || type->getIntegerBitWidth() > 64 ||
          type->getIntegerBitWidth() % 8 || (load && !load->isSimple()) || (store && !store->isSimple())) {
        if (store) values.clear();
        continue;
      }
      const unsigned count = type->getIntegerBitWidth() / 8;
      if (store) {
        for (unsigned index = 0; index < count; ++index)
          values[offset + index] = {store->getValueOperand(), index * 8};
        continue;
      }
      unsigned known = 0;
      for (unsigned index = 0; index < count; ++index) known += values.count(offset + index);
      if (!known) {
        for (unsigned index = 0; index < count; ++index) values[offset + index] = {load, index * 8};
        continue;
      }
      llvm::IRBuilder<> builder(load);
      // 未覆盖字节仍从当前 State 读取；只复用已知字节，不假设高位为零。
      for (unsigned index = 0; index < count;) {
        if (values.count(offset + index)) { ++index; continue; }
        const unsigned begin = index;
        while (index < count && !values.count(offset + index)) ++index;
        auto *part_type = builder.getIntNTy((index - begin) * 8);
        auto *part_ptr = builder.CreateGEP(builder.getInt8Ty(), state, builder.getInt64(offset + begin));
        auto *part = builder.CreateAlignedLoad(part_type, part_ptr, llvm::Align(1), "state.unknown");
        for (unsigned position = begin; position < index; ++position)
          values[offset + position] = {part, (position - begin) * 8};
      }
      llvm::SmallVector<std::pair<llvm::Value *, unsigned>, 8> parts;
      for (unsigned index = 0; index < count; ++index) {
        parts.push_back(values[offset + index]);
      }
      auto *result = Assemble(builder, type, parts);
      load->replaceAllUsesWith(result);
      load->eraseFromParent();
      ++changed;
    }
  }
  return changed;
}

// 从当前 memory token 向前查找覆盖每个读取字节的最近写入。
// 不跨未知 call、不同地址基底或控制流块，部分重叠写按小端字节拼接。
unsigned ForwardReads(llvm::Function &function) {
  llvm::SmallVector<llvm::CallInst *> reads;
  for (auto &instruction : llvm::instructions(function)) {
    auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
    if (call && call->getCalledFunction() &&
        MemoryWidth(call->getCalledFunction()->getName(), false)) reads.push_back(call);
  }
  unsigned changed = 0;
  for (auto *read : reads) {
    const unsigned width = MemoryWidth(read->getCalledFunction()->getName(), false);
    if (read->arg_size() != 2 || !read->getType()->isIntegerTy(width) ||
        !read->getArgOperand(1)->getType()->isIntegerTy(64)) continue;
    const auto source = Address(read->getArgOperand(1));
    llvm::SmallVector<std::pair<llvm::Value *, unsigned>, 8> bytes(width / 8, {nullptr, 0});
    auto *token = read->getArgOperand(0);
    unsigned missing = width / 8;
    for (auto *previous = read->getPrevNode(); previous && missing; previous = previous->getPrevNode()) {
      auto *write = llvm::dyn_cast<llvm::CallInst>(previous);
      if (!write) {
        if (previous->mayWriteToMemory() && !llvm::isa<llvm::StoreInst>(previous)) break;
        continue;
      }
      auto *callee = write->getCalledFunction();
      const auto store_width = callee ? MemoryWidth(callee->getName(), true) : 0;
      if (!store_width) {
        if (!IsHarmless(write) && !(callee && MemoryWidth(callee->getName(), false))) break;
        continue;
      }
      if (write != token || write->arg_size() != 3 ||
          !write->getArgOperand(1)->getType()->isIntegerTy(64) ||
          !write->getArgOperand(2)->getType()->isIntegerTy(store_width)) break;
      const auto destination = Address(write->getArgOperand(1));
      if (source.base != destination.base) break; // 无法证明不别名时停止。
      for (unsigned index = 0; index < width / 8; ++index) {
        const auto distance = source.offset + index - destination.offset;
        if (!bytes[index].first && distance < store_width / 8) {
          bytes[index] = {write->getArgOperand(2), unsigned(distance * 8)};
          --missing;
        }
      }
      token = write->getArgOperand(0);
    }
    if (missing) continue;
    llvm::IRBuilder<> builder(read);
    auto *value = Assemble(builder, read->getType(), bytes);
    read->replaceAllUsesWith(value);
    read->eraseFromParent();
    ++changed;
  }
  return changed;
}

// 仅删除在同一条直线路径上、无中间观察且被完整覆盖的 guest 写入。
unsigned RemoveOverwrittenStores(llvm::Function &function) {
  unsigned removed = 0;
  for (auto &block : function) {
    for (auto iterator = block.begin(); iterator != block.end();) {
      auto *write = llvm::dyn_cast<llvm::CallInst>(&*iterator++);
      if (!write || !write->getCalledFunction()) continue;
      const auto width = MemoryWidth(write->getCalledFunction()->getName(), true);
      if (!width || write->arg_size() != 3 || !write->hasOneUse() ||
          !write->getArgOperand(1)->getType()->isIntegerTy(64)) continue;
      const auto destination = Address(write->getArgOperand(1));
      auto *token = static_cast<llvm::Value *>(write);
      bool overwritten = false;
      for (auto *next = write->getNextNode(); next; next = next->getNextNode()) {
        auto *call = llvm::dyn_cast<llvm::CallInst>(next);
        if (!call) continue;
        auto *callee = call->getCalledFunction();
        const auto next_width = callee ? MemoryWidth(callee->getName(), true) : 0;
        if (!next_width) { if (!IsHarmless(call)) break; continue; }
        if (call->getArgOperand(0) != token || !call->getArgOperand(1)->getType()->isIntegerTy(64)) break;
        const auto address = Address(call->getArgOperand(1));
        if (destination.base != address.base) break;
        const uint64_t offset = destination.offset - address.offset;
        if (offset < next_width / 8 && offset + width / 8 <= next_width / 8) {
          overwritten = true;
          break;
        }
        if (!call->hasOneUse()) break;
        token = call;
      }
      if (overwritten) {
        write->replaceAllUsesWith(write->getArgOperand(0));
        write->eraseFromParent();
        ++removed;
      }
    }
  }
  return removed;
}

unsigned Count(llvm::Function &function) {
  unsigned count = 0;
  for (auto &instruction : llvm::instructions(function)) { (void) instruction; ++count; }
  return count;
}

struct FlagRegion { int64_t begin; int64_t end; };

std::optional<FlagRegion> FindFlagRegion(llvm::Module &module) {
  auto *x86 = llvm::StructType::getTypeByName(module.getContext(), "struct.X86State");
  if (!x86 || x86->getNumElements() < 4) return {};
  const auto *layout = module.getDataLayout().getStructLayout(x86);
  return FlagRegion{int64_t(layout->getElementOffset(2)),
                    int64_t(layout->getElementOffset(3) + module.getDataLayout().getTypeAllocSize(x86->getElementType(3)))};
}

bool FlagPointer(llvm::Value *pointer, llvm::Value *state, const llvm::DataLayout &layout,
                 FlagRegion region, unsigned width) {
  int64_t offset = 0;
  return llvm::GetPointerBaseWithConstantOffset(pointer, offset, layout) == state &&
         offset >= region.begin && offset + int64_t(width) <= region.end;
}

// 为可读性抽出真实的 flags 计算 DAG；helper 有完整函数体，不是凭空命名的语义伪代码。
bool FlagSlice(llvm::Value *value, llvm::Value *state, FlagRegion region,
               const llvm::DataLayout &layout, llvm::Value *stop,
               std::set<llvm::Instruction *> &nodes) {
  if (value == state || value == stop || llvm::isa<llvm::Constant>(value)) return true;
  auto *instruction = llvm::dyn_cast<llvm::Instruction>(value);
  if (!instruction) return false;
  if (nodes.count(instruction)) return true;
  if (auto *load = llvm::dyn_cast<llvm::LoadInst>(instruction)) {
    if (!load->isSimple() || !load->getType()->isIntegerTy() ||
        !FlagPointer(load->getPointerOperand(), state, layout, region,
                     layout.getTypeStoreSize(load->getType()))) return false;
  } else if (!llvm::isa<llvm::GetElementPtrInst>(instruction) &&
             !llvm::isa<llvm::BinaryOperator>(instruction) &&
             !llvm::isa<llvm::CastInst>(instruction)) return false;
  for (auto &operand : instruction->operands())
    if (!FlagSlice(operand.get(), state, region, layout, stop, nodes)) return false;
  nodes.insert(instruction);
  return true;
}

llvm::Value *CloneSlice(llvm::Value *value, llvm::BasicBlock *block,
                        std::map<llvm::Value *, llvm::Value *> &mapping) {
  if (mapping.count(value)) return mapping[value];
  if (llvm::isa<llvm::Constant>(value)) return value;
  auto *instruction = llvm::cast<llvm::Instruction>(value);
  auto *clone = instruction->clone();
  for (unsigned index = 0; index < clone->getNumOperands(); ++index)
    clone->setOperand(index, CloneSlice(instruction->getOperand(index), block, mapping));
  clone->insertInto(block, block->end());
  if (instruction->hasName()) clone->setName(instruction->getName());
  mapping[value] = clone;
  return clone;
}

unsigned OutlineFlags(llvm::Function &entry) {
  // 边界摘要只为直线单块生成，不跨 CFG 合流重排快照。
  if (entry.size() != 1) return 0;
  auto &module = *entry.getParent();
  auto region = FindFlagRegion(module);
  if (!region) return 0;
  auto *state = entry.getArg(0);
  const auto &layout = module.getDataLayout();
  llvm::Value *snapshot = nullptr;
  llvm::Instruction *snapshot_position = nullptr;
  for (auto &instruction : llvm::instructions(entry)) {
    auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
    if (!call || !call->getCalledFunction() || MemoryWidth(call->getCalledFunction()->getName(), true) != 64) continue;
    std::set<llvm::Instruction *> nodes;
    auto *value = call->getArgOperand(2);
    if (FlagSlice(value, state, *region, layout, nullptr, nodes) && nodes.size() >= 12) {
      snapshot = value;
      snapshot_position = call;
      break;
    }
  }
  if (!snapshot) return 0;
  // 不将已经改变的 flags 重读为入口快照。任何先前 flags 写入都会阻止 outlining。
  for (auto &instruction : entry.getEntryBlock()) {
    if (&instruction == snapshot_position) break;
    if (auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction)) {
      auto *callee = call->getCalledFunction();
      if (!IsHarmless(call) && (!callee || (!MemoryWidth(callee->getName(), true) && !MemoryWidth(callee->getName(), false)))) return 0;
    }
    if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
      if (FlagPointer(store->getPointerOperand(), state, layout, *region, layout.getTypeStoreSize(store->getValueOperand()->getType()))) return 0;
    }
  }
  auto *pack_type = llvm::FunctionType::get(snapshot->getType(), {state->getType()}, false);
  auto *pack = llvm::Function::Create(pack_type, llvm::GlobalValue::InternalLinkage, "nereus.x86.pack_flags", module);
  pack->addFnAttr(llvm::Attribute::NoInline);
  pack->addFnAttr(llvm::Attribute::NoUnwind);
  pack->setMemoryEffects(llvm::MemoryEffects::argMemOnly(llvm::ModRefInfo::Ref));
  pack->getArg(0)->setName("state");
  auto *pack_block = llvm::BasicBlock::Create(module.getContext(), "entry", pack);
  std::map<llvm::Value *, llvm::Value *> mapping{{state, pack->getArg(0)}};
  auto *packed = CloneSlice(snapshot, pack_block, mapping);
  llvm::IRBuilder<>(pack_block).CreateRet(packed);
  auto *snapshot_call = llvm::IRBuilder<>(snapshot_position).CreateCall(pack, {state}, "flags.snapshot");
  snapshot->replaceAllUsesWith(snapshot_call);

  llvm::SmallVector<llvm::StoreInst *> stores;
  for (auto &instruction : llvm::instructions(entry)) {
    if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
      if (FlagPointer(store->getPointerOperand(), state, layout, *region, layout.getTypeStoreSize(store->getValueOperand()->getType()))) stores.push_back(store);
    }
  }
  if (stores.empty()) return 1;
  // commit 区域内不允许混入 guest 访存、未知调用或其他 State 写入。
  std::set<llvm::Instruction *> allowed(stores.begin(), stores.end());
  for (llvm::Instruction *instruction = stores.front(); instruction; instruction = instruction->getNextNode()) {
    if (instruction->mayHaveSideEffects() && !allowed.count(instruction)) return 1;
    if (instruction == stores.back()) break;
  }
  for (auto *store : stores) {
    std::set<llvm::Instruction *> nodes;
    if (!FlagSlice(store->getValueOperand(), state, *region, layout, snapshot_call, nodes) ||
        !FlagSlice(store->getPointerOperand(), state, *region, layout, snapshot_call, nodes)) return 1;
  }
  auto *commit_type = llvm::FunctionType::get(llvm::Type::getVoidTy(module.getContext()), {state->getType(), snapshot_call->getType()}, false);
  auto *commit = llvm::Function::Create(commit_type, llvm::GlobalValue::InternalLinkage, "nereus.x86.commit_flags", module);
  commit->addFnAttr(llvm::Attribute::NoInline);
  commit->addFnAttr(llvm::Attribute::NoUnwind);
  commit->setMemoryEffects(llvm::MemoryEffects::argMemOnly());
  commit->getArg(0)->setName("state"); commit->getArg(1)->setName("flags.snapshot");
  auto *commit_block = llvm::BasicBlock::Create(module.getContext(), "entry", commit);
  mapping = {{state, commit->getArg(0)}, {snapshot_call, commit->getArg(1)}};
  llvm::SmallVector<std::pair<llvm::Value *, llvm::Value *>> outputs;
  for (auto *store : stores) outputs.push_back({CloneSlice(store->getValueOperand(), commit_block, mapping), CloneSlice(store->getPointerOperand(), commit_block, mapping)});
  llvm::IRBuilder<> builder(commit_block);
  for (unsigned index = 0; index < stores.size(); ++index) {
    auto *store = builder.CreateStore(outputs[index].first, outputs[index].second);
    store->setAlignment(stores[index]->getAlign());
  }
  builder.CreateRetVoid();
  llvm::IRBuilder<>(stores.front()).CreateCall(commit, {state, snapshot_call});
  for (auto *store : stores) store->eraseFromParent();
  return 2;
}

void NameBoundaryValues(llvm::Function &entry) {
  llvm::Value *stack_input = nullptr, *context_base = nullptr;
  for (auto &instruction : llvm::instructions(entry)) {
    if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
      auto *pointer = load->getPointerOperand();
      if (pointer->hasName() && pointer->getName().starts_with("R")) {
        load->setName(pointer->getName().lower() + ".in");
        if (pointer->getName() == "RSP") stack_input = load;
      }
    }
    if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction))
      if (store->getPointerOperand()->getName() == "RBP") context_base = store->getValueOperand();
  }
  if (!context_base || !stack_input) return;
  auto anchor = Address(context_base);
  if (anchor.base != stack_input) return;
  context_base->setName("context.base");
  unsigned memory_index = 0;
  std::map<int64_t, llvm::Value *> addresses{{0, context_base}};
  for (auto &instruction : llvm::instructions(entry)) {
    auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
    if (!call || !call->getCalledFunction() || !MemoryWidth(call->getCalledFunction()->getName(), true)) continue;
    const auto destination = Address(call->getArgOperand(1));
    if (destination.base != stack_input) continue;
    const int64_t displacement = int64_t(destination.offset - anchor.offset);
    llvm::IRBuilder<> builder(call);
    llvm::Value *address = context_base;
    if (addresses.count(displacement)) address = addresses[displacement];
    else {
      address = builder.CreateAdd(context_base, builder.getInt64(displacement),
          displacement > 0 ? "context.slot_" + llvm::utohexstr(uint64_t(displacement), true)
                           : "stack.scratch_m" + llvm::utohexstr(uint64_t(-displacement), true));
      addresses[displacement] = address;
    }
    call->setArgOperand(1, address);
    call->setName("memory." + std::to_string(++memory_index));
  }
  for (auto &instruction : llvm::instructions(entry)) {
    auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction);
    if (!store || store->getPointerOperand()->getName() != "RSP") continue;
    const auto value = Address(store->getValueOperand());
    const auto displacement = int64_t(value.offset - anchor.offset);
    if (value.base == stack_input && addresses.count(displacement)) store->setOperand(0, addresses[displacement]);
  }
}
}  // namespace

llvm::json::Object OptimizeLocalBlock(const llvm::json::Object &request) {
  const auto input = request.getString("input_bitcode");
  const auto directory = request.getString("output_dir");
  const auto name = request.getString("function_name");
  if (!input || !directory || !name) return Error("INVALID_REQUEST", "input_bitcode/output_dir/function_name required");
  llvm::LLVMContext context;
  llvm::SMDiagnostic diagnostic;
  auto module = llvm::parseIRFile(*input, diagnostic, context);
  if (!module) return Error("IR_INVALID", "cannot parse local bitcode");
  auto *function = module->getFunction(*name);
  if (!function || function->isDeclaration()) return Error("IR_INVALID", "entry function missing");
  function->setMetadata("nereus.observation", llvm::MDNode::get(context, {
      llvm::MDString::get(context, "normal-completion-state-and-guest-memory"),
      llvm::MDString::get(context, "guest-memory-is-disjoint-from-remill-State"),
      llvm::MDString::get(context, "ordinary-single-thread-memory"),
      llvm::MDString::get(context, "memory-accesses-complete-without-fault"),
      llvm::MDString::get(context, "no-intermediate-State-observer")}));
  const auto before = Count(*function);
  unsigned identities = 0;
  llvm::SmallVector<llvm::CallInst *> to_remove;
  for (auto &instruction : llvm::instructions(function)) {
    auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
    if (!call || !call->getCalledFunction()) continue;
    const auto helper = call->getCalledFunction()->getName();
    if (IsIdentity(helper) && call->arg_size() && call->getType() == call->getArgOperand(0)->getType()) {
      call->replaceAllUsesWith(call->getArgOperand(0));
      to_remove.push_back(call);
      ++identities;
    }
    if (MemoryWidth(helper, false) || MemoryWidth(helper, true)) {
      // 此分析副本采用 guest memory 与 State 分离的正常完成语义。
      // 仍将 guest 读写视为有顺序的副作用，不将写 helper 标为 readnone。
      const auto effects = llvm::MemoryEffects::inaccessibleMemOnly();
      call->setMemoryEffects(effects);
      call->getCalledFunction()->setMemoryEffects(effects);
    }
  }
  for (auto *call : to_remove) call->eraseFromParent();
  std::string error;
  const auto pipeline = "function(early-cse<memssa>,instcombine,gvn,dse,adce,simplifycfg),globaldce";
  if (!RunPipeline(*module, pipeline, error)) return Error("IR_INVALID", error);
  unsigned forwarded = 0, state_reads = 0, dead_writes = 0, iterations = 0;
  for (; iterations < 8; ++iterations) {
    const auto state_changes = ForwardState(*function);
    if (!RunPipeline(*module, pipeline, error)) return Error("IR_INVALID", error);
    const auto reads = ForwardReads(*function);
    const auto writes = RemoveOverwrittenStores(*function);
    forwarded += reads; dead_writes += writes;
    state_reads += state_changes;
    if (!RunPipeline(*module, pipeline, error)) return Error("IR_INVALID", error);
    if (!reads && !writes && !state_changes) break;
  }
  const auto optimized_before_outline = Count(*function);
  const auto outlined_helpers = OutlineFlags(*function);
  if (!RunPipeline(*module, "function(dce),globaldce", error)) return Error("IR_INVALID", error);
  NameBoundaryValues(*function);
  if (!RunPipeline(*module, "function(dce),globaldce", error)) return Error("IR_INVALID", error);
  unsigned total_instructions = 0;
  for (auto &defined : *module) if (!defined.isDeclaration()) total_instructions += Count(defined);
  const auto output = std::filesystem::u8path(directory->str());
  std::error_code ec;
  const auto bc_path = output / "block.optimized.bc";
  const auto ll_path = output / "block.optimized.ll";
  llvm::raw_fd_ostream bc(bc_path.string(), ec, llvm::sys::fs::OF_None);
  if (ec) return Error("OUTPUT_ERROR", ec.message());
  llvm::WriteBitcodeToFile(*module, bc); bc.close();
  if (bc.has_error()) return Error("OUTPUT_ERROR", "bitcode write failed");
  llvm::raw_fd_ostream ll(ll_path.string(), ec, llvm::sys::fs::OF_Text);
  if (ec) return Error("OUTPUT_ERROR", ec.message());
  module->print(ll, nullptr); ll.close();
  if (ll.has_error()) return Error("OUTPUT_ERROR", "IR write failed");
  return llvm::json::Object{
      {"protocol_version", 1}, {"ok", true}, {"llvm_ir", ll_path.string()}, {"bitcode", bc_path.string()},
      {"instructions_before", before}, {"instructions_after", Count(*function)},
      {"instructions_before_outlining", optimized_before_outline}, {"outlined_flag_helpers", outlined_helpers},
      {"total_instructions_including_helpers", total_instructions},
      {"identity_helpers_removed", identities}, {"guest_reads_forwarded", forwarded},
      {"state_reads_forwarded", state_reads},
      {"overwritten_guest_writes_removed", dead_writes},
      {"observation_model", "normal-completion-state-and-guest-memory"},
      {"preconditions", llvm::json::Array{"guest-memory-is-disjoint-from-remill-State", "ordinary-single-thread-memory", "memory-accesses-complete-without-fault", "no-intermediate-State-observer"}},
      {"fault_trace_preserved", false}, {"successors_followed", false}};
}
