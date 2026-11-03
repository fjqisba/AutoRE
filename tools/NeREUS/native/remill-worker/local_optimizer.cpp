#include "local_optimizer.h"
#include "branch_analysis.h"

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
#include <llvm/Support/SHA256.h>
#include <llvm/Support/raw_ostream.h>

#include <filesystem>
#include <optional>
#include <map>
#include <set>

namespace {
llvm::json::Object Error(llvm::StringRef code, llvm::StringRef message) {
  return llvm::json::Object{{"protocol_version", 1}, {"ok", false},
                           {"code", code.str()}, {"message", message.str()}};
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
  return callee && ((callee->isIntrinsic() && !call->mayWriteToMemory()) ||
      (callee->getName().starts_with("__remill_undefined_") && call->arg_empty()) ||
      callee->getName()=="__nereus_instruction_vip");
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

unsigned PromoteSnapshotReads(llvm::Function &function, const llvm::json::Array *facts,
                             llvm::json::Array &used,llvm::json::Array &blocked) {
  if (!facts) return 0;
  std::map<uint64_t,uint8_t> snapshot;
  for (auto &fact : *facts) {
    auto *object=fact.getAsObject(); if (!object) continue;
    auto address=object->getString("address"), bytes=object->getString("bytes");
    uint64_t base=0;
    if (!address || !bytes || address->getAsInteger(0,base) || bytes->size()%2) continue;
    for (size_t index=0;index<bytes->size();index+=2) {
      unsigned byte=0;
      if (bytes->substr(index,2).getAsInteger(16,byte)) break;
      snapshot[base+index/2]=uint8_t(byte);
    }
  }
  llvm::Value *initial_rsp=nullptr;
  const auto *layout_metadata=function.getMetadata("nereus.rsp.layout");
  const auto *rsp_offset=layout_metadata && layout_metadata->getNumOperands()==1
      ? llvm::mdconst::dyn_extract<llvm::ConstantInt>(layout_metadata->getOperand(0)):nullptr;
  if (!rsp_offset) return 0;
  const auto &layout=function.getParent()->getDataLayout();
  for (auto &instruction:llvm::instructions(function)) if(auto *load=llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
    int64_t offset=0;
    if(llvm::GetPointerBaseWithConstantOffset(load->getPointerOperand(),offset,layout)==function.getArg(0)
        && uint64_t(offset)==rsp_offset->getZExtValue() && load->getType()->isIntegerTy(64)) {initial_rsp=load;break;}
  }
  llvm::SmallVector<llvm::CallInst*> reads;
  for(auto &instruction:llvm::instructions(function)) if(auto *call=llvm::dyn_cast<llvm::CallInst>(&instruction))
    if(call->getCalledFunction() && MemoryWidth(call->getCalledFunction()->getName(),false)) reads.push_back(call);
  unsigned count=0;
  for(auto *read:reads) {
    const auto width=MemoryWidth(read->getCalledFunction()->getName(),false);
    auto *address=llvm::dyn_cast<llvm::ConstantInt>(read->getArgOperand(1));
    if(!address || !read->getType()->isIntegerTy(width)) continue;
    const auto base=address->getZExtValue();
    uint64_t value=0; bool available=true;
    for(unsigned index=0;index<width/8;++index) {
      if(!snapshot.count(base+index)) {available=false;break;}
      value|=uint64_t(snapshot[base+index])<<(index*8);
    }
    if(!available) continue;
    // 跳过有可能覆盖该快照的写入。栈与映像分离是明确新增的条件化前提。
    std::string reason,barrier,stack_base;
    for(auto *previous=read->getPrevNode();previous;previous=previous->getPrevNode()) {
      auto *call=llvm::dyn_cast<llvm::CallInst>(previous);if(!call)continue;
      auto *callee=call->getCalledFunction();
      const auto store_width=callee?MemoryWidth(callee->getName(),true):0;
      if(!store_width) {if(!IsHarmless(call) && !(callee && MemoryWidth(callee->getName(),false))) {
        available=false;reason="unknown-call-effects";llvm::raw_string_ostream text(barrier);call->print(text);break;}continue;}
      auto destination=Address(call->getArgOperand(1));
      if(initial_rsp && destination.base==initial_rsp) continue;
      if(destination.base) {
        available=false;reason="store-address-not-normalized-to-entry-stack";
        llvm::raw_string_ostream text(barrier);call->print(text);
        if(initial_rsp){llvm::raw_string_ostream input(stack_base);initial_rsp->printAsOperand(input,false);}
        break;
      }
      for(unsigned i=0;i<width/8;++i) if(base+i-destination.offset<store_width/8) available=false;
      if(!available){reason="overlapping-guest-write";llvm::raw_string_ostream text(barrier);call->print(text);break;}
    }
    if(!available){
      if(blocked.size()<512)blocked.push_back(llvm::json::Object{{"address","0x"+llvm::utohexstr(base,true)},
          {"width_bits",int64_t(width)},{"snapshot_available",true},{"reason",reason},
          {"barrier",barrier},{"entry_rsp_value",stack_base}});
      continue;
    }
    used.push_back(llvm::json::Object{{"address","0x"+llvm::utohexstr(base,true)},
        {"width_bits",int64_t(width)},{"value","0x"+llvm::utohexstr(value,true)},
        {"source","readonly-PE-preferred-base-snapshot"}});
    read->replaceAllUsesWith(llvm::ConstantInt::get(read->getType(),value));read->eraseFromParent();++count;
  }
  return count;
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
      if (!context_base && store->getPointerOperand()->getName() == "RBP") context_base = store->getValueOperand();
  }
  if (!context_base || !stack_input) return;
  auto anchor = Address(context_base);
  if (anchor.base != stack_input) return;
  // 跨块 DSE 可能只留下后建立的 RBP。它的定义晚于早期保存操作，
  // 必须在入口 RSP load 之后重新建立纯仿射坐标，保证支配全部用途。
  auto *input_instruction = llvm::dyn_cast<llvm::Instruction>(stack_input);
  if (!input_instruction || !input_instruction->getNextNode()) return;
  llvm::IRBuilder<> coordinate(input_instruction->getNextNode());
  context_base = coordinate.CreateAdd(stack_input, coordinate.getInt64(anchor.offset), "context.base");
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

llvm::json::Object InspectInitialization(llvm::Function &entry) {
  llvm::json::Array exits;
  llvm::SmallVector<llvm::CallInst *> transfers;
  std::optional<uint64_t> unique_target;
  bool resolved = true;
  for (auto &instruction : llvm::instructions(entry)) {
    auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
    if (!call || !call->getCalledFunction()) continue;
    const auto name = call->getCalledFunction()->getName();
    if (name != "__remill_jump" && name != "__remill_function_call" && name != "__remill_function_return" && name != "__remill_async_hyper_call") continue;
    transfers.push_back(call);
    const auto *constant = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1));
    // 返回结果在 Module 销毁后才被主循环序列化，必须持有字符串所有权。
    llvm::json::Object edge{{"kind", name.str()}, {"resolved", bool(constant)}};
    if (constant) {
      const auto target = constant->getZExtValue();
      edge["target"] = "0x" + llvm::utohexstr(target, true);
      if (unique_target && *unique_target != target) resolved = false;
      unique_target = target;
    } else {
      resolved = false;
      std::string expression; llvm::raw_string_ostream text(expression);
      call->getArgOperand(1)->printAsOperand(text,false);
      edge["target_value"] = text.str();
      llvm::json::Array reads;
      std::set<llvm::Value *> visited;
      llvm::SmallVector<llvm::Value *> pending{call->getArgOperand(1)};
      while (!pending.empty() && visited.size() < 4096) {
        auto *value = pending.pop_back_val();
        if (!visited.insert(value).second) continue;
        auto *dependency = llvm::dyn_cast<llvm::Instruction>(value);
        if (!dependency) continue;
        if (auto *read = llvm::dyn_cast<llvm::CallInst>(dependency)) {
          auto *callee = read->getCalledFunction();
          const auto width = callee ? MemoryWidth(callee->getName(),false) : 0;
          if (width) {
            llvm::json::Object item{{"width_bits",int64_t(width)}};
            if (auto *address = llvm::dyn_cast<llvm::ConstantInt>(read->getArgOperand(1)))
              item["address"] = "0x" + llvm::utohexstr(address->getZExtValue(),true);
            else { std::string address_text; llvm::raw_string_ostream stream(address_text); read->getArgOperand(1)->printAsOperand(stream,false); item["symbolic_address"] = stream.str(); }
            reads.push_back(std::move(item));
            pending.push_back(read->getArgOperand(1));
            continue;
          }
        }
        for (auto &operand : dependency->operands()) pending.push_back(operand.get());
      }
      edge["blocking_memory_reads"] = std::move(reads);
    }
    exits.push_back(std::move(edge));
  }
  llvm::json::Object result{{"policy", "tvm-state-machine-context-v2"},
      {"complete", false}, {"exits", std::move(exits)},
      {"unique_target_resolved", resolved && unique_target.has_value()}, {"saved_gpr_count", 0}};
  if (resolved && unique_target) result["next_target"] = "0x" + llvm::utohexstr(*unique_target, true);
  if (entry.size() != 1) { result["reason"] = "multiple-live-control-flow-paths"; return result; }
  auto *metadata = entry.getMetadata("nereus.gpr.layout");
  const auto flag_region = FindFlagRegion(*entry.getParent());
  if (!metadata || metadata->getNumOperands() != 16 || !flag_region) { result["reason"] = "unsupported-register-layout"; return result; }
  std::map<int64_t, std::string> registers;
  for (auto &item : metadata->operands()) {
    auto *pair = llvm::dyn_cast<llvm::MDNode>(item.get());
    if (!pair || pair->getNumOperands() != 2) continue;
    auto *name = llvm::dyn_cast<llvm::MDString>(pair->getOperand(0));
    auto *offset = llvm::mdconst::dyn_extract<llvm::ConstantInt>(pair->getOperand(1));
    if (name && offset) registers[int64_t(offset->getZExtValue())] = name->getString().str();
  }
  auto *state = entry.getArg(0);
  const auto &layout = entry.getParent()->getDataLayout();
  std::map<llvm::Value *, std::string> origins;
  std::set<int64_t> modified;
  std::map<std::string, llvm::Value *> final_registers;
  llvm::Value *initial_rsp = nullptr;
  std::map<int64_t, llvm::Value *> writes;
  for (auto &instruction : llvm::instructions(entry)) {
    if (auto *load = llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
      int64_t offset = 0;
      if (llvm::GetPointerBaseWithConstantOffset(load->getPointerOperand(), offset, layout) == state &&
          load->getType()->isIntegerTy(64) && registers.count(offset) && !modified.count(offset)) {
        origins[load] = registers[offset];
        if (registers[offset] == "RSP") initial_rsp = load;
      }
    }
    if (auto *store = llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
      int64_t offset = 0;
      if (llvm::GetPointerBaseWithConstantOffset(store->getPointerOperand(), offset, layout) == state) {
        const auto count = layout.getTypeStoreSize(store->getValueOperand()->getType());
        for (auto &reg : registers) if (offset < reg.first + 8 && reg.first < offset + int64_t(count)) modified.insert(reg.first);
        if (registers.count(offset) && store->getValueOperand()->getType()->isIntegerTy(64)) final_registers[registers[offset]] = store->getValueOperand();
      }
    }
    auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
    if (!call || !call->getCalledFunction()) continue;
    const auto name = call->getCalledFunction()->getName();
    const auto width = MemoryWidth(name, true);
    if (width) {
      const auto address = Address(call->getArgOperand(1));
      if (address.base != initial_rsp || !initial_rsp) { writes.clear(); continue; }
      const auto offset = int64_t(address.offset);
      for (auto it = writes.begin(); it != writes.end();) {
        if (offset < it->first + 8 && it->first < offset + int64_t(width / 8)) it = writes.erase(it); else ++it;
      }
      if (width == 64) writes[offset] = call->getArgOperand(2);
    } else if (!MemoryWidth(name, false) && name != "__remill_jump" && name != "__remill_function_call" &&
               name != "__remill_function_return" && !IsHarmless(call)) writes.clear();
  }
  auto origin = [&](llvm::Value *value) -> std::string {
    if (origins.count(value)) return origins[value];
    const auto affine = Address(value);
    if (affine.base == initial_rsp && affine.offset == 0) return "RSP";
    return {};
  };
  std::set<std::string> all_saved;
  for (auto &write : writes) {
    const auto name = origin(write.second);
    if (!name.empty()) all_saved.insert(name);
  }
  result["saved_gpr_count"] = int64_t(all_saved.size());
  llvm::json::Array missing;
  for (auto &reg : registers) if (!all_saved.count(reg.second)) missing.push_back(reg.second);
  result["missing_gprs"] = std::move(missing);
  result["reason"] = "register-save-or-context-publication-incomplete";
  // 只从连续保存区识别 guest frame，不依赖 Context 恰好在 R10 还是 R11。
  if (!initial_rsp) return result;
  std::optional<int64_t> guest_frame;
  llvm::json::Array frame_slots;
  for (auto &candidate : writes) {
    std::set<std::string> saved;
    llvm::json::Array slots;
    bool flags = false, valid = true;
    for (unsigned index = 0; index < 17; ++index) {
      const auto address = candidate.first + int64_t(index * 8);
      if (!writes.count(address)) { valid = false; break; }
      const auto name = origin(writes[address]);
      if (!name.empty()) {
        if (!saved.insert(name).second) { valid = false; break; }
        slots.push_back(llvm::json::Object{{"offset", int64_t(index * 8)}, {"source", name}});
      } else {
        std::set<llvm::Instruction *> slice;
        if (!FlagSlice(writes[address], state, *flag_region, layout, nullptr, slice) || slice.size() < 8 || flags) { valid = false; break; }
        flags = true;
        slots.push_back(llvm::json::Object{{"offset", int64_t(index * 8)}, {"source", "FLAGS"}});
      }
    }
    if (valid && saved.size() == 16 && flags) {
      guest_frame = candidate.first;
      frame_slots = std::move(slots);
    }
  }
  result["stage"] = guest_frame ? "GuestStateSaved" : "SavingGuestState";
  result["guest_state_saved"] = guest_frame.has_value();
  if (!guest_frame) return result;
  result["frame_offset_from_entry_rsp"] = *guest_frame;
  result["context_pointer_offset_from_entry_rsp"] = *guest_frame - 8;
  result["slots"] = std::move(frame_slots);
  llvm::json::Array roles, runtime_writes, register_values;
  for (auto &reg : final_registers) {
    const auto value = Address(reg.second);
    llvm::json::Object item{{"register", reg.first}};
    if (value.base == initial_rsp) {
      item["entry_rsp_offset"] = int64_t(value.offset);
      if (int64_t(value.offset) == *guest_frame - 8) {
        item["role"] = "guest_context_pointer";
        roles.push_back(llvm::json::Object{{"register",reg.first},{"role","guest_context_pointer"},{"entry_rsp_offset",int64_t(value.offset)}});
      }
    } else if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(reg.second)) {
      item["constant"] = "0x" + llvm::utohexstr(constant->getZExtValue(), true);
      item["role"] = "constant_address_candidate";
      roles.push_back(llvm::json::Object{{"register",reg.first},{"role","constant_address_candidate"},{"constant","0x" + llvm::utohexstr(constant->getZExtValue(), true)}});
    }
    register_values.push_back(std::move(item));
  }
  std::optional<int64_t> runtime_base;
  if (final_registers.count("RBP")) {
    const auto frame = Address(final_registers["RBP"]);
    // 第一个帧仅保存 guest 状态；新的、更低的 RBP 帧表示继续建立解释器运行上下文。
    if (frame.base == initial_rsp && int64_t(frame.offset) < *guest_frame - 0x90) runtime_base = int64_t(frame.offset);
  }
  if (runtime_base) {
    for (auto &write : writes) {
      const auto relative = write.first - *runtime_base;
      if (relative < 0 || relative >= 0xa0) continue;
      llvm::json::Object item{{"offset", relative}, {"entry_rsp_offset", write.first}};
      const auto source = origin(write.second);
      if (!source.empty()) item["source"] = source;
      else if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(write.second)) item["constant"] = "0x" + llvm::utohexstr(constant->getZExtValue(), true);
      else { std::string text; llvm::raw_string_ostream stream(text); write.second->printAsOperand(stream, false); item["value"] = stream.str(); }
      runtime_writes.push_back(std::move(item));
    }
    result["stage"] = "BuildingRuntimeContext";
    result["runtime_frame_offset_from_entry_rsp"] = *runtime_base;
  }
  result["runtime_context_writes"] = std::move(runtime_writes);
  result["register_roles"] = std::move(roles);
  result["final_register_values"] = std::move(register_values);
  result["reason"] = "guest-state-saved-but-runtime-and-dispatch-boundary-not-proven";
  // CALL 本身不是完成条件。只有证明运行帧、解码状态和派发边界后才能置 complete；
  // 当前证据不足时继续状态机，遇到未解析边按协议报错，绝不返回伪完成。
  return result;
}

llvm::json::Array ContextReadDependencies(llvm::Function &entry) {
  llvm::json::Array reads;
  std::set<llvm::Value*> visited;
  llvm::SmallVector<llvm::Value*> pending;
  for(auto &instruction:llvm::instructions(entry))if(auto *call=llvm::dyn_cast<llvm::CallInst>(&instruction))
    if(call->getCalledFunction() && MemoryWidth(call->getCalledFunction()->getName(),true)){
      pending.push_back(call->getArgOperand(1));pending.push_back(call->getArgOperand(2));
    }
  while(!pending.empty()&&visited.size()<10000){
    auto *value=pending.pop_back_val();if(!visited.insert(value).second)continue;
    auto *instruction=llvm::dyn_cast<llvm::Instruction>(value);if(!instruction)continue;
    if(auto *call=llvm::dyn_cast<llvm::CallInst>(instruction)){
      auto *callee=call->getCalledFunction();const auto width=callee?MemoryWidth(callee->getName(),false):0;
      if(width){
        if(auto *address=llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1)))
          reads.push_back(llvm::json::Object{{"address","0x"+llvm::utohexstr(address->getZExtValue(),true)},{"width_bits",int64_t(width)}});
        pending.push_back(call->getArgOperand(1));continue;
      }
    }
    for(auto &operand:instruction->operands())pending.push_back(operand.get());
  }
  return reads;
}

// 真正的调用者返回必须同时证明栈平衡和返回地址来自入口栈槽。
// 单独看到 RET 或进入某个 epilogue 块都不足以宣布 VM 函数已结束。
llvm::json::Object InspectFunctionReturn(llvm::Function &entry) {
  llvm::json::Object result{{"is_caller_return",false}};
  if(entry.size()!=1)return result;
  const auto *metadata=entry.getMetadata("nereus.rsp.layout");
  const auto *offset=metadata && metadata->getNumOperands()==1
      ?llvm::mdconst::dyn_extract<llvm::ConstantInt>(metadata->getOperand(0)):nullptr;
  if(!offset)return result;
  const auto &layout=entry.getParent()->getDataLayout();
  llvm::Value *initial_rsp=nullptr,*final_rsp=nullptr,*return_target=nullptr;
  bool modified=false;
  for(auto &instruction:llvm::instructions(entry)) {
    if(auto *load=llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
      int64_t actual=0;
      if(!modified && load->isSimple() && load->getType()->isIntegerTy(64)
          && llvm::GetPointerBaseWithConstantOffset(load->getPointerOperand(),actual,layout)==entry.getArg(0)
          && uint64_t(actual)==offset->getZExtValue() && !initial_rsp)initial_rsp=load;
    }
    if(auto *store=llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
      int64_t actual=0;
      if(llvm::GetPointerBaseWithConstantOffset(store->getPointerOperand(),actual,layout)==entry.getArg(0)
          && uint64_t(actual)==offset->getZExtValue()) {
        modified=true; final_rsp=store->getValueOperand();
      }
    }
    if(auto *call=llvm::dyn_cast<llvm::CallInst>(&instruction))
      if(call->getCalledFunction() && call->getCalledFunction()->getName()=="__remill_function_return")
        return_target=call->getArgOperand(1);
  }
  if(!return_target || !initial_rsp || !final_rsp)return result;
  const auto final=Address(final_rsp);
  const bool balanced=final.base==initial_rsp && final.offset>=8 && final.offset<=8+65535;
  auto *read=llvm::dyn_cast<llvm::CallInst>(return_target);
  const auto slot=read && read->arg_size()==2 ?Address(read->getArgOperand(1)):AffineAddress{nullptr,0};
  const bool caller_slot=read && read->getCalledFunction()
      && MemoryWidth(read->getCalledFunction()->getName(),false)==64
      && slot.base==initial_rsp && slot.offset==0;
  result["native_ret"]=true;result["caller_stack_restored"]=balanced;
  result["target_from_entry_return_slot"]=caller_slot;
  if(final.base==initial_rsp)result["final_rsp_offset_from_entry"]=int64_t(final.offset);
  result["is_caller_return"]=balanced && caller_slot;
  std::string text;llvm::raw_string_ostream stream(text);return_target->print(stream);
  result["target_expression"]=stream.str();
  result["scope"]="current-path-normal-completion-stack-and-return-slot";
  return result;
}

llvm::json::Array InstructionVipTrace(llvm::Function &entry,const llvm::json::Object *config){
  llvm::json::Array result;
  if(!config)return result;
  const auto seed_text=config->getString("stream_base");
  const auto slot=config->getInteger("cursor_slot_from_entry_rsp");
  uint64_t seed=0;
  if(!seed_text||seed_text->getAsInteger(0,seed))return result;
  llvm::Value *initial_rsp=nullptr;
  bool initialized=false;
  std::optional<uint64_t> current;
  for(auto &instruction:llvm::instructions(entry)){
    auto *marker=llvm::dyn_cast<llvm::CallInst>(&instruction);
    if(!marker||!marker->getCalledFunction()||marker->getCalledFunction()->getName()!="__nereus_instruction_vip")continue;
    if(marker->arg_size()!=19)continue;
    if(!initial_rsp)initial_rsp=marker->getArgOperand(3+4);
    // 在已证明参与字节码读取的 seed 第一次实际进入寄存器后初始化；
    // 不回填 seed 到先前尚未建立游标的指令上。
    if(!initialized){
      for(unsigned index=3;index<19;++index)
        if(auto *constant=llvm::dyn_cast<llvm::ConstantInt>(marker->getArgOperand(index)))
          if(constant->getZExtValue()==seed){initialized=true;current=seed;break;}
    }
    std::string source=initialized?"register-value-provenance":"not-initialized";
    if(initialized&&slot){
      llvm::Value *token=marker->getArgOperand(2);
      for(unsigned limit=0;limit<8192;++limit){
        auto *write=llvm::dyn_cast<llvm::CallInst>(token);
        if(!write||!write->getCalledFunction())break;
        const auto width=MemoryWidth(write->getCalledFunction()->getName(),true);
        if(!width)break;
        const auto destination=Address(write->getArgOperand(1));
        if(destination.base!=initial_rsp){current.reset();source="unresolved-alias";break;}
        const uint64_t distance=uint64_t(*slot)-destination.offset;
        const bool overlaps=distance<width/8 || destination.offset-uint64_t(*slot)<8;
        if(overlaps){
          auto *value=llvm::dyn_cast<llvm::ConstantInt>(write->getArgOperand(2));
          if(distance==0&&width==64&&value){current=value->getZExtValue();source="cursor-memory-version";}
          else {current.reset();source="unresolved-cursor-write";}
          break;
        }
        token=write->getArgOperand(0);
      }
    }
    const auto *ordinal=llvm::dyn_cast<llvm::ConstantInt>(marker->getArgOperand(0));
    const auto *rip=llvm::dyn_cast<llvm::ConstantInt>(marker->getArgOperand(1));
    if(ordinal&&rip)result.push_back(llvm::json::Object{{"ordinal",int64_t(ordinal->getZExtValue())},
        {"rip","0x"+llvm::utohexstr(rip->getZExtValue(),true)},
        {"vip","0x"+llvm::utohexstr(current.value_or(0),true)},
        {"vip_initialized",initialized},{"vip_resolved",current.has_value()},
        {"boundary","before-native-instruction"},{"source",source}});
  }
  return result;
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
    if (helper.starts_with("__remill_undefined_") && call->arg_empty()) {
      // 未规定标志值保留为显式未知调用，但它不会改写任何 GPR/guest memory。
      // 不替换为零，不给它 speculatable 属性。
      call->setMemoryEffects(llvm::MemoryEffects::none());
      call->getCalledFunction()->setMemoryEffects(llvm::MemoryEffects::none());
    }
  }
  for (auto *call : to_remove) call->eraseFromParent();
  std::string error;
  const auto pipeline = "function(early-cse<memssa>,instcombine,gvn,dse,adce,simplifycfg),globaldce";
  if (!RunPipeline(*module, pipeline, error)) return Error("IR_INVALID", error);
  unsigned forwarded = 0, state_reads = 0, dead_writes = 0, iterations = 0;
  unsigned promoted=0;llvm::json::Array used_snapshot,blocked_snapshot,iteration_history;
  // 比较完整表示，不使用指令数或自定义 pass 命中数作为收敛条件。
  // LLVM 自身仍可能在自定义 pass 无命中时继续折叠表达式、规范化栈地址。
  auto ir_snapshot = [&]() {
    std::string text; llvm::raw_string_ostream stream(text);
    module->print(stream, nullptr); return stream.str();
  };
  auto state_snapshot = [&]() {
    llvm::json::Value state(llvm::json::Object{
        {"initialization", InspectInitialization(*function)},
        {"branch", AnalyzeBranch(*function)},
        {"context_reads", ContextReadDependencies(*function)}});
    std::string text; llvm::raw_string_ostream stream(text);
    stream << state; return stream.str();
  };
  auto digest = [](llvm::StringRef text) {
    const auto hash = llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(
        reinterpret_cast<const uint8_t *>(text.data()), text.size()));
    return llvm::toHex(llvm::ArrayRef<uint8_t>(hash), true);
  };
  auto previous_ir = ir_snapshot(), previous_state = state_snapshot();
  std::set<std::pair<std::string,std::string>> seen;
  seen.emplace(digest(previous_ir),digest(previous_state));
  bool converged = false;
  std::string stop_reason = "iteration-budget-exhausted";
  const auto iteration_budget=unsigned(std::clamp<int64_t>(request.getInteger("iteration_budget").value_or(256),1,4096));
  while (iterations < iteration_budget) {
    const auto state_changes = ForwardState(*function);
    if (!RunPipeline(*module, pipeline, error)) return Error("IR_INVALID", error);
    const auto reads = ForwardReads(*function);
    const auto constants=PromoteSnapshotReads(*function,request.getArray("image_facts"),used_snapshot,blocked_snapshot);
    promoted+=constants;
    const auto writes = RemoveOverwrittenStores(*function);
    forwarded += reads; dead_writes += writes;
    state_reads += state_changes;
    if (!RunPipeline(*module, pipeline, error)) return Error("IR_INVALID", error);
    ++iterations;
    auto current_ir = ir_snapshot(), current_state = state_snapshot();
    const bool ir_changed = current_ir != previous_ir;
    const bool state_changed = current_state != previous_state;
    const auto ir_hash = digest(current_ir), state_hash = digest(current_state);
    iteration_history.push_back(llvm::json::Object{
        {"iteration",int64_t(iterations)}, {"ir_changed",ir_changed},
        {"state_changed",state_changed}, {"ir_sha256",ir_hash}, {"state_sha256",state_hash},
        {"instructions",Count(*function)}, {"state_reads_forwarded",state_changes},
        {"guest_reads_forwarded",reads}, {"snapshot_reads_promoted",constants},
        {"overwritten_guest_writes_removed",writes}});
    if (!ir_changed && !state_changed) {
      converged = true; stop_reason = "fixed-point"; break;
    }
    if (!seen.emplace(ir_hash,state_hash).second) {
      stop_reason = "optimization-cycle"; break;
    }
    previous_ir = std::move(current_ir); previous_state = std::move(current_state);
  }
  const auto optimized_before_outline = Count(*function);
  auto instruction_vips=InstructionVipTrace(*function,request.getObject("vip_trace"));
  auto initialization = InspectInitialization(*function);
  auto branch_analysis=AnalyzeBranch(*function);
  auto function_return=InspectFunctionReturn(*function);
  auto context_reads=ContextReadDependencies(*function);
  if(promoted){
    function->setMetadata("nereus.image.snapshot",llvm::MDNode::get(context,{
        llvm::MDString::get(context,"readonly-PE-preferred-base-snapshot"),
        llvm::MDString::get(context,"entry-stack-disjoint-from-image"),
        llvm::MDString::get(context,"runtime-image-equals-supplied-snapshot-at-promoted-addresses")}));
  }
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
      {"initialization", std::move(initialization)},
      {"branch_analysis",std::move(branch_analysis)},
      {"function_return",std::move(function_return)},
      {"context_read_dependencies",std::move(context_reads)},
      {"instruction_vips",std::move(instruction_vips)},
      {"instructions_before_outlining", optimized_before_outline}, {"outlined_flag_helpers", outlined_helpers},
      {"total_instructions_including_helpers", total_instructions},
      {"identity_helpers_removed", identities}, {"guest_reads_forwarded", forwarded},
      {"state_reads_forwarded", state_reads},
      {"snapshot_reads_promoted",promoted},{"snapshot_reads",std::move(used_snapshot)},
      {"snapshot_reads_blocked",std::move(blocked_snapshot)},
      {"iteration_budget",int64_t(iteration_budget)},{"iterations",int64_t(iterations)},
      {"converged",converged},{"stop_reason",stop_reason},
      {"iteration_budget_exhausted",!converged && stop_reason=="iteration-budget-exhausted"},
      {"iteration_history",std::move(iteration_history)},
      {"overwritten_guest_writes_removed", dead_writes},
      {"observation_model", "normal-completion-state-and-guest-memory"},
      {"preconditions", llvm::json::Array{"guest-memory-is-disjoint-from-remill-State", "ordinary-single-thread-memory", "memory-accesses-complete-without-fault", "no-intermediate-State-observer"}},
      {"fault_trace_preserved", false}, {"successors_followed", false}};
}
