#include <glog/logging.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Linker/Linker.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/ModRef.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <set>
#include "local_optimizer.h"
#include "local_validation.h"
#include "branch_analysis.h"

namespace {
constexpr int64_t kProtocolVersion = 1;
constexpr size_t kMaximumFrame = 16 * 1024 * 1024;

llvm::json::Object Error(const std::string &code, const std::string &message) {
  return llvm::json::Object{{"protocol_version", kProtocolVersion}, {"ok", false},
          {"code", code}, {"message", message}};
}

llvm::json::Object Handle(const llvm::json::Object &request) {
  if (request.getInteger("protocol_version") != kProtocolVersion)
    return Error("SEMANTICS_VERSION_MISMATCH", "protocol_version must equal 1");
  auto operation = request.getString("op");
  if (!operation) return Error("INVALID_REQUEST", "missing op");
  if (*operation == "optimize-local") return OptimizeLocalBlock(request);
  if (*operation == "validate-local") return ValidateLocalBlock(request);
  if (*operation == "hello") {
    return llvm::json::Object{{"protocol_version", kProtocolVersion}, {"ok", true},
            {"provider", "remill"}, {"revision", NEREUS_REMILL_REVISION},
            {"llvm", LLVM_VERSION_STRING}, {"nir_import", false},
            {"capabilities", llvm::json::Array{"decode-one", "lift-one-bitcode", "lift-basic-block", "optimize-local", "validate-local"}},
            {"architectures", llvm::json::Array{"x86", "amd64"}}};
  }
  const bool lift_block = *operation == "lift-block";
  if (*operation != "lift-one" && !lift_block) return Error("INVALID_OPERATION", "unknown op");

  auto architecture = request.getString("architecture");
  auto hex = request.getString("bytes");
  auto address = request.getString("pc");
  auto output = request.getString("output_dir");
  auto semantics = request.getString("semantics_dir");
  if (!architecture || !hex || !address || !output || !semantics)
    return Error("INVALID_REQUEST", "architecture/bytes/pc/output_dir/semantics_dir required");
  if (*architecture != "x86" && *architecture != "amd64")
    return Error("UNSUPPORTED_ARCHITECTURE", "worker currently accepts x86 and amd64");
  uint64_t pc = 0;
  if (address->getAsInteger(0, pc) || (*architecture == "x86" && pc > UINT32_MAX))
    return Error("INVALID_ADDRESS", "pc is outside the architecture address range");
  const size_t max_hex_size = lift_block ? 262144 : 30;
  if (hex->empty() || hex->size() > max_hex_size || hex->size() % 2)
    return Error("INVALID_BYTES", "instruction/block bytes exceed limits or are invalid");
  std::string bytes;
  for (size_t index = 0; index < hex->size(); index += 2) {
    unsigned byte = 0;
    if (hex->substr(index, 2).getAsInteger(16, byte))
      return Error("INVALID_BYTES", "invalid hex encoding");
    bytes.push_back(static_cast<char>(byte));
  }
  const auto semantics_path = std::filesystem::u8path(semantics->str());
  const auto address_limit = *architecture == "x86" ? uint64_t(UINT32_MAX) : UINT64_MAX;
  if (bytes.size() > address_limit - pc)
    return Error("INVALID_ADDRESS", "instruction span overflows architecture address space");
  if (!std::filesystem::is_regular_file(semantics_path / (architecture->str() + ".bc")))
    return Error("SEMANTICS_PROVIDER_MISSING", "semantics bitcode not found");

  llvm::LLVMContext context;
  auto arch = remill::Arch::Get(context, "windows", architecture->str());
  if (!arch) return Error("UNSUPPORTED_ARCHITECTURE", "Remill architecture unavailable");
  auto module = remill::LoadArchSemantics(arch.get(), {semantics_path});
  remill::IntrinsicTable intrinsics(module.get());
  std::string function_name = lift_block
      ? "nereus_bb_" + llvm::utohexstr(pc, true) : "nereus_lifted_instruction";
  auto function = arch->DefineLiftedFunction(function_name, module.get());
  // 寄存器临时变量名可能被 LLVM 消除，布局信息必须来自 Remill，而不是靠变量名猜偏移。
  function->setMetadata("nereus.rsp.layout", llvm::MDNode::get(context, {
      llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), arch->RegisterByName(arch->StackPointerRegisterName())->offset))}));
  llvm::SmallVector<llvm::Metadata *, 16> register_layout;
  for (const auto *name : {"RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}) {
    if (const auto *reg = arch->RegisterByName(name))
      register_layout.push_back(llvm::MDNode::get(context, {llvm::MDString::get(context, name),
          llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), reg->offset))}));
  }
  function->setMetadata("nereus.gpr.layout", llvm::MDNode::get(context, register_layout));
  auto block = &function->getEntryBlock();
  // NEXT_PC 是 Remill 指令提升的输入，必须在第一条指令前初始化，之后顺序传递。
  remill::StoreNextProgramCounter(block, llvm::ConstantInt::get(intrinsics.pc_type, pc));
  std::vector<size_t> lengths;
  if (lift_block) {
    const auto length_array = request.getArray("instruction_lengths");
    if (!length_array || length_array->empty() || length_array->size() > 32768)
      return Error("INVALID_REQUEST", "instruction_lengths required for lift-block");
    size_t total = 0;
    for (const auto &item : *length_array) {
      const auto value = item.getAsInteger();
      if (!value || *value < 1 || *value > 15)
        return Error("INVALID_REQUEST", "invalid instruction length");
      lengths.push_back(static_cast<size_t>(*value));
      total += static_cast<size_t>(*value);
    }
    if (total != bytes.size()) return Error("INVALID_REQUEST", "instruction lengths do not match bytes");
  } else {
    lengths.push_back(bytes.size());
  }
  llvm::json::Array instruction_map;
  // Rust 已从上一轮优化 IR 计算边目标；非连续源地址保留为每条指令的地址映射。
  const auto *source_pcs = request.getArray("instruction_pcs");
  const auto *block_ends = request.getArray("block_end_indices");
  if ((source_pcs || block_ends) && (!source_pcs || !block_ends || source_pcs->size() != lengths.size()))
    return Error("INVALID_REQUEST", "instruction_pcs/block_end_indices mismatch");
  std::set<size_t> boundaries;
  if (block_ends) for (const auto &item : *block_ends) {
    const auto end = item.getAsInteger();
    if (!end || *end < 1 || uint64_t(*end) > lengths.size()) return Error("INVALID_REQUEST", "invalid block end");
    boundaries.insert(size_t(*end));
  }
  if (block_ends && (boundaries.size() != block_ends->size() || !boundaries.count(lengths.size())))
    return Error("INVALID_REQUEST", "chain boundaries must be unique and end at the last instruction");
  size_t offset = 0;
  remill::Instruction instruction;
  const bool trace_vip=request.getBoolean("trace_instruction_vip").value_or(false);
  const auto trace_seed_register=request.getString("trace_seed_register").value_or("");
  llvm::Function *trace_marker=nullptr;
  if(trace_vip){
    auto *word=llvm::Type::getInt64Ty(context);
    std::vector<llvm::Type*> arguments{word,word,arch->MemoryPointerType()};
    for(unsigned i=0;i<16;++i)arguments.push_back(word);
    trace_marker=llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getVoidTy(context),arguments,false),
        llvm::GlobalValue::ExternalLinkage,"__nereus_instruction_vip",module.get());
    // 仅供分析的边界记录点：不访问 State，保留参数快照直到优化器读取。
    trace_marker->setMemoryEffects(llvm::MemoryEffects::inaccessibleMemOnly());
    trace_marker->addFnAttr(llvm::Attribute::NoUnwind);
  }
  for (size_t index = 0; index < lengths.size(); ++index) {
    instruction.Reset();
    uint64_t instruction_pc = pc + offset;
    if (source_pcs) {
      const auto address_text = (*source_pcs)[index].getAsString();
      if (!address_text || address_text->getAsInteger(0, instruction_pc)) return Error("INVALID_ADDRESS", "invalid source PC");
      if (index == 0 && instruction_pc != pc) return Error("INVALID_ADDRESS", "chain entry PC mismatch");
      if (index && !boundaries.count(index)) {
        const auto previous = (*source_pcs)[index - 1].getAsString();
        uint64_t previous_pc = 0;
        if (!previous || previous->getAsInteger(0, previous_pc) || instruction_pc != previous_pc + lengths[index - 1])
          return Error("INVALID_BLOCK", "non-contiguous instructions inside native block");
      }
    }
    if (instruction_pc > address_limit || lengths[index] > address_limit - instruction_pc)
      return Error("INVALID_ADDRESS", "source instruction exceeds address space");
    if(trace_marker){
      auto lifter=arch->DefaultLifter(intrinsics);
      auto *state=remill::NthArgument(function,remill::kStatePointerArgNum);
      llvm::SmallVector<llvm::Value*,19> values{
          llvm::ConstantInt::get(llvm::Type::getInt64Ty(context),index+request.getInteger("instruction_ordinal_base").value_or(0)),
          llvm::ConstantInt::get(llvm::Type::getInt64Ty(context),instruction_pc),
          remill::LoadMemoryPointer(block,intrinsics)};
      for(const auto *name:{"RAX","RBX","RCX","RDX","RSP","RBP","RSI","RDI","R8","R9","R10","R11","R12","R13","R14","R15"}){
        if(!arch->RegisterByName(name))return Error("TRACE_ARCH_UNSUPPORTED","instruction VIP trace currently requires amd64");
        // 只追踪由前一轮数据流确认的 seed 承载者和入口栈坐标。
        // 记录全部暂存寄存器会让本应消除的 MBA 中间值变为可观察值，妨碍地址归一化。
        values.push_back(trace_seed_register==name || llvm::StringRef(name)=="RSP"
            ?lifter->LoadRegValue(block,state,name):llvm::ConstantInt::get(llvm::Type::getInt64Ty(context),0));
      }
      llvm::IRBuilder<>(block).CreateCall(trace_marker,values);
    }
    const auto span = std::string_view(bytes).substr(offset, lengths[index]);
    if (!arch->DecodeInstruction(instruction_pc, span, instruction, arch->CreateInitialContext()))
      return Error("UNSUPPORTED_INSN", "Remill failed to decode instruction at 0x" + llvm::utohexstr(pc + offset));
    if (instruction.bytes.size() != lengths[index])
      return Error("DECODER_MISMATCH", "Remill and caller disagree on instruction length");
    if (lift_block && index + 1 != lengths.size() && instruction.IsControlFlow() && !boundaries.count(index + 1))
      return Error("INVALID_BLOCK", "control flow occurs before block end");
    if (boundaries.count(index + 1) && index + 1 != lengths.size() &&
        instruction.category != remill::Instruction::kCategoryDirectJump &&
        instruction.category != remill::Instruction::kCategoryIndirectJump &&
        instruction.category != remill::Instruction::kCategoryConditionalBranch &&
        instruction.category != remill::Instruction::kCategoryDirectFunctionCall &&
        instruction.category != remill::Instruction::kCategoryIndirectFunctionCall &&
        instruction.category != remill::Instruction::kCategoryFunctionReturn)
      return Error("INVALID_BLOCK", "unsupported internal chain terminator");
    const auto status = instruction.GetLifter()->LiftIntoBlock(instruction, block);
    if (status != remill::kLiftedInstruction)
      return Error("SEMANTICS_GAP", "Remill could not lift at 0x" + llvm::utohexstr(pc + offset));
    instruction_map.push_back(llvm::json::Object{
        {"pc", "0x" + llvm::utohexstr(instruction_pc, true)},
        {"length", static_cast<int64_t>(lengths[index])},
        {"instruction", instruction.Serialize()}, {"isel", instruction.function}});
    offset += lengths[index];
  }
  if (!lift_block) {
    // 单指令模式只返回状态，不冒充整函数恢复。
    auto memory = remill::LoadMemoryPointer(block, intrinsics);
    llvm::IRBuilder<> builder(block);
    builder.CreateRet(memory);
  } else {
    switch (instruction.category) {
      case remill::Instruction::kCategoryDirectJump:
      case remill::Instruction::kCategoryIndirectJump:
        remill::AddTerminatingTailCall(block, intrinsics.jump, intrinsics);
        break;
      case remill::Instruction::kCategoryConditionalBranch: {
        auto taken = llvm::BasicBlock::Create(context, "taken", function);
        auto not_taken = llvm::BasicBlock::Create(context, "not_taken", function);
        llvm::IRBuilder<> builder(block);
        builder.CreateCondBr(remill::LoadBranchTaken(block), taken, not_taken);
        remill::AddTerminatingTailCall(taken, intrinsics.jump, intrinsics);
        remill::AddTerminatingTailCall(not_taken, intrinsics.jump, intrinsics);
        break;
      }
      case remill::Instruction::kCategoryDirectFunctionCall:
      case remill::Instruction::kCategoryIndirectFunctionCall:
        remill::AddTerminatingTailCall(block, intrinsics.function_call, intrinsics);
        break;
      case remill::Instruction::kCategoryFunctionReturn:
        remill::AddTerminatingTailCall(block, intrinsics.function_return, intrinsics);
        break;
      case remill::Instruction::kCategoryAsyncHyperCall:
        remill::AddTerminatingTailCall(block, intrinsics.async_hyper_call, intrinsics);
        break;
      default:
        return Error("UNSUPPORTED_TERMINATOR", "block terminator is not implemented");
    }
    // Guest 访存/环境 intrinsic 不能因上游属性被当作纯函数而删除；保留副作用与顺序。
    for (auto &candidate : *module) {
      if (candidate.getName().starts_with("__remill_")) {
        candidate.setMemoryEffects(llvm::MemoryEffects::unknown());
        candidate.removeFnAttr(llvm::Attribute::Speculatable);
        for (auto *user : candidate.users()) {
          if (auto *call = llvm::dyn_cast<llvm::CallBase>(user))
            call->setMemoryEffects(llvm::MemoryEffects::unknown());
        }
      }
    }
  }
  if(auto prefix_path=request.getString("prefix_bitcode")) {
    const auto prefix_name=request.getString("prefix_function");
    if(!prefix_name)return Error("INVALID_REQUEST","prefix_function required");
    llvm::SMDiagnostic prefix_diagnostic;
    auto prefix_module=llvm::parseIRFile(*prefix_path,prefix_diagnostic,context);
    auto *prefix=prefix_module?prefix_module->getFunction(*prefix_name):nullptr;
    if(!prefix || prefix->size()!=1)return Error("PREFIX_INVALID","single-path fixed-point prefix required");
    // opt 会补充 AS270/271/272 的目标布局；普通 guest/State 指针布局须保持一致。
    if(prefix_module->getTargetTriple()!=module->getTargetTriple()
        || prefix_module->getDataLayout().getPointerSizeInBits()!=module->getDataLayout().getPointerSizeInBits()
        || prefix_module->getDataLayout().getTypeAllocSize(arch->StateStructType())
            !=module->getDataLayout().getTypeAllocSize(arch->StateStructType()))
      return Error("PREFIX_LAYOUT_MISMATCH","prefix target/State layout mismatch");
    module->setDataLayout(prefix_module->getDataLayout());
    llvm::CallInst *exit=nullptr;
    for(auto &item:prefix->getEntryBlock())if(auto *call=llvm::dyn_cast<llvm::CallInst>(&item))
      if(call->getCalledFunction() && (call->getCalledFunction()->getName()=="__remill_jump"
          || call->getCalledFunction()->getName()=="__remill_function_call"
          || call->getCalledFunction()->getName()=="__remill_function_return")) {
        if(exit)return Error("PREFIX_INVALID","multiple prefix exits");exit=call;
      }
    auto *next=exit?llvm::dyn_cast<llvm::ConstantInt>(exit->getArgOperand(1)):nullptr;
    if(next && next->getZExtValue()!=pc)return Error("PREFIX_TARGET_MISMATCH","prefix target differs from appended entry");
    if(!next) {
      const auto expected=request.getString("prefix_target_model_sha256");
      const auto proven=request.getString("prefix_unique_target");uint64_t target=0;
      auto model=AnalyzeBranch(*prefix);auto smt=model.getString("smt2");
      if(!exit || !expected || !proven || proven->getAsInteger(0,target) || target!=pc || !smt)
        return Error("PREFIX_TARGET_MISMATCH","symbolic prefix requires a matching unique-target proof");
      const auto hash=llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t*>(smt->data()),smt->size()));
      if(llvm::toHex(llvm::ArrayRef<uint8_t>(hash),true)!=*expected)
        return Error("PREFIX_PROOF_MISMATCH","unique-target model does not match current prefix IR");
    }
    exit->replaceAllUsesWith(exit->getArgOperand(2));exit->eraseFromParent();
    const auto prefix_symbol="__nereus_prefix";
    prefix->setName(prefix_symbol);
    prefix->removeFnAttr(llvm::Attribute::NoInline);prefix->removeFnAttr(llvm::Attribute::OptimizeNone);
    prefix->addFnAttr(llvm::Attribute::AlwaysInline);
    function->setName("__nereus_append");
    function->removeFnAttr(llvm::Attribute::NoInline);function->removeFnAttr(llvm::Attribute::OptimizeNone);
    function->addFnAttr(llvm::Attribute::AlwaysInline);
    if(llvm::Linker::linkModules(*module,std::move(prefix_module)))return Error("PREFIX_INVALID","cannot link prefix");
    prefix=module->getFunction(prefix_symbol);
    auto *wrapper=llvm::Function::Create(function->getFunctionType(),llvm::GlobalValue::ExternalLinkage,*prefix_name,module.get());
    wrapper->getArg(0)->setName("state");wrapper->getArg(1)->setName("pc");wrapper->getArg(2)->setName("memory");
    for(auto metadata:{"nereus.rsp.layout","nereus.gpr.layout","nereus.observation","nereus.image.snapshot"})
      if(auto *node=prefix->getMetadata(metadata))wrapper->setMetadata(metadata,node);
    auto *entry=llvm::BasicBlock::Create(context,"entry",wrapper);
    llvm::IRBuilder<> builder(entry);
    auto *memory=builder.CreateCall(prefix,{wrapper->getArg(0),wrapper->getArg(1),wrapper->getArg(2)});
    auto *result=builder.CreateCall(function,{wrapper->getArg(0),llvm::ConstantInt::get(intrinsics.pc_type,pc),memory});
    builder.CreateRet(result);
    function=wrapper;function_name=prefix_name->str();
  }
  std::string diagnostic;
  llvm::raw_string_ostream diagnostics(diagnostic);
  if (llvm::verifyModule(*module, &diagnostics))
    return Error("IR_INVALID", diagnostics.str());

  std::error_code ec;
  auto output_path = std::filesystem::u8path(output->str());
  std::filesystem::create_directories(output_path, ec);
  if (ec) return Error("OUTPUT_ERROR", ec.message());
  const auto bc_path = output_path / (lift_block ? "block.raw.bc" : "instruction.bc");
  const auto ll_path = output_path / (lift_block ? "block.raw.ll" : "instruction.ll");
  // 保留原始语义，不在前端 smoke 中运行 O3 或删除 memory/env intrinsic。
  // 上游临时文件 rename 在 Windows 已存在目标时失败；直接使用 LLVM 输出流并检查写入错误。
  llvm::raw_fd_ostream bc_stream(bc_path.string(), ec, llvm::sys::fs::OF_None);
  if (ec) return Error("OUTPUT_ERROR", ec.message());
  llvm::WriteBitcodeToFile(*module, bc_stream);
  bc_stream.close();
  if (bc_stream.has_error()) return Error("OUTPUT_ERROR", "failed to write bitcode");
  llvm::raw_fd_ostream ll_stream(ll_path.string(), ec, llvm::sys::fs::OF_Text);
  if (ec) return Error("OUTPUT_ERROR", ec.message());
  module->print(ll_stream, nullptr);
  ll_stream.close();
  if (ll_stream.has_error()) return Error("OUTPUT_ERROR", "failed to write LLVM IR");
  return llvm::json::Object{{"protocol_version", kProtocolVersion}, {"ok", true},
          {"architecture", architecture->str()}, {"pc", address->str()},
          {"length", static_cast<int64_t>(bytes.size())},
          {"instruction_count", static_cast<int64_t>(lengths.size())},
          {"function_name", function_name}, {"instructions", std::move(instruction_map)},
          {"instruction", instruction.Serialize()},
          {"bitcode", bc_path.string()}, {"llvm_ir", ll_path.string()},
          {"triple", module->getTargetTriple()},
          {"data_layout", module->getDataLayoutStr()},
          {"state_size", static_cast<int64_t>(module->getDataLayout().getTypeAllocSize(arch->StateStructType()))},
          {"normalized", false}, {"function_recovered", false}};
}
}  // namespace

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);
  FLAGS_logtostderr = true;
  // JSONL 仅使用 stdout，依赖日志留在 stderr；超过帧上限即拒绝并结束进程。
  std::string line;
  char byte = 0;
  while (std::cin.get(byte)) {
    if (byte != '\n') {
      if (line.size() >= kMaximumFrame) {
        llvm::outs() << llvm::json::Value(Error("FRAME_TOO_LARGE", "frame exceeds 16 MiB")) << '\n';
        llvm::outs().flush();
        return 2;
      }
      line.push_back(byte);
      continue;
    }
    auto value = llvm::json::parse(line);
    llvm::json::Object response;
    if (!value) {
      llvm::consumeError(value.takeError());
      response = Error("INVALID_JSON", "request is not valid JSON");
    } else if (auto object = value->getAsObject()) {
      response = Handle(*object);
      if (auto request_id = object->getInteger("request_id"))
        response["request_id"] = *request_id;
    } else {
      response = Error("INVALID_REQUEST", "request must be an object");
    }
    llvm::outs() << llvm::json::Value(std::move(response)) << '\n';
    llvm::outs().flush();
    line.clear();
  }
  return 0;
}
