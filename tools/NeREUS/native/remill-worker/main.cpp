#include <glog/logging.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
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
#include "local_optimizer.h"
#include "local_validation.h"

namespace {
constexpr int64_t kProtocolVersion = 1;
constexpr size_t kMaximumFrame = 1024 * 1024;

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
  const size_t max_hex_size = lift_block ? 32768 : 30;
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
  const std::string function_name = lift_block
      ? "nereus_bb_" + llvm::utohexstr(pc, true) : "nereus_lifted_instruction";
  auto function = arch->DefineLiftedFunction(function_name, module.get());
  // 寄存器临时变量名可能被 LLVM 消除，布局信息必须来自 Remill，而不是靠变量名猜偏移。
  function->setMetadata("nereus.rsp.layout", llvm::MDNode::get(context, {
      llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), arch->RegisterByName(arch->StackPointerRegisterName())->offset))}));
  auto block = &function->getEntryBlock();
  // NEXT_PC 是 Remill 指令提升的输入，必须在第一条指令前初始化，之后顺序传递。
  remill::StoreNextProgramCounter(block, llvm::ConstantInt::get(intrinsics.pc_type, pc));
  std::vector<size_t> lengths;
  if (lift_block) {
    const auto length_array = request.getArray("instruction_lengths");
    if (!length_array || length_array->empty() || length_array->size() > 4096)
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
  size_t offset = 0;
  remill::Instruction instruction;
  for (size_t index = 0; index < lengths.size(); ++index) {
    instruction.Reset();
    const auto span = std::string_view(bytes).substr(offset, lengths[index]);
    if (!arch->DecodeInstruction(pc + offset, span, instruction, arch->CreateInitialContext()))
      return Error("UNSUPPORTED_INSN", "Remill failed to decode instruction at 0x" + llvm::utohexstr(pc + offset));
    if (instruction.bytes.size() != lengths[index])
      return Error("DECODER_MISMATCH", "Remill and caller disagree on instruction length");
    if (lift_block && index + 1 != lengths.size() && instruction.IsControlFlow())
      return Error("INVALID_BLOCK", "control flow occurs before block end");
    const auto status = instruction.GetLifter()->LiftIntoBlock(instruction, block);
    if (status != remill::kLiftedInstruction)
      return Error("SEMANTICS_GAP", "Remill could not lift at 0x" + llvm::utohexstr(pc + offset));
    instruction_map.push_back(llvm::json::Object{
        {"pc", "0x" + llvm::utohexstr(pc + offset, true)},
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
        llvm::outs() << llvm::json::Value(Error("FRAME_TOO_LARGE", "frame exceeds 1 MiB")) << '\n';
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
