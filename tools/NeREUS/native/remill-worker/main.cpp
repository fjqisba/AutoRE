#include <glog/logging.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include <filesystem>
#include <iostream>
#include <string>

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
  if (*operation == "hello") {
    return llvm::json::Object{{"protocol_version", kProtocolVersion}, {"ok", true},
            {"provider", "remill"}, {"revision", NEREUS_REMILL_REVISION},
            {"llvm", LLVM_VERSION_STRING}, {"nir_import", false},
            {"capabilities", llvm::json::Array{"decode-one", "lift-one-bitcode"}},
            {"architectures", llvm::json::Array{"x86", "amd64"}}};
  }
  if (*operation != "lift-one") return Error("INVALID_OPERATION", "unknown op");

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
  if (hex->empty() || hex->size() > 30 || hex->size() % 2)
    return Error("INVALID_BYTES", "provide one instruction, up to 15 bytes");
  std::string bytes;
  for (size_t index = 0; index < hex->size(); index += 2) {
    unsigned byte = 0;
    if (hex->substr(index, 2).getAsInteger(16, byte))
      return Error("INVALID_BYTES", "invalid hex encoding");
    bytes.push_back(static_cast<char>(byte));
  }
  const auto semantics_path = std::filesystem::u8path(semantics->str());
  if (!std::filesystem::is_regular_file(semantics_path / (architecture->str() + ".bc")))
    return Error("SEMANTICS_PROVIDER_MISSING", "semantics bitcode not found");

  llvm::LLVMContext context;
  auto arch = remill::Arch::Get(context, "windows", architecture->str());
  if (!arch) return Error("UNSUPPORTED_ARCHITECTURE", "Remill architecture unavailable");
  auto module = remill::LoadArchSemantics(arch.get(), {semantics_path});
  remill::Instruction instruction;
  if (!arch->DecodeInstruction(pc, bytes, instruction, arch->CreateInitialContext()))
    return Error("UNSUPPORTED_INSN", "Remill failed to decode instruction");
  if (instruction.bytes.size() != bytes.size())
    return Error("INVALID_BYTES", "expected exactly one complete instruction");

  remill::IntrinsicTable intrinsics(module.get());
  auto function = arch->DefineLiftedFunction("nereus_lifted_instruction", module.get());
  auto block = &function->getEntryBlock();
  const auto status = instruction.GetLifter()->LiftIntoBlock(instruction, block);
  if (status != remill::kLiftedInstruction)
    return Error("SEMANTICS_GAP", "Remill decoded but could not lift instruction");
  // 仅提供单指令状态转换，不将其包装成已恢复的 guest 函数控制流。
  auto memory = remill::LoadMemoryPointer(block, intrinsics);
  llvm::IRBuilder<> builder(block);
  builder.CreateRet(memory);
  std::string diagnostic;
  llvm::raw_string_ostream diagnostics(diagnostic);
  if (llvm::verifyModule(*module, &diagnostics))
    return Error("IR_INVALID", diagnostics.str());

  std::error_code ec;
  auto output_path = std::filesystem::u8path(output->str());
  std::filesystem::create_directories(output_path, ec);
  if (ec) return Error("OUTPUT_ERROR", ec.message());
  const auto bc_path = output_path / "instruction.bc";
  const auto ll_path = output_path / "instruction.ll";
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
          {"length", static_cast<int64_t>(instruction.bytes.size())},
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
