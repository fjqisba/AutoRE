#pragma once
#include <llvm/Support/JSON.h>

// 对局部 Remill IR 做带明确观察模型的语义化简，原始提升产物始终保留。
llvm::json::Object OptimizeLocalBlock(const llvm::json::Object &request);
