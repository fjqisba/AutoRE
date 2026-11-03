#pragma once
#include <llvm/Support/JSON.h>
namespace llvm { class Function; }
llvm::json::Object AnalyzeBranch(llvm::Function &function);
