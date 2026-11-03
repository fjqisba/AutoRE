#pragma once
#include <llvm/Support/JSON.h>
namespace llvm { class Function; class Value; }
llvm::json::Object AnalyzeBranch(llvm::Function &function);
llvm::json::Array AnalyzeStackAddresses(llvm::Function &function);
unsigned NormalizeStackAddresses(llvm::Function &function, const llvm::json::Array *proofs);
llvm::json::Array AnalyzeReadAddresses(llvm::Function &function);
std::string ReadAddressId(llvm::Value *address, unsigned width);
