#include "branch_analysis.h"
#include <llvm/ADT/StringExtras.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <sstream>

namespace {
class BitVectorModel {
 public:
  std::string declarations, definitions;
  llvm::json::Array inputs;
  bool overapproximation=false;
  std::map<llvm::Value*,std::string> memo;
  unsigned next=0;

  std::string emit(llvm::Value *value) {
    if(!value->getType()->isIntegerTy()) return {};
    const auto width=value->getType()->getIntegerBitWidth();
    if(auto *constant=llvm::dyn_cast<llvm::ConstantInt>(value)) {
      llvm::SmallString<64> decimal;constant->getValue().toString(decimal,10,false);
      return "(_ bv"+decimal.str().str()+" "+std::to_string(width)+")";
    }
    if(memo.count(value))return memo[value];
    const auto name="n"+std::to_string(next++);
    memo[value]=name;
    std::string expression;
    if(auto *binary=llvm::dyn_cast<llvm::BinaryOperator>(value)) {
      const auto lhs=emit(binary->getOperand(0)),rhs=emit(binary->getOperand(1));
      std::string op;
      switch(binary->getOpcode()) {
        case llvm::Instruction::Add:op="bvadd";break;
        case llvm::Instruction::Sub:op="bvsub";break;
        case llvm::Instruction::Mul:op="bvmul";break;
        case llvm::Instruction::And:op="bvand";break;
        case llvm::Instruction::Or:op="bvor";break;
        case llvm::Instruction::Xor:op="bvxor";break;
        case llvm::Instruction::Shl:op="bvshl";break;
        case llvm::Instruction::LShr:op="bvlshr";break;
        case llvm::Instruction::AShr:op="bvashr";break;
        default:break;
      }
      if(!op.empty() && !lhs.empty() && !rhs.empty()) expression="("+op+" "+lhs+" "+rhs+")";
    } else if(auto *cast=llvm::dyn_cast<llvm::CastInst>(value)) {
      const auto source=emit(cast->getOperand(0));
      const auto from=cast->getOperand(0)->getType()->getIntegerBitWidth();
      if(!source.empty()) {
        if(cast->getOpcode()==llvm::Instruction::Trunc)expression="((_ extract "+std::to_string(width-1)+" 0) "+source+")";
        else if(cast->getOpcode()==llvm::Instruction::ZExt || cast->getOpcode()==llvm::Instruction::SExt)
          expression="((_ "+std::string(cast->getOpcode()==llvm::Instruction::ZExt?"zero_extend":"sign_extend")+" "+std::to_string(width-from)+") "+source+")";
      }
    } else if(auto *compare=llvm::dyn_cast<llvm::ICmpInst>(value)) {
      const auto lhs=emit(compare->getOperand(0)),rhs=emit(compare->getOperand(1));std::string op;
      switch(compare->getPredicate()) {
        case llvm::CmpInst::ICMP_EQ:op="=";break;case llvm::CmpInst::ICMP_NE:op="distinct";break;
        case llvm::CmpInst::ICMP_ULT:op="bvult";break;case llvm::CmpInst::ICMP_ULE:op="bvule";break;
        case llvm::CmpInst::ICMP_UGT:op="bvugt";break;case llvm::CmpInst::ICMP_UGE:op="bvuge";break;
        case llvm::CmpInst::ICMP_SLT:op="bvslt";break;case llvm::CmpInst::ICMP_SLE:op="bvsle";break;
        case llvm::CmpInst::ICMP_SGT:op="bvsgt";break;case llvm::CmpInst::ICMP_SGE:op="bvsge";break;
        default:break;
      }
      if(!op.empty() && !lhs.empty() && !rhs.empty())expression="(ite ("+op+" "+lhs+" "+rhs+") #b1 #b0)";
    } else if(auto *select=llvm::dyn_cast<llvm::SelectInst>(value)) {
      const auto condition=emit(select->getCondition()),yes=emit(select->getTrueValue()),no=emit(select->getFalseValue());
      if(!condition.empty() && !yes.empty() && !no.empty())expression="(ite (= "+condition+" #b1) "+yes+" "+no+")";
    }
    if(expression.empty()) {
      const bool input=llvm::isa<llvm::LoadInst>(value) || llvm::isa<llvm::Argument>(value) || llvm::isa<llvm::CallInst>(value);
      if(!input)overapproximation=true;
      if(auto *call=llvm::dyn_cast<llvm::CallInst>(value)) {
        // 未建模 guest 读取之间的内存关联；即使操作码全部支持，模型也仍为过近似。
        if(!call->getCalledFunction() || !call->getCalledFunction()->getName().starts_with("__remill_undefined_"))
          overapproximation=true;
      }
      declarations+="(declare-fun "+name+" () (_ BitVec "+std::to_string(width)+"))\n";
      std::string source;llvm::raw_string_ostream stream(source);value->print(stream);
      inputs.push_back(llvm::json::Object{{"name",name},{"width",int64_t(width)},{"source",stream.str()},
          {"abstracted",!input}});
    } else definitions+="(define-fun "+name+" () (_ BitVec "+std::to_string(width)+") "+expression+")\n";
    return name;
  }
};
}

llvm::json::Object AnalyzeBranch(llvm::Function &function) {
  llvm::SmallVector<llvm::CallInst*> exits;
  for(auto &instruction:llvm::instructions(function)) {
    auto *call=llvm::dyn_cast<llvm::CallInst>(&instruction);
    if(!call || !call->getCalledFunction())continue;
    const auto name=call->getCalledFunction()->getName();
    if(name=="__remill_jump" || name=="__remill_function_call" || name=="__remill_function_return")exits.push_back(call);
  }
  if(exits.empty())return llvm::json::Object{{"kind","unresolved"},{"reason","no-control-transfer"}};
  BitVectorModel model;
  std::string target;
  if(exits.size()==1)target=model.emit(exits.front()->getArgOperand(1));
  else if(exits.size()==2) {
    auto *branch=llvm::dyn_cast<llvm::BranchInst>(function.getEntryBlock().getTerminator());
    if(branch && branch->isConditional()) {
      llvm::CallInst *yes=nullptr,*no=nullptr;
      for(auto *call:exits) {
        if(call->getParent()==branch->getSuccessor(0))yes=call;
        if(call->getParent()==branch->getSuccessor(1))no=call;
      }
      if(yes && no) {
        const auto c=model.emit(branch->getCondition()),a=model.emit(yes->getArgOperand(1)),b=model.emit(no->getArgOperand(1));
        if(!c.empty()&&!a.empty()&&!b.empty())target="(ite (= "+c+" #b1) "+a+" "+b+")";
      }
    }
  }
  if(target.empty())return llvm::json::Object{{"kind","unresolved"},{"reason","unsupported-control-flow-shape"}};
  const unsigned width=exits.front()->getArgOperand(1)->getType()->getIntegerBitWidth();
  const auto smt="(set-option :produce-models true)\n(set-logic QF_BV)\n"+model.declarations+model.definitions+
      "(define-fun target () (_ BitVec "+std::to_string(width)+") "+target+")\n";
  auto *constant=exits.size()==1?llvm::dyn_cast<llvm::ConstantInt>(exits.front()->getArgOperand(1)):nullptr;
  llvm::json::Object result{{"kind",constant?"direct":"symbolic-indirect"},{"smt2",smt},
      {"target_width",int64_t(width)},{"inputs",std::move(model.inputs)},
      {"overapproximation",model.overapproximation},{"memory_inputs_independent",true},
      {"classification_scope","current-state-LLVM-bitvectors"}};
  if(constant) result["target"]="0x"+llvm::utohexstr(constant->getZExtValue(),true);
  return result;
}
