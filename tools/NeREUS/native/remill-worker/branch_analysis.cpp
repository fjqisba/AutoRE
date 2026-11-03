#include "branch_analysis.h"
#include <llvm/ADT/StringExtras.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <sstream>
#include <optional>
#include <set>

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

std::string Assumptions(llvm::Function &function,BitVectorModel &model) {
  std::string result;
  for(auto &instruction:llvm::instructions(function))if(auto *call=llvm::dyn_cast<llvm::CallInst>(&instruction))
    if(call->getCalledFunction() && call->getCalledFunction()->getIntrinsicID()==llvm::Intrinsic::assume)
      result+="(assert (= "+model.emit(call->getArgOperand(0))+" #b1))\n";
  return result;
}

llvm::Value *EntryStack(llvm::Function &function) {
  auto *metadata=function.getMetadata("nereus.rsp.layout");
  auto *offset=metadata && metadata->getNumOperands()==1
      ?llvm::mdconst::dyn_extract<llvm::ConstantInt>(metadata->getOperand(0)):nullptr;
  if(!offset || function.size()!=1)return nullptr;
  const auto &layout=function.getParent()->getDataLayout();
  for(auto &instruction:llvm::instructions(function))if(auto *load=llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
    int64_t actual=0;
    if(load->isSimple() && load->getType()->isIntegerTy(64)
        && llvm::GetPointerBaseWithConstantOffset(load->getPointerOperand(),actual,layout)==function.getArg(0)
        && uint64_t(actual)==offset->getZExtValue())return load;
  }
  return nullptr;
}

bool SimpleStack(llvm::Value *value,llvm::Value *stack) {
  if(value==stack)return true;
  auto *binary=llvm::dyn_cast<llvm::BinaryOperator>(value);
  return binary && (binary->getOpcode()==llvm::Instruction::Add || binary->getOpcode()==llvm::Instruction::Sub)
      && llvm::isa<llvm::ConstantInt>(binary->getOperand(1)) && SimpleStack(binary->getOperand(0),stack);
}

// 在 RSP=0 处求候选偏移只用于猜候选；随后必须证明所有 64 位 RSP 都等价。
std::optional<llvm::APInt> EvaluateAtZeroImpl(llvm::Value *value,llvm::Value *stack,
    std::map<llvm::Value*,std::optional<llvm::APInt>> &memo,unsigned budget=512) {
  if(!budget || !value->getType()->isIntegerTy())return {};
  if(memo.count(value))return memo[value];
  if(memo.size()>=2048)return {};
  memo[value]={};
  auto evaluate=[&](llvm::Value *operand){return EvaluateAtZeroImpl(operand,stack,memo,budget-1);};
  auto compute=[&]() ->std::optional<llvm::APInt> {
  if(value==stack)return llvm::APInt(64,0);
  if(auto *constant=llvm::dyn_cast<llvm::ConstantInt>(value))return constant->getValue();
  if(auto *binary=llvm::dyn_cast<llvm::BinaryOperator>(value)) {
    auto a=evaluate(binary->getOperand(0));if(!a)return {};
    auto b=evaluate(binary->getOperand(1));
    if(!a || !b)return {};
    switch(binary->getOpcode()) {
      case llvm::Instruction::Add:return *a+*b;case llvm::Instruction::Sub:return *a-*b;
      case llvm::Instruction::Mul:return *a**b;case llvm::Instruction::And:return *a&*b;
      case llvm::Instruction::Or:return *a|*b;case llvm::Instruction::Xor:return *a^*b;
      case llvm::Instruction::Shl:if(b->uge(a->getBitWidth()))return {};return a->shl(b->getZExtValue());
      case llvm::Instruction::LShr:if(b->uge(a->getBitWidth()))return {};return a->lshr(b->getZExtValue());
      case llvm::Instruction::AShr:if(b->uge(a->getBitWidth()))return {};return a->ashr(b->getZExtValue());
      default:return {};
    }
  }
  if(auto *cast=llvm::dyn_cast<llvm::CastInst>(value)) {
    auto source=evaluate(cast->getOperand(0));if(!source)return {};
    const auto width=cast->getType()->getIntegerBitWidth();
    switch(cast->getOpcode()) {
      case llvm::Instruction::Trunc:return source->trunc(width);
      case llvm::Instruction::ZExt:return source->zext(width);
      case llvm::Instruction::SExt:return source->sext(width);
      default:return {};
    }
  }
  return {};
  };
  return memo[value]=compute();
}
std::optional<llvm::APInt> EvaluateAtZero(llvm::Value *value,llvm::Value *stack) {
  std::map<llvm::Value*,std::optional<llvm::APInt>> memo;
  return EvaluateAtZeroImpl(value,stack,memo);
}

struct StackCandidate {llvm::Value *value;uint64_t offset;std::string id,smt;};
std::vector<StackCandidate> StackCandidates(llvm::Function &function,llvm::Value *stack) {
  std::vector<StackCandidate> result;std::set<llvm::Value*> seen;
  if(!stack)return result;
  for(auto &instruction:llvm::instructions(function)) {
    auto *call=llvm::dyn_cast<llvm::CallInst>(&instruction);
    if(!call || !call->getCalledFunction() || call->arg_size()<2)continue;
    auto name=call->getCalledFunction()->getName();
    if(!name.starts_with("__remill_read_memory_") && !name.starts_with("__remill_write_memory_"))continue;
    auto *value=call->getArgOperand(1);
    if(!value->getType()->isIntegerTy(64) || llvm::isa<llvm::ConstantInt>(value)
        || !seen.insert(value).second || SimpleStack(value,stack))continue;
    auto offset=EvaluateAtZero(value,stack);
    if(!offset || offset->getBitWidth()!=64)continue;
    BitVectorModel model;model.memo[stack]="entry_rsp";
    model.declarations="(declare-fun entry_rsp () (_ BitVec 64))\n";
    auto target=model.emit(value);
    if(target.empty() || !model.inputs.empty() || model.overapproximation)continue;
    const auto smt="(set-logic QF_BV)\n"+model.declarations+model.definitions+
        "(assert (distinct "+target+" (bvadd entry_rsp (_ bv"+std::to_string(offset->getZExtValue())+" 64))))\n(check-sat)\n";
    const auto hash=llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t*>(smt.data()),smt.size()));
    result.push_back({value,offset->getZExtValue(),llvm::toHex(llvm::ArrayRef<uint8_t>(hash),true),smt});
  }
  return result;
}
}

llvm::json::Array AnalyzeStackAddresses(llvm::Function &function) {
  llvm::json::Array result;
  for(auto &candidate:StackCandidates(function,EntryStack(function))) {
    std::string text;llvm::raw_string_ostream stream(text);candidate.value->print(stream);
    result.push_back(llvm::json::Object{{"id",candidate.id},{"offset",int64_t(candidate.offset)},
        {"smt2",candidate.smt},{"expression",stream.str()}});
  }
  return result;
}

unsigned NormalizeStackAddresses(llvm::Function &function,const llvm::json::Array *proofs) {
  if(!proofs || proofs->empty())return 0;
  std::set<std::string> approved;
  for(auto &proof:*proofs)if(auto id=proof.getAsString())approved.insert(id->str());
  auto *stack=EntryStack(function);unsigned count=0;
  for(auto &candidate:StackCandidates(function,stack)) {
    if(!approved.count(candidate.id))continue;
    auto *instruction=llvm::dyn_cast<llvm::Instruction>(candidate.value);if(!instruction)continue;
    auto *normalized=llvm::IRBuilder<>(instruction).CreateAdd(stack,
        llvm::ConstantInt::get(stack->getType(),candidate.offset),"stack.proven");
    candidate.value->replaceAllUsesWith(normalized);++count;
  }
  return count;
}

std::string ReadAddressId(llvm::Value *address,unsigned width) {
  BitVectorModel model;auto target=model.emit(address);
  auto *instruction=llvm::dyn_cast<llvm::Instruction>(address);
  const auto assumptions=instruction?Assumptions(*instruction->getFunction(),model):std::string();
  const auto text=model.declarations+model.definitions+target+assumptions+std::to_string(width);
  const auto hash=llvm::SHA256::hash(llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t*>(text.data()),text.size()));
  return llvm::toHex(llvm::ArrayRef<uint8_t>(hash),true);
}

llvm::json::Array AnalyzeReadAddresses(llvm::Function &function) {
  llvm::json::Array result;std::set<std::string> seen;
  for(auto &instruction:llvm::instructions(function)) {
    auto *call=llvm::dyn_cast<llvm::CallInst>(&instruction);
    if(!call || !call->getCalledFunction() || call->arg_size()!=2)continue;
    auto name=call->getCalledFunction()->getName();
    if(!name.consume_front("__remill_read_memory_"))continue;
    unsigned width=0;if(name.getAsInteger(10,width) || (width!=8 && width!=16 && width!=32 && width!=64))continue;
    auto *address=call->getArgOperand(1);
    if(llvm::isa<llvm::ConstantInt>(address))continue;
    const auto id=ReadAddressId(address,width);if(!seen.insert(id).second)continue;
    BitVectorModel model;auto target=model.emit(address);if(target.empty())continue;
    const auto assumptions=Assumptions(function,model);
    result.push_back(llvm::json::Object{{"id",id},{"width_bits",int64_t(width)},
        {"kind","symbolic-indirect"},{"target_width",64},{"overapproximation",model.overapproximation},
        {"inputs",std::move(model.inputs)},
        {"smt2","(set-option :produce-models true)\n(set-logic QF_BV)\n"+model.declarations+model.definitions+
          "(define-fun target () (_ BitVec 64) "+target+")\n"+assumptions}});
  }
  return result;
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
  const auto assumptions=Assumptions(function,model);
  const unsigned width=exits.front()->getArgOperand(1)->getType()->getIntegerBitWidth();
  const auto smt="(set-option :produce-models true)\n(set-logic QF_BV)\n"+model.declarations+model.definitions+
      "(define-fun target () (_ BitVec "+std::to_string(width)+") "+target+")\n"+assumptions;
  auto *constant=exits.size()==1?llvm::dyn_cast<llvm::ConstantInt>(exits.front()->getArgOperand(1)):nullptr;
  llvm::json::Object result{{"kind",constant?"direct":"symbolic-indirect"},{"smt2",smt},
      {"target_width",int64_t(width)},{"inputs",std::move(model.inputs)},
      {"overapproximation",model.overapproximation},{"memory_inputs_independent",true},
      {"classification_scope","current-state-LLVM-bitvectors"}};
  if(constant) result["target"]="0x"+llvm::utohexstr(constant->getZExtValue(),true);
  return result;
}
