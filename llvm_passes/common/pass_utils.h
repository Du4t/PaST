#ifndef PASS_UTILS_H
#define PASS_UTILS_H

#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "source_location.h"
#include <string>

using namespace llvm;

static SourceLocation getSourceLocation(Instruction *I) {
    SourceLocation loc;
    const DebugLoc &DL = I->getDebugLoc();
    if (DL) {
        loc.line = DL.getLine();
        if (auto *Scope = cast_or_null<DIScope>(DL.getScope())) {
            loc.file = Scope->getFilename().str();
            loc.function = Scope->getName().str();
        }
    }
    return loc;
}

static FunctionCallee getRecordCmp(Module &M) {
    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(M.getContext()),
        {
            Type::getInt32Ty(M.getContext()),
            Type::getInt64Ty(M.getContext()),
            Type::getInt64Ty(M.getContext()),
            Type::getInt32Ty(M.getContext()),
            Type::getInt32Ty(M.getContext()),
        },
        false
    );
    return M.getOrInsertFunction("__fuzz_rt_record_cmp", FT);
}

static FunctionCallee getRecordBB(Module &M) {
    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(M.getContext()),
        {
            Type::getInt32Ty(M.getContext()),
            Type::getInt32Ty(M.getContext()),
        },
        false
    );
    return M.getOrInsertFunction("__fuzz_rt_record_bb", FT);
}

static FunctionCallee getRecordStateHit(Module &M) {
    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(M.getContext()),
        {Type::getInt32Ty(M.getContext())},
        false
    );
    return M.getOrInsertFunction("__fuzz_rt_record_state_hit", FT);
}

static FunctionCallee getRecordPreHit(Module &M) {
    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(M.getContext()),
        {Type::getInt32Ty(M.getContext())},
        false
    );
    return M.getOrInsertFunction("__fuzz_rt_record_pre_hit", FT);
}

static FunctionCallee getRecordPostHit(Module &M) {
    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(M.getContext()),
        {Type::getInt32Ty(M.getContext())},
        false
    );
    return M.getOrInsertFunction("__fuzz_rt_record_post_hit", FT);
}

static FunctionCallee getRecordBarrierHit(Module &M) {
    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(M.getContext()),
        {Type::getInt32Ty(M.getContext())},
        false
    );
    return M.getOrInsertFunction("__fuzz_rt_record_barrier_hit", FT);
}

static FunctionCallee getRecordBranchBarrier(Module &M) {
    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(M.getContext()),
        {
            Type::getInt32Ty(M.getContext()),
            Type::getInt8Ty(M.getContext()),
        },
        false
    );
    return M.getOrInsertFunction("__fuzz_rt_record_branch_barrier", FT);
}

static FunctionCallee getRecordSnapshot(Module &M) {
    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(M.getContext()),
        {
            Type::getInt32Ty(M.getContext()),
            Type::getInt32Ty(M.getContext()),
            Type::getInt64Ty(M.getContext()),
        },
        false
    );
    return M.getOrInsertFunction("__fuzz_rt_record_snapshot", FT);
}

#endif
