#include "pass_utils.h"

using namespace llvm;

namespace {

struct CmpBarrierPass : public PassInfoMixin<CmpBarrierPass> {
    uint32_t NextBarrierId = 0;

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
        if (F.isDeclaration()) return PreservedAnalyses::all();

        Module *M = F.getParent();
        FunctionCallee RecordCmp = getRecordCmp(*M);

        SmallVector<Instruction *, 16> ToInstrument;

        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                if (auto *Cmp = dyn_cast<CmpInst>(&I)) {
                    if (Cmp->getOperand(0)->getType()->isIntegerTy()) {
                        ToInstrument.push_back(Cmp);
                    }
                }
            }
        }

        for (Instruction *Cmp : ToInstrument) {
            uint32_t barrier_id = NextBarrierId++;

            auto *CmpI = cast<CmpInst>(Cmp);
            Value *LHS = CmpI->getOperand(0);
            Value *RHS = CmpI->getOperand(1);

            IRBuilder<> Builder(Cmp->getParent(), ++Cmp->getIterator());

            Value *LHS64 = Builder.CreateZExt(LHS, Type::getInt64Ty(M->getContext()));
            Value *RHS64 = Builder.CreateZExt(RHS, Type::getInt64Ty(M->getContext()));

            uint32_t predicate = (uint32_t)CmpI->getPredicate();
            Value *Outcome = Cmp;

            Value *Args[] = {
                ConstantInt::get(Type::getInt32Ty(M->getContext()), barrier_id),
                LHS64,
                RHS64,
                ConstantInt::get(Type::getInt32Ty(M->getContext()), predicate),
                Outcome,
            };
            Builder.CreateCall(RecordCmp, Args);
        }

        errs() << "[CmpBarrierPass] Instrumented " << ToInstrument.size()
               << " comparisons in " << F.getName() << "\n";

        return PreservedAnalyses::none();
    }

    static bool isRequired() { return true; }
};

} // anonymous namespace

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "CmpBarrierPass", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "cmp-barrier") {
                        FPM.addPass(CmpBarrierPass());
                        return true;
                    }
                    return false;
                });
        }
    };
}
