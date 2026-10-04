#include "pass_utils.h"
#include <map>
#include <set>
#include <sstream>
#include <fstream>

using namespace llvm;

namespace {

enum StateRole { ROLE_PRE = 0, ROLE_BARRIER = 1, ROLE_POST = 2 };

struct StateEntry {
    uint32_t state_id;
    std::string transition_id;
    StateRole role;
    std::string type;
    std::string file;
    uint32_t line;
    std::string function;
    int32_t bb_id;
};

struct StateHitPass : public PassInfoMixin<StateHitPass> {
    std::multimap<std::string, StateEntry> LocationToStates;

    StateHitPass() {
        const char *state_map_path = getenv("FTFUZZ_STATE_MAP");
        if (state_map_path) loadStateMap(state_map_path);
    }

    void loadStateMap(const std::string &path) {
        auto BufOrErr = MemoryBuffer::getFile(path);
        if (!BufOrErr) {
            errs() << "[StateHitPass] Failed to open " << path << "\n";
            return;
        }
        std::string content = BufOrErr.get()->getBuffer().str();
        std::istringstream iss(content);
        std::string line;
        bool header = true;
        uint32_t count = 0, barrier_count = 0;

        while (std::getline(iss, line)) {
            if (header) { header = false; continue; }
            if (line.empty()) continue;

            std::istringstream ls(line);
            std::string field;
            std::vector<std::string> fields;
            while (std::getline(ls, field, ',')) fields.push_back(field);
            if (fields.size() < 8) continue;

            StateEntry entry;
            entry.state_id = (uint32_t)std::stoul(fields[0]);
            entry.transition_id = fields[1];

            std::string role_str = fields[2];
            if (role_str == "pre") entry.role = ROLE_PRE;
            else if (role_str == "barrier") entry.role = ROLE_BARRIER;
            else if (role_str == "post") entry.role = ROLE_POST;
            else continue;

            entry.type = fields[3];
            entry.file = fields[4];
            entry.line = (uint32_t)std::stoul(fields[5]);
            entry.function = fields[6];
            entry.bb_id = (int32_t)std::stoi(fields[7]);

            std::string basename = entry.file;
            size_t slash = basename.find_last_of("/\\");
            if (slash != std::string::npos) basename = basename.substr(slash + 1);

            std::string key = basename + ":" + std::to_string(entry.line)
                              + ":" + entry.function;
            LocationToStates.insert({key, entry});
            count++;
            if (entry.role == ROLE_BARRIER) barrier_count++;
        }
        errs() << "[StateHitPass] Loaded " << count << " state map entries"
               << " (" << barrier_count << " barriers, "
               << (count - barrier_count) << " pre/post metadata-only)\n";
    }

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
        if (F.isDeclaration()) return PreservedAnalyses::all();
        if (LocationToStates.empty()) return PreservedAnalyses::all();

        std::string funcName = F.getName().str();
        SmallVector<std::pair<Instruction *, const StateEntry *>, 16> ToInstrument;

        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                SourceLocation loc = getSourceLocation(&I);
                if (loc.line == 0) continue;

                std::string basename = loc.file;
                size_t slash = basename.find_last_of("/\\");
                if (slash != std::string::npos) basename = basename.substr(slash + 1);

                std::string key = basename + ":" + std::to_string(loc.line)
                                  + ":" + funcName;

                auto range = LocationToStates.equal_range(key);
                for (auto it = range.first; it != range.second; ++it) {
                    /* Only instrument barriers. Pre/Post are metadata-only. */
                    if (it->second.role == ROLE_BARRIER)
                        ToInstrument.push_back({&I, &it->second});
                }
            }
        }

        if (ToInstrument.empty())
            return PreservedAnalyses::all();

        // Deduplicate by (state_id, BasicBlock*):
        // Multiple instructions at the same source line (common in switch-case
        // expansions like sqlite3's codeTriggerProgram) would otherwise cause
        // the same barrier to be instrumented many times at the same BB,
        // bloating the IR and crashing LLVM 14 codegen.
        //
        // Also limit each BB to MAX_BARRIERS_PER_BB barriers to avoid
        // overwhelming instruction selection in dense switch-patterned functions.
        {
            const unsigned MAX_BARRIERS_PER_BB = 2;
            std::set<std::pair<uint32_t, BasicBlock *>> seen;  // (state_id, BB) dedup
            std::map<BasicBlock *, unsigned> bb_count;          // per-BB cap
            SmallVector<std::pair<Instruction *, const StateEntry *>, 16> Deduplicated;
            unsigned skipped = 0;

            for (auto &pair : ToInstrument) {
                BasicBlock *BB = pair.first->getParent();
                uint32_t sid = pair.second->state_id;

                // Dedup: skip if this (state_id, BB) already instrumented
                auto key = std::make_pair(sid, BB);
                if (seen.find(key) != seen.end()) {
                    skipped++;
                    continue;
                }

                // Per-BB limit: skip if this BB already has enough barriers
                if (bb_count[BB] >= MAX_BARRIERS_PER_BB) {
                    skipped++;
                    continue;
                }

                seen.insert(key);
                bb_count[BB]++;
                Deduplicated.push_back(pair);
            }

            if (skipped > 0) {
                errs() << "[StateHitPass] Deduplicated " << ToInstrument.size()
                       << " → " << Deduplicated.size()
                       << " barriers (skipped " << skipped << ") in "
                       << F.getName() << "\n";
            }

            ToInstrument = std::move(Deduplicated);
        }

        Module *M = F.getParent();
        FunctionCallee RecordStateHit = getRecordStateHit(*M);
        FunctionCallee RecordBranchBarrier = getRecordBranchBarrier(*M);

        for (auto &pair : ToInstrument) {
            Instruction *I = pair.first;
            const StateEntry *entry = pair.second;

            if (entry->type == "branch" || entry->type == "branch_edge") {
                Instruction *Term = I->getParent()->getTerminator();
                if (auto *Br = dyn_cast<BranchInst>(Term)) {
                    if (Br->isConditional()) {
                        Value *Cond = Br->getCondition();
                        IRBuilder<> BrBuilder(Term);
                        Value *TargetTaken = BrBuilder.CreateZExt(
                            Cond, Type::getInt8Ty(M->getContext()));
                        Value *StateIdVal = ConstantInt::get(
                            Type::getInt32Ty(M->getContext()), entry->state_id);
                        BrBuilder.CreateCall(RecordBranchBarrier,
                                             {StateIdVal, TargetTaken});
                    } else {
                        IRBuilder<> BrBuilder(Term);
                        Value *StateIdVal = ConstantInt::get(
                            Type::getInt32Ty(M->getContext()), entry->state_id);
                        BrBuilder.CreateCall(RecordStateHit, {StateIdVal});
                    }
                }
                /* else: terminator is not a BranchInst (e.g. SwitchInst,
                   ReturnInst). Skip — branch-edge barriers cannot be
                   meaningfully instrumented on non-branch terminators, and
                   doing so can trigger LLVM 14 codegen crashes in functions
                   with large switch statements (e.g. sqlite3 codeTriggerProgram). */
            } else {
                /* BB-fallback barrier — instrument on BranchInst AND SwitchInst BBs
                   (switches compiled to jump tables are otherwise invisible barriers;
                   MAX_BARRIERS_PER_BB=2 cap prevents the original codegen crash). */
                Instruction *Term = I->getParent()->getTerminator();
                if (isa<BranchInst>(Term) || isa<SwitchInst>(Term)) {
                    IRBuilder<> Builder(I);
                    Value *StateIdVal = ConstantInt::get(
                        Type::getInt32Ty(M->getContext()), entry->state_id);
                    Builder.CreateCall(RecordStateHit, {StateIdVal});
                }
            }
        }

        errs() << "[StateHitPass] Instrumented " << ToInstrument.size()
               << " barriers in " << F.getName() << "\n";
        return PreservedAnalyses::none();
    }

    static bool isRequired() { return true; }
};

} // anonymous namespace

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "StateHitPass", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "state-hit") {
                        FPM.addPass(StateHitPass());
                        return true;
                    }
                    return false;
                });
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, llvm::OptimizationLevel) {
                    FunctionPassManager FPM;
                    FPM.addPass(StateHitPass());
                    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                });
        }
    };
}
