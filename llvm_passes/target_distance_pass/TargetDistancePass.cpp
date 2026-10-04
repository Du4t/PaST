#include "pass_utils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/InstrTypes.h"
#include <set>
#include <unordered_map>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>

using namespace llvm;

namespace {

/// Allocate a globally unique BB ID range using a shared counter file.
/// This ensures that parallel compilation units (separate compiler processes)
/// get non-overlapping BB ID ranges, avoiding ID collisions in bb_map.csv.
static uint32_t allocateGlobalBBIdRange(const std::string &counter_path,
                                         uint32_t count) {
    size_t slash = counter_path.rfind('/');
    if (slash != std::string::npos) {
        sys::fs::create_directories(counter_path.substr(0, slash));
    }

    int fd = open(counter_path.c_str(), O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        errs() << "[TargetDistancePass] WARNING: Cannot open BB ID counter "
               << counter_path << ", using local IDs\n";
        return 0;
    }

    flock(fd, LOCK_EX);

    uint32_t current = 0;
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        current = (uint32_t)strtoul(buf, nullptr, 10);
    }

    uint32_t start = current;
    current += count;

    lseek(fd, 0, SEEK_SET);
    (void)ftruncate(fd, 0);
    (void)write(fd, buf, snprintf(buf, sizeof(buf), "%u", current));

    flock(fd, LOCK_UN);
    close(fd);

    return start;
}

struct TargetDistancePass : public PassInfoMixin<TargetDistancePass> {
    DenseMap<uint32_t, uint32_t> BBDistance;
    uint32_t NextBBId = 0;
    uint32_t BBIdOffset = 0;
    std::string BBMapPath;
    std::string CFGPath;
    std::string CallsPath;
    std::string BranchesPath;
    std::string CounterPath;
    std::vector<std::string> BBMapEntries;
    std::vector<std::string> CFGEdges;
    std::vector<std::string> CallEdges;
    std::vector<std::string> BranchEntries;
    static std::set<std::pair<std::string, std::string>> FuncCallGraph;
    static bool CallGraphWritten;
    std::string OutputDir;
    uint32_t NextBranchId = 0;

    DenseMap<BasicBlock *, uint32_t> BBToId;
    DenseMap<StringRef, uint32_t> FuncEntryId;

    // Pass 2: map from "file:line:function" to BB ID (loaded from bb_map.csv)
    std::unordered_map<std::string, uint32_t> LocationToBBId;

    bool ShouldWriteMapAndCFG;
    bool BBIdsAllocated = false;

    TargetDistancePass() {
        const char *csv_path = getenv("DGF_DISTANCE_FILE");
        if (!csv_path) csv_path = getenv("FTFUZZ_BB_DISTANCE_CSV");
        // Fallback: check common locations
        if (!csv_path || !*csv_path) {
            const char *dgf_dir = getenv("FTFUZZ_DGF_DIR");
            if (!dgf_dir) dgf_dir = getenv("DGF_DIR");  // try alternate env var
            if (!dgf_dir) {
                // Pass1 (write-map): no distance file, skip loading, generate bb_map to /tmp/ftfuzz_dgf
                ShouldWriteMapAndCFG = true;
                OutputDir = "/tmp/ftfuzz_dgf";
            }
            static std::string default_path;
            if (dgf_dir) {
                default_path = std::string(dgf_dir) + "/bb_distance_full.csv";
                if (FILE *f = fopen(default_path.c_str(), "r")) { fclose(f); csv_path = default_path.c_str(); }
                else {
                    // Pass1: distance file doesn't exist yet, skip loading
                    ShouldWriteMapAndCFG = true;
                    OutputDir = "/tmp/ftfuzz_dgf";
                }
            }
        }
        if (csv_path && *csv_path) {
            loadDistanceCSV(csv_path);
        }

        ShouldWriteMapAndCFG = BBDistance.empty();

        const char *dgf_dir_env = getenv("FTFUZZ_DGF_DIR");
        if (!dgf_dir_env) dgf_dir_env = getenv("DGF_DIR");
        OutputDir = dgf_dir_env ? dgf_dir_env : "/tmp/ftfuzz_dgf";
        const char *map_path = getenv("FTFUZZ_BB_MAP_FILE");
        if (map_path) {
            BBMapPath = map_path;
            size_t last_slash = BBMapPath.rfind('/');
            if (last_slash != std::string::npos)
                OutputDir = BBMapPath.substr(0, last_slash);
        } else if (csv_path) {
            size_t last_slash = std::string(csv_path).rfind('/');
            if (last_slash != std::string::npos)
                OutputDir = std::string(csv_path).substr(0, last_slash);
            BBMapPath = OutputDir + "/bb_map.csv";
        } else {
            BBMapPath = OutputDir + "/bb_map.csv";
        }

        CFGPath = OutputDir + "/bb_cfg.csv";
        CallsPath = OutputDir + "/bb_calls.csv";
        BranchesPath = OutputDir + "/bb_branches.csv";
        CounterPath = OutputDir + "/bb_id_counter.txt";

        // In Pass 2, load bb_map.csv to build location -> BB ID mapping
        if (!ShouldWriteMapAndCFG) {
            loadBBMap(BBMapPath);
        }
    }

    void loadDistanceCSV(const std::string &path) {
        errs() << "[TargetDistancePass] Loading distance from " << path << "\n";
        auto BufOrErr = MemoryBuffer::getFile(path);
        if (!BufOrErr) {
            errs() << "[TargetDistancePass] Failed to open " << path << "\n";
            return;
        }
        std::string content = BufOrErr.get()->getBuffer().str();
        size_t pos = 0;
        while (pos < content.size()) {
            size_t nl = content.find('\n', pos);
            if (nl == std::string::npos) nl = content.size();
            std::string line = content.substr(pos, nl - pos);
            pos = nl + 1;
            if (line.empty() || line[0] == '#') continue;
            size_t comma = line.find(',');
            if (comma == std::string::npos) continue;
            try {
                uint32_t bb_id = (uint32_t)std::stoul(line.substr(0, comma));
                double raw_dist = std::stod(line.substr(comma + 1));
                uint32_t scaled;
                if (std::isinf(raw_dist) || std::isnan(raw_dist) || raw_dist < 0.0) {
                    scaled = 0xFFFFFFFFU;  // DGF_INF_DISTANCE — skip unreachable/negative BBs
                } else {
                    scaled = (uint32_t)(raw_dist * 100.0 + 0.5);  /* AFLGo scale: ×100 */
                }
                if (scaled != 0xFFFFFFFFU) {
                    BBDistance[bb_id] = scaled;
                }
            } catch (...) {
                continue;
            }
        }
        errs() << "[TargetDistancePass] Loaded " << BBDistance.size()
               << " BB distance entries\n";
    }

    void loadBBMap(const std::string &path) {
        errs() << "[TargetDistancePass] Loading BB map from " << path << "\n";
        auto BufOrErr = MemoryBuffer::getFile(path);
        if (!BufOrErr) {
            errs() << "[TargetDistancePass] Failed to open " << path << "\n";
            return;
        }
        std::string content = BufOrErr.get()->getBuffer().str();
        size_t pos = 0;
        bool first_line = true;
        unsigned loaded = 0;
        while (pos < content.size()) {
            size_t nl = content.find('\n', pos);
            if (nl == std::string::npos) nl = content.size();
            std::string line = content.substr(pos, nl - pos);
            pos = nl + 1;
            if (first_line) { first_line = false; continue; }
            if (line.empty()) continue;

            size_t c1 = line.find(',');
            if (c1 == std::string::npos) continue;
            size_t c2 = line.find(',', c1 + 1);
            if (c2 == std::string::npos) continue;
            size_t c3 = line.find(',', c2 + 1);
            if (c3 == std::string::npos) continue;

            try {
                uint32_t bb_id = (uint32_t)std::stoul(line.substr(0, c1));
                std::string file = line.substr(c1 + 1, c2 - c1 - 1);
                std::string line_str = line.substr(c2 + 1, c3 - c2 - 1);
                std::string func = line.substr(c3 + 1);

                if (!file.empty() && line_str != "0") {
                    std::string key = file + ":" + line_str + ":" + func;
                    if (LocationToBBId.find(key) == LocationToBBId.end()) {
                        LocationToBBId[key] = bb_id;
                        loaded++;
                    }
                }
            } catch (...) {
                continue;
            }
        }
        errs() << "[TargetDistancePass] Loaded " << loaded
               << " location -> BB ID mappings\n";
    }

    void writeOutputFiles() {
        if (!ShouldWriteMapAndCFG) return;

        size_t last_slash = BBMapPath.rfind('/');
        if (last_slash != std::string::npos) {
            sys::fs::create_directories(BBMapPath.substr(0, last_slash));
        }

        if (!BBMapEntries.empty()) {
            bool file_exists = sys::fs::exists(BBMapPath);
            std::error_code EC;
            raw_fd_ostream OS(BBMapPath, EC, sys::fs::OF_Append);
            if (!EC) {
                if (!file_exists) OS << "bb_id,file,line,function\n";
                for (const auto &entry : BBMapEntries) OS << entry << "\n";
                OS.close();
                errs() << "[TargetDistancePass] Appended " << BBMapEntries.size()
                       << " BB map entries to " << BBMapPath << "\n";
            }
        }

        if (!CFGEdges.empty()) {
            bool file_exists = sys::fs::exists(CFGPath);
            std::error_code EC;
            raw_fd_ostream OS(CFGPath, EC, sys::fs::OF_Append);
            if (!EC) {
                if (!file_exists) OS << "src_bb_id,dst_bb_id\n";
                for (const auto &entry : CFGEdges) OS << entry << "\n";
                OS.close();
                errs() << "[TargetDistancePass] Appended " << CFGEdges.size()
                       << " CFG edges to " << CFGPath << "\n";
            }
        }

        if (!CallEdges.empty()) {
            bool file_exists = sys::fs::exists(CallsPath);
            std::error_code EC;
            raw_fd_ostream OS(CallsPath, EC, sys::fs::OF_Append);
            if (!EC) {
                if (!file_exists) OS << "src_bb_id,called_function\n";
                for (const auto &entry : CallEdges) OS << entry << "\n";
                OS.close();
                errs() << "[TargetDistancePass] Appended " << CallEdges.size()
                       << " call edges to " << CallsPath << "\n";
            }
        }

        if (!BranchEntries.empty()) {
            bool file_exists = sys::fs::exists(BranchesPath);
            std::error_code EC;
            raw_fd_ostream OS(BranchesPath, EC, sys::fs::OF_Append);
            if (!EC) {
                if (!file_exists) OS << "branch_id,src_bb_id,true_dst_bb_id,false_dst_bb_id,file,line,column,function,condition_kind\n";
                for (const auto &entry : BranchEntries) OS << entry << "\n";
                OS.close();
                errs() << "[TargetDistancePass] Appended " << BranchEntries.size()
                       << " branch records to " << BranchesPath << "\n";
            }
        }

    }

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
        if (F.isDeclaration()) return PreservedAnalyses::all();

        Module *M = F.getParent();

        FunctionCallee RecordDist = M->getOrInsertFunction(
            "__dgf_record_bb_distance",
            FunctionType::get(
                Type::getVoidTy(M->getContext()),
                {
                    Type::getInt32Ty(M->getContext()),
                    Type::getInt32Ty(M->getContext()),
                },
                false
            )
        );

        // On first function, allocate a global BB ID range for this
        // compilation unit using a file-locked counter.
        if (!BBIdsAllocated) {
            BBIdsAllocated = true;
            if (ShouldWriteMapAndCFG) {
                BBIdOffset = allocateGlobalBBIdRange(CounterPath, 100000);
                errs() << "[TargetDistancePass] Allocated global BB ID range: "
                       << BBIdOffset << " - " << (BBIdOffset + 99999) << "\n";
            }
        }

        // First pass: assign BB IDs and record source locations
        uint32_t funcEntryId = NextBBId;
        for (BasicBlock &BB : F) {
            uint32_t local_id = NextBBId++;
            uint32_t bb_id = BBIdOffset + local_id;
            BBToId[&BB] = bb_id;

            // Record source location
            std::string file = "";
            unsigned line = 0;
            std::string func = F.getName().str();

            for (Instruction &I : BB) {
                SourceLocation loc = getSourceLocation(&I);
                if (loc.line != 0) {
                    file = loc.file;
                    line = loc.line;
                    func = loc.function.empty() ? func : loc.function;
                    break;
                }
            }

            // In Pass 2: look up BB ID from bb_map.csv by source location
            uint32_t distance = 0xFFFFFFFF;
            if (!ShouldWriteMapAndCFG && !file.empty() && line != 0) {
                std::string key = file + ":" + std::to_string(line) + ":" + func;
                auto it = LocationToBBId.find(key);
                if (it != LocationToBBId.end()) {
                    bb_id = it->second;
                    BBToId[&BB] = bb_id;
                    auto dist_it = BBDistance.find(bb_id);
                    if (dist_it != BBDistance.end()) {
                        distance = dist_it->second;
                    }
                }
            }

            if (ShouldWriteMapAndCFG) {
                std::string map_entry = std::to_string(bb_id) + "," +
                                        file + "," +
                                        std::to_string(line) + "," +
                                        func;
                BBMapEntries.push_back(map_entry);
            }

            // Instrument: call __dgf_record_bb_distance(bb_id, distance)
            Instruction *InsertPt = &*BB.getFirstInsertionPt();
            IRBuilder<> Builder(InsertPt);
            Value *Args[] = {
                ConstantInt::get(Type::getInt32Ty(M->getContext()), bb_id),
                ConstantInt::get(Type::getInt32Ty(M->getContext()), distance),
            };
            Builder.CreateCall(RecordDist, Args);
        }

        // Record function entry BB ID
        if (ShouldWriteMapAndCFG) {
            FuncEntryId[F.getName()] = BBIdOffset + funcEntryId;
        }

        // Second pass: record CFG edges and call edges
        if (ShouldWriteMapAndCFG) {
            for (BasicBlock &BB : F) {
                uint32_t src_id = BBToId[&BB];

                for (BasicBlock *Succ : successors(&BB)) {
                    auto it = BBToId.find(Succ);
                    if (it != BBToId.end()) {
                        CFGEdges.push_back(std::to_string(src_id) + "," +
                                           std::to_string(it->second));
                    }
                }

                // Record branch metadata for conditional terminators
                Instruction *Term = BB.getTerminator();
                if (auto *Br = dyn_cast<BranchInst>(Term)) {
                    if (Br->isConditional()) {
                        BasicBlock *TrueBB = Br->getSuccessor(0);
                        BasicBlock *FalseBB = Br->getSuccessor(1);
                        auto true_it = BBToId.find(TrueBB);
                        auto false_it = BBToId.find(FalseBB);
                        if (true_it != BBToId.end() && false_it != BBToId.end()) {
                            uint32_t bid = NextBranchId++;
                            std::string bfile = "", bfunc = F.getName().str();
                            unsigned bline = 0, bcol = 0;
                            SourceLocation bloc = getSourceLocation(Term);
                            if (bloc.line != 0) {
                                bfile = bloc.file;
                                bline = bloc.line;
                                bfunc = bloc.function.empty() ? bfunc : bloc.function;
                            }
                            std::string cond_kind = "unknown";
                            Value *Cond = Br->getCondition();
                            if (auto *CmpI = dyn_cast<CmpInst>(Cond))
                                cond_kind = CmpI->getPredicateName(CmpI->getPredicate()).str();
                            else if (isa<LoadInst>(Cond))
                                cond_kind = "load_test";
                            BranchEntries.push_back(
                                std::to_string(bid) + "," +
                                std::to_string(src_id) + "," +
                                std::to_string(true_it->second) + "," +
                                std::to_string(false_it->second) + "," +
                                bfile + "," + std::to_string(bline) + "," +
                                std::to_string(bcol) + "," + bfunc + "," +
                                cond_kind);
                        }
                    }
                }

                for (Instruction &I : BB) {
                    if (auto *CallI = dyn_cast<CallInst>(&I)) {
                        Function *Callee = CallI->getCalledFunction();
                        if (Callee && Callee->getName().size() > 0) {
                            CallEdges.push_back(std::to_string(src_id) + "," +
                                                Callee->getName().str());
                        }
                    }
                }
            }

            /* ---- Function-level call graph (like opt -dot-callgraph) ---- */
            if (ShouldWriteMapAndCFG) {
                std::string callerName = F.getName().str();
                for (BasicBlock &BB : F) {
                    for (Instruction &I : BB) {
                        CallInst *CII = dyn_cast<CallInst>(&I);
                    if (CII) {
                        Function *Callee = CII->getCalledFunction();
                        if (Callee && Callee->getName().size() > 0)
                            FuncCallGraph.insert({callerName, Callee->getName().str()});
                    }
                    }
                }
            }
        }

        return PreservedAnalyses::none();
    }

    ~TargetDistancePass() {
        writeOutputFiles();
        // Write callgraph once, at very end (atexit ensures all TUs are done)
        if (!CallGraphWritten && !FuncCallGraph.empty()) {
            static bool atexit_registered = false;
            if (!atexit_registered) {
                atexit_registered = true;
                std::atexit([]() {
                    CallGraphWritten = true;
                    std::string CgPath = "/tmp/ftfuzz_dgf/callgraph.csv";
                    // Try env-based path first
                    const char *map_path = getenv("FTFUZZ_BB_MAP_FILE");
                    if (map_path) {
                        std::string s(map_path);
                        size_t sl = s.rfind('/');
                        if (sl != std::string::npos)
                            CgPath = s.substr(0, sl) + "/callgraph.csv";
                    }
                    std::error_code EC;
                    raw_fd_ostream OS(CgPath, EC);
                    if (!EC) {
                        OS << "caller,callee\n";
                        for (const auto &edge : FuncCallGraph)
                            OS << edge.first << "," << edge.second << "\n";
                        OS.close();
                        errs() << "[TargetDistancePass] Wrote " << FuncCallGraph.size()
                               << " function-level callgraph edges to " << CgPath << "\n";
                    }
                });
            }
        }
    }

    static bool isRequired() { return true; }
};

} // anonymous namespace

std::set<std::pair<std::string, std::string>> TargetDistancePass::FuncCallGraph;
bool TargetDistancePass::CallGraphWritten = false;

extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "TargetDistancePass", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "target-distance") {
                        FPM.addPass(TargetDistancePass());
                        return true;
                    }
                    return false;
                });
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, llvm::OptimizationLevel Level) {
                    FunctionPassManager FPM;
                    FPM.addPass(TargetDistancePass());
                    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                });
        }
    };
}
