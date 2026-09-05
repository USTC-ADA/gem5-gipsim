/*
 * GipsimTracer 的提交状态、检查点和文件序列化。
 *
 * 本文件只处理已经选择完动态路径的指令：核对逻辑访存与微操作的一一
 * 对应关系、更新各核输出流和依赖关系，最终生成
 * gipsim-microop-trace 目录。
 */

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>

#include "base/logging.hh"
#include "cpu/gipsim_tracer.hh"
#include "cpu/thread_context.hh"
#include "sim/sim_exit.hh"

namespace gem5::trace
{
int32_t
GipsimTracer::internUops(std::vector<NormalizedMicroOp> uops)
{
    std::ostringstream key;
    for (const auto &uop : uops) {
        key << uop.memory << ':' << uop.control << ':' << uop.execType << ':';
        for (auto reg : uop.srcs) key << reg << ',';
        key << ':';
        for (auto reg : uop.dsts) key << reg << ',';
        key << ':';
        for (auto successor : uop.successors) key << successor << ',';
        key << ';';
    }
    const auto [position, inserted] = globalUopsIndexes.emplace(
        key.str(), static_cast<int32_t>(globalUops.size()));
    if (inserted) globalUops.push_back(std::move(uops));
    return position->second;
}

GipsimTracer::IndexTriple
GipsimTracer::currentCheckpoint(unsigned core) const
{
    const auto &output = outputs.at(core);
    return {output.instr.size(), output.memPaddr.size(),
            output.brPaddr.size()};
}

void
GipsimTracer::appendBranchAddress(PendingInstruction &entry, Addr target)
{
    const int context = entry.thread->contextId();
    auto &addresses = outputs.at(entry.thread->cpuId()).brPaddr;
    if (entry.repeatMemoryOperations && target == entry.pc) {
        /* REP loop-back is a logical per-iteration branch, but gem5 remains
         * inside the already-fetched macro-op instead of fetching it again. */
        addresses.push_back(entry.ppc);
        return;
    }
    /* br_paddr is the next instruction actually fetched in this context,
     * including exception/interrupt redirection. Neither the computed target
     * nor a historical PC mapping determines that physical address. */
    const size_t index = addresses.size();
    addresses.push_back(0);
    pendingBranches[context] = {
        static_cast<unsigned>(entry.thread->cpuId()), index};
}

bool
GipsimTracer::unresolvedBranches() const
{
    return !pendingBranches.empty();
}

bool
GipsimTracer::emitInstruction(
    PendingInstruction &entry,
    const std::vector<InstRecord::MemoryAccess> &recordedMemory,
    Addr nextPc, int selector)
{
    const unsigned core = entry.thread->cpuId();
    auto &output = outputs[core];
    if (selector < 0 && entry.bitScanKind) {
        /* 源为零时只退休公共前缀、内部条件分支和终止 fault 微操作：
         * register/memory/RIP-relative 三种形态分别为 4/5/6 个微操作；
         * 非零路径均显著更长。 */
        selector = entry.microops.size() <= 6 ? 1 : 0;
    } else if (selector < 0 && entry.iret) {
        selector = selectX86IretPath(entry);
    } else if (selector < 0 && entry.x86DynamicKind) {
        selector = selectX86DynamicPath(entry);
    } else if (selector < 0 && entry.conditionalMemory) {
        selector = recordedMemory.empty() ? 0 : 1;
    }
    selector = std::max(selector, 0);
    auto uops = selectedMicroops(entry, selector);
    const size_t expectedMemory = std::count_if(
        uops.begin(), uops.end(), [](const auto &uop) {
            return uop.memory != "none";
        });
    const size_t expectedBranches = std::count_if(
        uops.begin(), uops.end(), [](const auto &uop) {
            return uop.control != "none";
        });
    auto memory = recordedMemory;
    if (isX86FarJump(entry.x86DynamicKind)) {
        /* gem5's far-jump ROM reads the selector before the offset, while
         * x86 defines the memory operand layout as offset followed by
         * selector.  Normalize from the observed addresses, so every far
         * pointer instance is serialized in ISA operand order without a
         * per-test or per-address exception. */
        std::stable_sort(memory.begin(), memory.end(),
            [](const auto &left, const auto &right) {
                return left.vaddr < right.vaddr;
            });
    }
    bool x86FloatMemoryOrder = false;
    if (isa == "x86_64" && expectedMemory > 1) {
        const uint32_t floatRead = mapExecType(enums::FloatMemRead);
        const uint32_t floatWrite = mapExecType(enums::FloatMemWrite);
        x86FloatMemoryOrder = std::all_of(
            uops.begin(), uops.end(), [=](const auto &uop) {
                return uop.memory == "none" || uop.execType == floatRead ||
                    uop.execType == floatWrite;
            });
    }
    if (x86FloatMemoryOrder) {
        /* gem5 may retire the high-address x87/SIMD memory micro-op first.
         * Preserve the selected path's load-before-store phases, then order
         * the logical accesses in each phase by ISA operand address. */
        using MemoryAccess = InstRecord::MemoryAccess;
        std::vector<MemoryAccess> reads;
        std::vector<MemoryAccess> writes;
        std::vector<MemoryAccess> atomics;
        for (const auto &access : memory) {
            if (access.type == MemoryAccess::Type::Read)
                reads.push_back(access);
            else if (access.type == MemoryAccess::Type::Write)
                writes.push_back(access);
            else
                atomics.push_back(access);
        }
        const auto byAddress = [](const auto &left, const auto &right) {
            return left.vaddr < right.vaddr;
        };
        std::stable_sort(reads.begin(), reads.end(), byAddress);
        std::stable_sort(writes.begin(), writes.end(), byAddress);
        std::stable_sort(atomics.begin(), atomics.end(), byAddress);
        size_t read = 0;
        size_t write = 0;
        size_t atomic = 0;
        std::vector<MemoryAccess> ordered;
        ordered.reserve(memory.size());
        for (const auto &uop : uops) {
            if (uop.memory == "load" && read < reads.size())
                ordered.push_back(std::move(reads[read++]));
            else if (uop.memory == "store" && write < writes.size())
                ordered.push_back(std::move(writes[write++]));
            else if (uop.memory == "atomic" && atomic < atomics.size())
                ordered.push_back(std::move(atomics[atomic++]));
        }
        if (ordered.size() == memory.size())
            memory = std::move(ordered);
    }
    fatal_if(expectedMemory != memory.size(),
             "GipsimTracer PC %#x selected path has %d memory uops but %d "
             "accesses", entry.pc, expectedMemory, memory.size());
    fatal_if(expectedBranches != size_t(entry.branch),
             "GipsimTracer PC %#x selected path has %d branch uops", entry.pc,
             expectedBranches);
    const int32_t uopsIndex = internUops(std::move(uops));
    const IndexTriple before = currentCheckpoint(core);

    const InstRecord::MemoryAccess *load = nullptr;
    const InstRecord::MemoryAccess *store = nullptr;
    for (const auto &access : memory) {
        if (!load && access.type != InstRecord::MemoryAccess::Type::Write)
            load = &access;
        if (access.type != InstRecord::MemoryAccess::Type::Read)
            store = &access;
    }
    const InstRecord::MemoryAccess *acquire = load;
    IndexTriple acquireBefore = before;
    if (entry.acquire && !acquire && output.previousLoadValid) {
        acquire = &output.previousLoad;
        acquireBefore = output.previousLoadBefore;
    }
    if (entry.acquire && acquire) {
        for (auto release = releases.rbegin(); release != releases.rend();
             ++release) {
            const size_t bytes = std::min(
                release->value.size(), acquire->readValue.size());
            if (release->pa != acquire->paddr || bytes == 0) continue;
            // Masked accesses contain unspecified data at inactive bytes.
            // Only bytes actually transferred by both operations are values
            // that can establish a dependency; an empty overlap cannot.
            bool overlap = false;
            bool equal = true;
            for (size_t byte = 0; byte < bytes; ++byte) {
                if ((!release->byteEnable.empty() &&
                     !release->byteEnable[byte]) ||
                    (!acquire->byteEnable.empty() &&
                     !acquire->byteEnable[byte])) continue;
                overlap = true;
                if (release->value[byte] != acquire->readValue[byte]) {
                    equal = false;
                    break;
                }
            }
            if (!overlap || !equal) continue;
            output.dependencyCheckpoints.push_back({
                acquireBefore,
                std::pair<uint32_t, size_t>(release->core,
                                             release->checkpoint)});
            release->referencedByAcquire = true;
            break;
        }
    }

    output.instr.push_back({entry.ppc,
        static_cast<uint32_t>(entry.encoding.size()), uopsIndex});
    output.memPaddr.reserve(output.memPaddr.size() + memory.size());
    for (const auto &access : memory)
        output.memPaddr.push_back(access.paddr);
    if (entry.branch)
        appendBranchAddress(entry, nextPc);

    ++sequence;
    if (++output.instructionsSincePeriod == 1000) {
        output.periodCheckpoints.push_back(currentCheckpoint(core));
        output.instructionsSincePeriod = 0;
    }

    if (entry.release && !store) output.completedReleaseBarrier = true;
    if (store && (entry.release || output.completedReleaseBarrier)) {
        const size_t checkpoint = output.dependencyCheckpoints.size();
        output.dependencyCheckpoints.push_back(
            {currentCheckpoint(core), std::nullopt});
        releases.push_back({store->paddr, store->writtenValue,
                            store->byteEnable, core, checkpoint, false});
        output.completedReleaseBarrier = false;
    }
    output.previousLoadValid = load != nullptr;
    if (load) {
        output.previousLoad = *load;
        output.previousLoadBefore = before;
    }
    return maxInstructions && sequence >= maxInstructions;
}

void
GipsimTracer::reachInstructionLimit()
{
    active = false;
    for (auto &[context, entry] : pending) entry = PendingInstruction{};
    /* pending contains incomplete, not-yet-emitted architectural instructions
     * and is therefore discarded at the cutoff.  pendingBranches instead
     * belongs to already-emitted branches whose br_paddr slots await the next
     * actual instruction fetch. The two states may coexist across contexts.
     *
     * active=false prevents retire() from creating more pending instructions,
     * while fetch callbacks remain enabled to resolve those committed branch
     * slots.  Once all slots are complete, use gem5's canonical MAX_INSTS
     * cause so the standard dispatcher invokes the configured handler and
     * endROI(). */
    if (unresolvedBranches()) {
        instructionLimitPending = true;
    } else {
        exitSimLoopNow("a thread reached the max instruction count");
    }
}

void
GipsimTracer::finalize()
{
    if (finalized || !started) return;
    fatal_if(
        unresolvedBranches(),
        "GipsimTracer ROI ended before the next instruction after a "
        "retired branch was fetched");

    std::vector<std::vector<size_t>> mappings(numCores);
    for (unsigned core = 0; core < numCores; ++core) {
        auto &output = outputs[core];
        const auto final = currentCheckpoint(core);
        if (output.periodCheckpoints.empty() ||
            output.periodCheckpoints.back().instr != final.instr ||
            output.periodCheckpoints.back().memPaddr != final.memPaddr ||
            output.periodCheckpoints.back().brPaddr != final.brPaddr) {
            output.periodCheckpoints.push_back(final);
        }
        output.dependencyCheckpoints.push_back({final, std::nullopt});
        std::vector<bool> keep(output.dependencyCheckpoints.size(), false);
        keep.front() = true;
        keep.back() = true;
        for (size_t index = 0; index < keep.size(); ++index)
            keep[index] = keep[index] ||
                output.dependencyCheckpoints[index].from.has_value();
        for (const auto &release : releases) {
            if (release.referencedByAcquire && release.core == core &&
                release.checkpoint < keep.size())
                keep[release.checkpoint] = true;
        }
        mappings[core].assign(keep.size(), size_t(-1));
        size_t next = 0;
        for (size_t index = 0; index < keep.size(); ++index)
            if (keep[index]) mappings[core][index] = next++;
    }
    for (unsigned core = 0; core < numCores; ++core) {
        auto &checkpoints = outputs[core].dependencyCheckpoints;
        std::vector<DependencyCheckpoint> filtered;
        for (size_t index = 0; index < checkpoints.size(); ++index) {
            if (mappings[core][index] == size_t(-1)) continue;
            auto checkpoint = checkpoints[index];
            if (checkpoint.from) {
                auto &[sourceCore, sourceCheckpoint] = *checkpoint.from;
                fatal_if(sourceCore >= mappings.size() ||
                         sourceCheckpoint >= mappings[sourceCore].size() ||
                         mappings[sourceCore][sourceCheckpoint] == size_t(-1),
                         "GipsimTracer dependency checkpoint was filtered");
                sourceCheckpoint = mappings[sourceCore][sourceCheckpoint];
            }
            filtered.push_back(std::move(checkpoint));
        }
        checkpoints = std::move(filtered);
    }
    writeTrace();
    finalized = true;
}

void
GipsimTracer::writeTrace() const
{
    namespace fs = std::filesystem;
    const fs::path directory(traceDirectory);
    fs::create_directories(directory);
    auto open = [](const fs::path &path) {
        std::ofstream output(path, std::ios::trunc);
        if (!output) fatal("GipsimTracer cannot open %s", path.c_str());
        return output;
    };
    auto writeIndex = [](std::ostream &out, const IndexTriple &idx) {
        out << "{\"instr\":" << idx.instr
            << ",\"mem_paddr\":" << idx.memPaddr
            << ",\"br_paddr\":" << idx.brPaddr << '}';
    };
    {
        auto manifest = open(directory / "manifest.json");
        manifest << "{\n  \"format\": \"gipsim-microop-trace\",\n"
                    "  \"streams\": [\"instr\", \"uops\", "
                    "\"mem_paddr\", \"br_paddr\", "
                    "\"period_checkpoint\", "
                    "\"dependency_checkpoint\"]\n}\n";
    }
    {
        auto out = open(directory / "uops.jsonl");
        for (size_t sequence = 0; sequence < globalUops.size(); ++sequence) {
            const auto &uops = globalUops[sequence];
            out << "{\"index\":" << sequence << ",\"uops\":[";
            for (size_t index = 0; index < uops.size(); ++index) {
                if (index) out << ',';
                const auto &uop = uops[index];
                const char *type = uop.memory == "store" ? "STORE" :
                    uop.memory != "none" ? "LOAD" :
                    uop.control != "none" ? "BRANCH" : "TRIVIAL";
                out << "{\"type\":\"" << type << "\",\"exec_type\":"
                    << uop.execType << ",\"srcs\":[";
                for (size_t n = 0; n < uop.srcs.size(); ++n) {
                    if (n) out << ',';
                    out << uop.srcs[n];
                }
                out << "],\"dsts\":[";
                for (size_t n = 0; n < uop.dsts.size(); ++n) {
                    if (n) out << ',';
                    out << uop.dsts[n];
                }
                out << "],\"successors\":[";
                for (size_t n = 0; n < uop.successors.size(); ++n) {
                    if (n) out << ',';
                    fatal_if(uop.successors[n] == 0 ||
                             index + uop.successors[n] >= uops.size(),
                             "GipsimTracer invalid relative successor");
                    out << uop.successors[n];
                }
                out << "]}";
            }
            out << "]}\n";
        }
    }
    for (unsigned core = 0; core < numCores; ++core) {
        const auto &output = outputs[core];
        auto corePath = [&](const char *stream) {
            return directory / ("core" + std::to_string(core) + "." +
                                stream + ".jsonl");
        };
        {
            auto out = open(corePath("instr"));
            for (size_t index = 0; index < output.instr.size(); ++index) {
                const auto &record = output.instr[index];
                fatal_if(
                    static_cast<size_t>(record.uopsIdx) >= globalUops.size(),
                    "GipsimTracer invalid uops index");
                out << "{\"index\":" << index << ",\"ppc\":\""
                    << hexAddress(record.ppc) << "\",\"size\":"
                    << record.size << ",\"uops_idx\":" << record.uopsIdx
                    << "}\n";
            }
        }
        for (const auto &[name, values] :
             {std::pair{"mem_paddr", &output.memPaddr},
              std::pair{"br_paddr", &output.brPaddr}}) {
            auto out = open(corePath(name));
            for (size_t index = 0; index < values->size(); ++index)
                out << "{\"index\":" << index << ",\"paddr\":\""
                    << hexAddress((*values)[index]) << "\"}\n";
        }
        {
            auto out = open(corePath("period_checkpoint"));
            for (size_t index = 0;
                 index < output.periodCheckpoints.size(); ++index) {
                out << "{\"index\":" << index << ",\"idx\":";
                writeIndex(out, output.periodCheckpoints[index]);
                out << "}\n";
            }
        }
        {
            auto out = open(corePath("dependency_checkpoint"));
            for (size_t index = 0;
                 index < output.dependencyCheckpoints.size(); ++index) {
                const auto &checkpoint = output.dependencyCheckpoints[index];
                out << "{\"index\":" << index << ",\"idx\":";
                writeIndex(out, checkpoint.idx);
                out << ",\"from\":";
                if (!checkpoint.from) out << "null";
                else out << "{\"core_idx\":" << checkpoint.from->first
                         << ",\"checkpoint_idx\":"
                         << checkpoint.from->second << '}';
                out << "}\n";
            }
        }
    }
}

std::string
GipsimTracer::hexAddress(Addr value)
{
    std::ostringstream out;
    out << "0x" << std::hex << std::nouppercase << std::setw(16)
        << std::setfill('0') << value;
    return out.str();
}

} // namespace gem5::trace
