/*
 * GipsimTracer 的事件入口与 ROI 生命周期。
 *
 * 本文件只协调 InstRecord 回调、体系结构指令聚合入口和仿真退出事件；
 * ISA 相关解释及 trace 文件布局分别位于另外两个实现文件。
 */

#include "cpu/gipsim_tracer.hh"

#include "base/logging.hh"
#include "cpu/static_inst.hh"
#include "cpu/thread_context.hh"
#include "sim/sim_events.hh"
#include "sim/sim_exit.hh"
#include "sim/simulate.hh"

namespace gem5::trace
{

void
GipsimTracerRecord::dump()
{
    if (getFaulting()) tracer.discardFaulting(*this);
    else tracer.retire(*this);
}

void
GipsimTracerRecord::onFetchedInstruction()
{
    tracer.observeFetch(*this);
}

GipsimTracer::GipsimTracer(const GipsimTracerParams &params)
    : InstTracer(params), traceDirectory(params.trace_dir), isa(params.isa),
      numCores(params.num_cores), maxInstructions(params.max_instructions),
      outputs(numCores)
{
    if (isa != "x86_64" && isa != "aarch64" && isa != "rv64gc")
        fatal("GipsimTracer only supports x86_64, aarch64, and rv64gc");
}

GipsimTracer::~GipsimTracer()
{
    finalize();
}

InstRecord *
GipsimTracer::getInstRecord(Tick when, ThreadContext *tc,
                           const StaticInstPtr staticInst,
                           const PCStateBase &pc,
                           const StaticInstPtr macroStaticInst)
{
    return new GipsimTracerRecord(*this, when, tc, staticInst, pc,
                                 macroStaticInst, active);
}

void
GipsimTracer::startROI()
{
    if (started) {
        if (finalized)
            inform("GipsimTracer ROI has already ended; ignoring "
                   "startROI()\n");
        else
            inform("GipsimTracer ROI has already started; ignoring "
                   "startROI()\n");
        return;
    }
    inform("GipsimTracer ROI starts now\n");
    for (unsigned core = 0; core < numCores; ++core) {
        auto &output = outputs[core];
        output.periodCheckpoints.push_back({0, 0, 0});
        output.dependencyCheckpoints.push_back({{0, 0, 0}, std::nullopt});
    }
    active = true;
    started = true;
    if (beginMarker.valid)
        finishPending(beginMarker);
}

void
GipsimTracer::endROI(const std::string &reason)
{
    if (!started)
        fatal("GipsimTracer ROI is not available to end");
    if (finalized) {
        inform("GipsimTracer ROI has already ended; ignoring endROI(%s)\n",
               reason);
        return;
    }
    active = false;
    for (auto &[context, entry] : pending)
        entry = PendingInstruction{};
    inform("GipsimTracer ROI ends now; reason: %s\n", reason);
    if (unresolvedBranches()) {
        // endROI is a handler-side API, invoked after simulate() returns.
        // Do not retire more instructions; resume only far enough to obtain
        // the next real fetch after each branch committed at cutoff.
        // This cannot be done by translating a PC inside the tracer.
        struct DeferredExit
        {
            std::string cause;
            int code;
            uint64_t hypercall;
            std::map<std::string, std::string> payload;
        };
        std::vector<DeferredExit> exits;
        roiEndPending = true;
        while (true) {
            auto *event = simulate();
            if (event->getCause() == "gipsim trace branch fetch complete")
                break;
            fatal_if(event == simulate_limit_event ||
                     event->getCause() == "user interrupt received",
                     "GipsimTracer cannot finish next-instruction fetches "
                     "before "
                     "simulation was stopped: %s", event->getCause());
            // A different core can already have another exit event queued.
            // Preserve its payload for the normal dispatcher if the caller
            // elects to continue simulation after ending this ROI.
            exits.push_back({event->getCause(), event->getCode(),
                             event->getHypercallId(), event->getPayload()});
        }
        roiEndPending = false;
        for (auto event = exits.rbegin(); event != exits.rend(); ++event) {
            new GlobalSimLoopExitEvent(curTick(), event->cause, event->code,
                                       0, event->hypercall, event->payload);
        }
    }
    finalize();
}

void
GipsimTracer::retire(const GipsimTracerRecord &record)
{
    if (!started) {
        if (record.getFetchPaddrValid() &&
            isWorkBegin(record.getEncoding())) {
            // The event handler runs after this instruction retires. Keep
            // its native uop/fetch record, but let startROI() enable tracing.
            beginPending(beginMarker, record, record.getStaticInst());
            appendRecord(beginMarker, record);
        } else if (beginMarker.thread == record.getThread()) {
            // A handler which did not start tracing must not cause a later
            // unrelated startROI() to replay an old workbegin.
            beginMarker = PendingInstruction{};
        }
        return;
    }
    if (!record.wasROIActive() || !active) return;
    const StaticInstPtr &staticInst = record.getStaticInst();
    StaticInstPtr architecturalInst = record.getMacroStaticInst();
    if (!architecturalInst) architecturalInst = staticInst;
    int context = record.getThread()->contextId();
    PendingInstruction &entry = pending[context];
    if (!record.getFetchPaddrValid() || record.getEncoding().empty()) {
        /* Interrupt/fault-entry ROM micro-ops are not fetched architectural
         * instructions and carry no decoder fetch record.  They may execute
         * while the ROI is active but must not become retired trace
         * entries. */
        fatal_if(entry.valid,
                 "missing fetch state in the middle of macro-op at PC %#x",
                 record.getPCState().instAddr());
        return;
    }
    if (!entry.valid) {
        /* Another core can be part-way through a macro-op when this core
         * triggers workbegin.  Its leading micro-ops are outside the ROI, so
         * the remaining micro-ops cannot form a retired architectural
         * instruction by themselves.  Ignore that suffix and begin at the
         * next complete instruction boundary. */
        if (staticInst->isMicroop() && !staticInst->isFirstMicroop())
            return;
        beginPending(entry, record, architecturalInst);
    }
    else if (!staticInst->isMicroop())
        fatal("unfinished macro-op before PC %#x",
              record.getPCState().instAddr());
    const bool limit = appendRecord(entry, record);
    if (limit) {
        entry = PendingInstruction{};
        reachInstructionLimit();
        return;
    }
    if (!staticInst->isMicroop() || staticInst->isLastMicroop())
        finishPending(entry);
}

void
GipsimTracer::discardFaulting(const GipsimTracerRecord &record)
{
    if (!record.wasROIActive()) return;
    int context = record.getThread()->contextId();
    pending[context] = PendingInstruction{};
}

void
GipsimTracer::observeFetch(const GipsimTracerRecord &record)
{
    if (!record.getFetchPaddrValid() || record.getEncoding().empty())
        return;
    const int context = record.getThread()->contextId();
    const Addr ppc = record.getFetchPaddr();
    // The next fetched instruction may be an exception/interrupt handler,
    // not the branch's computed virtual target. No target-PC match is needed.
    const auto branch = pendingBranches.find(context);
    if (branch != pendingBranches.end()) {
        outputs.at(branch->second.core).brPaddr.at(branch->second.index) = ppc;
        pendingBranches.erase(branch);
    }
    if (roiEndPending && !unresolvedBranches()) {
        roiEndPending = false;
        exitSimLoopNow("gipsim trace branch fetch complete");
    } else if (instructionLimitPending && !unresolvedBranches()) {
        instructionLimitPending = false;
        exitSimLoopNow("a thread reached the max instruction count");
    }
}

} // namespace gem5::trace
