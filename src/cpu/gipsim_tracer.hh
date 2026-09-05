/*
 * GipsimTracer 的公开接口与运行期状态。
 *
 * 实现按职责分为三个翻译单元：
 *   - gipsim_tracer.cc：ROI 生命周期、退休/故障/取指事件入口；
 *   - gipsim_tracer_isa.cc：ISA 识别、宏指令聚合和微操作路径规范化；
 *   - gipsim_tracer_output.cc：记录提交、检查点构造和文件序列化。
 */

#ifndef __CPU_GIPSIM_TRACER_HH__
#define __CPU_GIPSIM_TRACER_HH__

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "enums/OpClass.hh"
#include "params/GipsimTracer.hh"
#include "sim/insttracer.hh"

namespace gem5::trace
{

class GipsimTracer;

/**
 * 一次 gem5 StaticInst 执行对应的动态记录。
 *
 * BaseSimpleCPU::preExecute() 在译码后、执行前为当前 StaticInst 创建本记录。
 * 非宏指令的 staticInst 就是体系结构指令；宏指令则由每个动态 micro-op 各建
 * 一条记录，并通过 macroStaticInst 共同指向所属体系结构指令。
 *
 * AtomicSimpleCPU 随后从真实取指事务向基类 InstRecord 填入指令字节和首字节
 * 物理地址；setFetchedInstruction() 会立即调用 onFetchedInstruction()，使前一
 * 条已退休分支能在下一条实际取指指令执行前获得真实取指结果。指令执行期间，
 * SimpleExecContext 填入普通执行谓词和访存谓词，AtomicSimpleCPU 的数据访问
 * 路径则在整个逻辑访存完成后填入唯一的物理地址及读写值。cache line packet
 * 等 CPU 内部事务不会暴露给本记录。
 *
 * postExecute() 调用 dump()：正常完成的记录交给 retire() 聚合，真实 fault
 * 交给 discardFaulting() 清除同一 context 的未完成宏指令。CPU 随后销毁本
 * 对象。构造时冻结 ROI 激活状态，避免跨 ROI 边界的执行被误收录。
 */
class GipsimTracerRecord : public InstRecord
{
  public:
    /** 建立动态执行记录，并冻结创建时的 ROI 激活状态。 */
    GipsimTracerRecord(GipsimTracer &tracer, Tick when, ThreadContext *tc,
                       const StaticInstPtr static_inst,
                       const PCStateBase &pc,
                       const StaticInstPtr macro_static_inst,
                       bool roi_active)
        : InstRecord(when, tc, static_inst, pc, macro_static_inst),
          tracer(tracer), roiActiveAtCreation(roi_active)
    {}

    /** 把本次成功退休或 fault 记录提交给所属 tracer。 */
    void dump() override;

    /** fault 时也必须回调，以丢弃尚未完成的宏指令聚合状态。 */
    bool needsFaultNotification() const override { return true; }

    /** 返回创建本记录时（而不是 dump 时）的 ROI 状态。 */
    bool wasROIActive() const { return roiActiveAtCreation; }

  private:
    /** 取指信息就绪时，回填同一 context 前一已退休分支的 br_paddr。 */
    void onFetchedInstruction() override;

    GipsimTracer &tracer;
    const bool roiActiveAtCreation;
};

/**
 * 将 gem5 的已退休指令转换为 gipsim-microop-trace 的 InstTracer。
 *
 * Trace 生成流程如下：
 *
 * 1. 仿真事件 handler 调用 startROI()；第一次调用建立各核零号检查点，
 *    后续调用幂等。若本次 handler 由刚退休的 workbegin 触发，将该指令
 *    作为 ROI 第一条记录；workend 也正常退休并记录，然后由 handler 结束 ROI。
 * 2. CPU 为每个动态 StaticInst 创建 GipsimTracerRecord，并在执行期间填入
 *    实际取指物理地址、指令字节、谓词和已经完成的逻辑访存。
 * 3. dump() 把成功退休的记录送入 retire()。同一体系结构指令的 gem5
 *    micro-op 按 context 聚合；fault 则通过 discardFaulting() 丢弃未完成聚合。
 * 4. ISA 层从实际退休序列选择已审计的动态路径。REP 每个已完成迭代立即
 *    形成一条 trace 指令；普通宏指令在末 micro-op 退休后形成一条。
 * 5. emitInstruction() 核对访存 micro-op 与逻辑访问的一一对应关系，执行必要
 *    的 ISA 操作数排序，并建立分支/内存流和跨核依赖检查点。
 *    internUops() 只比较最终 uops 内容，不比较 ISA、PC 或指令编码；
 *    因而即使编码不同，只要 type、exec_type、srcs、dsts 和 successors 完全
 *    相同，就会跨指令、跨核心复用同一个全局 uops 条目。
 * 6. workend 或 tracer 自己的全局 max_instructions 由外部事件 handler 统一
 *    调用 endROI()；finalize() 清理检查点后，由 writeTrace() 一次性写入
 *    trace_dir。
 *
 * Tracer 只记录正常退休路径。ROI 边界处未完成的宏指令和 faulting 尝试
 * 不进入输出。
 */
class GipsimTracer : public InstTracer
{
  public:
    /** 从 SimObject 参数读取输出目录、ISA、核数和全局指令上限。 */
    explicit GipsimTracer(const GipsimTracerParams &params);

    /** 若正常事件路径尚未结束 ROI，析构时进行一次最终写出。 */
    ~GipsimTracer() override;

    /** 为一次动态 StaticInst 执行创建带 Gipsim 语义的记录。 */
    InstRecord *getInstRecord(
        Tick when, ThreadContext *tc, const StaticInstPtr static_inst,
        const PCStateBase &pc,
        const StaticInstPtr macro_static_inst = nullptr) override;

    /**
     * 开始唯一的 ROI。第一次调用生效；包括 ROI 内和结束后的重复调用均
     * 幂等，不会重置已采集状态。
     */
    void startROI() override;

    /**
     * 由 simulate() 返回后的用户 handler 调用：停止接收退休记录、丢弃
     * 不完整指令，并生成最终 trace。若已提交分支尚缺下一条实际取指，恢复
     * 仿真直到这些真实取指到达；不把期间执行的指令加入 ROI。不能在 CPU
     * 正在处理的事件内部递归调用此接口。
     */
    void endROI(const std::string &reason) override;

    /** 当前是否接受新退休记录。 */
    bool roiActive() const { return active; }

    /** 接收一个成功退休的 StaticInst 记录。 */
    void retire(const GipsimTracerRecord &record);

    /** 接收 fault 通知并取消同一 context 尚未完成的宏指令。 */
    void discardFaulting(const GipsimTracerRecord &record);

    /** 用下一条实际取指的物理地址回填 br_paddr，包括异常/中断转向。 */
    void observeFetch(const GipsimTracerRecord &record);

    /**
     * gem5 micro-op 的 trace 中间表示。
     *
     * 该类型公开是为了让独立的 ISA 规范化翻译单元构造候选路径；它不是
     * SimObject 的外部配置接口。
     */
    struct NormalizedMicroOp
    {
        /** 建立具有指定访存与控制类别的中间微操作。 */
        NormalizedMicroOp(std::string memory, std::string control)
            : memory(std::move(memory)), control(std::move(control))
        {}

        /** "none"、"load"、"store" 或 "atomic"。 */
        std::string memory;
        /** "none"、"internal"、"conditional" 或 "unconditional"。 */
        std::string control;
        /** 映射到目标 ISA exec_type ABI 的执行类别。 */
        uint32_t execType = 0;
        /** gipsim 架构寄存器编号表示的输入、输出依赖。 */
        std::vector<uint32_t> srcs;
        std::vector<uint32_t> dsts;
        /** 由 gem5 内部临时寄存器推导出的相对生产者后继边。 */
        std::vector<uint32_t> successors;
        /** 该微操作是否属于 AArch64 谓词访存候选。 */
        bool predicatedMemory = false;
        /** 候选访存是否在本次动态执行中被谓词关闭。 */
        bool inactiveMemory = false;
        /**
         * 没有架构 trace 编号的 gem5 内部寄存器。选择最终路径后由它们
         * 计算 successors，随后清除，不写入文件。
         */
        std::vector<uint64_t> internalSrcs;
        std::vector<uint64_t> internalDsts;
    };

  private:
    /** 三条并行输出流在同一逻辑时刻的下标。 */
    struct IndexTriple
    {
        size_t instr = 0;
        size_t memPaddr = 0;
        size_t brPaddr = 0;
    };

    /** instr 流中的一条已提交体系结构指令。 */
    struct InstrRecord
    {
        Addr ppc;
        uint32_t size;
        int32_t uopsIdx;
    };

    /** 本核流位置以及可选的跨核 release 来源。 */
    struct DependencyCheckpoint
    {
        IndexTriple idx;
        std::optional<std::pair<uint32_t, size_t>> from;
    };

    /**
     * 按 context 聚合、尚未完整提交的一条体系结构指令。
     * memory 中每一项来自一个已完成主动访存的动态 micro-op；一条体系结构
     * 指令可包含多个此类 micro-op，因此这里仍使用向量。
     */
    struct PendingInstruction
    {
        ThreadContext *thread = nullptr;
        Addr pc = 0;
        Addr ppc = 0;
        std::vector<uint8_t> encoding;
        std::vector<InstRecord::MemoryAccess> memory;
        std::vector<NormalizedMicroOp> microops;
        unsigned repeatMemoryOperations = 0;
        unsigned currentRepeatMemoryOperations = 0;
        uint64_t repeatIterationsEmitted = 0;
        uint8_t bitScanKind = 0;
        uint8_t x86DynamicKind = 0;
        bool iret = false;
        bool branch = false;
        bool unconditionalBranch = false;
        bool conditionalMemory = false;
        bool acquire = false;
        bool release = false;
        bool valid = false;
    };

    /** 一个核已经提交的各输出流及依赖分析临时状态。 */
    struct CoreOutput
    {
        std::vector<InstrRecord> instr;
        std::vector<Addr> memPaddr;
        std::vector<Addr> brPaddr;
        std::vector<IndexTriple> periodCheckpoints;
        std::vector<DependencyCheckpoint> dependencyCheckpoints;
        uint64_t instructionsSincePeriod = 0;
        bool completedReleaseBarrier = false;
        bool previousLoadValid = false;
        InstRecord::MemoryAccess previousLoad;
        IndexTriple previousLoadBefore;
    };

    /** 已完成退休、可供后续 acquire 匹配的跨核 release。 */
    struct ReleaseRecord
    {
        Addr pa;
        std::vector<uint8_t> value;
        /** Empty means all bytes are valid; inactive lanes never match. */
        std::vector<bool> byteEnable;
        unsigned core;
        size_t checkpoint;
        /** 是否至少有一个 acquire checkpoint 引用了该 release。 */
        bool referencedByAcquire = false;
    };

    /** 已退休分支等待同一 context 下一条实际取指的唯一地址槽。 */
    struct PendingBranch
    {
        unsigned core;
        size_t index;
    };

    /** 所有 trace 文件所在目录。 */
    const std::string traceDirectory;
    /** trace ABI 使用的 ISA 名称。 */
    const std::string isa;
    /** 共享本 tracer 的 CPU 核数。 */
    const unsigned numCores;
    /** 全核合计的最大 trace 指令数；零表示不限制。 */
    const uint64_t maxInstructions;

    std::vector<CoreOutput> outputs;
    std::vector<std::vector<NormalizedMicroOp>> globalUops;
    std::unordered_map<std::string, int32_t> globalUopsIndexes;
    std::vector<ReleaseRecord> releases;
    bool active = false;
    bool started = false;
    bool finalized = false;
    uint64_t sequence = 0;
    std::map<int, PendingInstruction> pending;
    /** handler 启用 ROI 前，暂存刚退休的 workbegin；不缓存其他启动指令。 */
    PendingInstruction beginMarker;
    /**
     * 每个 context 至多有一个待回填分支：下一条指令执行前的取指回调先
     * 消费该槽，因此下一条分支退休时旧槽已清空。不以计算出的目标 PC 索引。
     */
    std::map<int, PendingBranch> pendingBranches;
    bool instructionLimitPending = false;
    /** endROI() called from a stopped simulation's handler is
     * draining fetch. */
    bool roiEndPending = false;

    /** 用首个退休 micro-op 初始化一条待提交体系结构指令。 */
    void beginPending(PendingInstruction &, const GipsimTracerRecord &,
                      const StaticInstPtr &architectural_inst);

    /**
     * 追加一个已退休 micro-op。REP 的非终止迭代会在这里立即提交，因此
     * 返回该次提交是否恰好达到全局指令上限。
     */
    bool appendRecord(PendingInstruction &, const GipsimTracerRecord &);

    /** 完成普通宏指令或 REP 的终止段。 */
    void finishPending(PendingInstruction &);

    /**
     * 把一条完整动态路径提交到输出状态，并唯一地计算是否达到指令上限。
     * 返回值由 REP 中途提交路径或普通/REP 终止路径分别处理，不会重复计数。
     */
    bool emitInstruction(PendingInstruction &,
                         const std::vector<InstRecord::MemoryAccess> &,
                         Addr next_pc, int selector);

    /** 按动态 selector 选择并填充最终微操作路径。 */
    std::vector<NormalizedMicroOp> selectedMicroops(
        const PendingInstruction &, int selector) const;

    /** 将 gem5 OpClass 转换为当前 ISA 的 exec_type ABI。 */
    uint32_t mapExecType(enums::OpClass op_class) const;

    /** 识别触发外部 handler 的 workbegin；marker 本身也是退休指令。 */
    bool isWorkBegin(const std::vector<uint8_t> &encoding) const;

    /** 判断已分类的 x86 动态指令族是否为 far JMP。 */
    static bool isX86FarJump(uint8_t kind);

    /** 依据实际退休 shape 选择 IRET 的已审计动态路径。 */
    int selectX86IretPath(const PendingInstruction &entry) const;

    /** 依据实际退休 shape 选择其他 x86 动态指令的已审计路径。 */
    int selectX86DynamicPath(const PendingInstruction &entry) const;

    /** 驻留微操作数组并返回全局 uops 索引。 */
    int32_t internUops(std::vector<NormalizedMicroOp>);

    /** 返回指定核各输出流的当前位置。 */
    IndexTriple currentCheckpoint(unsigned core) const;

    /** REP 逻辑回边直接记录原取指地址；普通分支建立动态取指回填项。 */
    void appendBranchAddress(PendingInstruction &, Addr target);

    /** 是否仍有尚未看到下一条实际取指的分支。 */
    bool unresolvedBranches() const;

    /**
     * 在 emitInstruction() 已完整提交一条逻辑指令、追加其内存/分支流并使
     * 全局 sequence 达到 maxInstructions 后调用。它立即停止接收新退休记录
     * 并丢弃各 context 的不完整宏指令；若已提交分支仍等待下一条实际取指，
     * 则保留取指回调直至全部地址回填，再产生标准 MAX_INSTS 事件。外部
     * handler 随后调用 endROI() 完成序列化。
     */
    void reachInstructionLimit();

    /** 完成依赖检查点压缩并写出一次性结果。 */
    void finalize();

    /** 把地址序列化为固定宽度十六进制字符串。 */
    static std::string hexAddress(Addr);

    /** 在 traceDirectory 中写入 manifest、uops 和各核流文件。 */
    void writeTrace() const;
};

} // namespace gem5::trace

#endif // __CPU_GIPSIM_TRACER_HH__
