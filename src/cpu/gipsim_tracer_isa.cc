/*
 * GipsimTracer 的 ISA 解释与动态微操作路径规范化。
 *
 * 本文件把 gem5 StaticInst/InstRecord 状态映射到统一 trace ABI，并集中处理
 * x86 宏微码动态路径、REP 迭代以及三种 ISA 的特殊语义。它不负责创建
 * ROI，也不直接写文件。
 */

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <memory>
#include <set>
#include <string_view>
#include <utility>

#include "arch/x86/ldstflags.hh"
#include "arch/x86/pcstate.hh"
#include "arch/x86/regs/int.hh"
#include "arch/x86/regs/misc.hh"
#include "arch/x86/regs/segment.hh"
#include "arch/x86/x86_traits.hh"
#include "base/logging.hh"
#include "cpu/gipsim_tracer.hh"
#include "cpu/static_inst.hh"
#include "cpu/thread_context.hh"
#include "enums/OpClass.hh"

namespace gem5::trace
{
namespace
{

/** 把 gem5 内部寄存器类和类内编号组合成稳定的临时依赖键。 */
uint64_t
internalRegisterKey(const RegId &reg)
{
    return (uint64_t(reg.classValue()) << 32) | uint32_t(reg.index());
}

/**
 * 向数组追加一个规范化到自然数空间内的寄存器 id。
 *
 * 架构寄存器与 trace id 的对应关系：
 *   x86-64：RAX..R15=0..15，RFLAGS=16，ST0..ST7/MM0..MM7=17..24，
 *           XMM0..XMM15=25..40；gem5 的全部 CC 子寄存器合并为 RFLAGS，
 *           每个 XMM 的 low/high FloatReg 合并为同一个 id。
 *   AArch64：X0..X31=0..31，V0..V31=32..63，SP 的各 EL 别名=64，
 *            N/C/Z/V=65/66/67/68，P0..P15=80..95，FFR=96，ZA=97。
 *   RV64GC：X0..X31=0..31，F0..F31=32..63。
 *
 * 一个 gem5 RegId 可能展开成多个 id（例如合并存储的 NZ），也可能不是
 * trace 架构寄存器。后者返回 false，由调用者使用 internalRegisterKey()
 * 保存为仅用于推导同指令 successors 的内部依赖。
 */
bool
appendTraceRegisters(std::vector<uint32_t> &output, const std::string &isa,
                     const RegId &reg)
{
    const size_t initialSize = output.size();
    const uint32_t index = reg.index();
    if (isa == "x86_64") {
        // AH/CH/DH/BH use folded RegIds, but depend on RAX/RCX/RDX/RBX.
        // Clear only the fold bit; microcode temporaries remain internal.
        const uint32_t intIndex = index & ~X86ISA::IntFoldBit;
        if (reg.is(IntRegClass) && intIndex < X86ISA::int_reg::NumArchRegs)
            output.push_back(intIndex);
        else if (reg.is(CCRegClass)) output.push_back(16);
        else if (reg.is(FloatRegClass)) {
            /* x87/MMX 使用 17..24；gem5 把每个 XMM 拆成相邻的 low/high
             * FloatReg，trace 则把两半合并为同一个 25..40 编号。 */
            if (index < 8) output.push_back(17 + index);
            else if (index < 40) output.push_back(25 + (index - 8) / 2);
        }
        else if (reg.is(VecRegClass) && index < 16)
            output.push_back(25 + index);
    } else if (isa == "aarch64") {
        if (reg.is(IntRegClass)) {
            if (index < 32) output.push_back(index);
            /* gem5's Sp0..Sp3/Spx aliases occupy 38..42.  The generated
             * AArch64 decoder uses one architectural register id for SP. */
            else if (index >= 38 && index <= 42) output.push_back(64);
        } else if (reg.is(CCRegClass)) {
            /* gem5 stores N/Z together; the current generated trace ABI
             * exposes N/C/Z as independent dependency ids 65..67. */
            if (index == 0) {
                output.push_back(65);
                output.push_back(67);
            } else if (index == 1) {
                output.push_back(66);
            } else if (index == 2) {
                output.push_back(68);
            }
        } else if ((reg.is(FloatRegClass) || reg.is(VecRegClass)) &&
                   index < 32) {
            output.push_back(32 + index);
        } else if (reg.is(VecPredRegClass) && index < 17) {
            /* P0..P15 and FFR are architectural.  PREG_UREG0 is gem5's
             * internal predicate temporary and remains a successor edge. */
            output.push_back(80 + index);
        } else if (reg.is(MatRegClass) && index == 0) {
            output.push_back(97);
        }
    } else {
        if (reg.is(IntRegClass) && index < 32) output.push_back(index);
        else if ((reg.is(FloatRegClass) || reg.is(VecRegClass)) && index < 32)
            output.push_back(32 + index);
    }
    return output.size() != initialSize;
}

/**
 * 按 ISA 把 gem5 OpClass 映射成生成 decoder 使用的 exec_type 编号。
 * 下列数组就是完整对应表：数组下标是 trace exec_type id，元素是 gem5
 * OpClass 名称；顺序与各 ISA 生成的 exec_type.hpp 完全一致。
 */
uint32_t
traceExecType(const std::string &isa, enums::OpClass opClass)
{
    /* This is gem5's independent serialization map for the trace contract.
     * It intentionally does not include or call gipsim's decoder.  Values
     * mirror the three exec_type.hpp ABI lists. */
    static const std::vector<std::string_view> x86Names = {
        "IntAlu", "IntMult", "IntDiv", "FloatAdd", "FloatCmp",
        "FloatCvt", "FloatMult", "FloatMisc", "FloatDiv", "FloatSqrt",
        "SimdAdd", "SimdAlu", "SimdCmp", "SimdCvt", "SimdMisc",
        "SimdMult", "SimdShift", "SimdFloatAdd", "SimdFloatAlu",
        "SimdFloatCmp", "SimdFloatCvt", "SimdFloatDiv", "SimdFloatMult",
        "SimdFloatSqrt", "MemRead", "MemWrite", "FloatMemRead",
        "FloatMemWrite", "No_OpClass",
    };
    static const std::vector<std::string_view> aarch64Names = {
        "FloatAdd", "FloatCmp", "FloatCvt", "FloatDiv", "FloatMisc",
        "FloatMult", "FloatMultAcc", "FloatSqrt", "IntAlu", "IntDiv",
        "IntMult", "Matrix", "MatrixMov", "MatrixOP", "MemRead",
        "MemWrite", "No_OpClass", "SimdAdd", "SimdAddAcc", "SimdAes",
        "SimdAesMix", "SimdAlu", "SimdCmp", "SimdCvt", "SimdDiv",
        "SimdFloatAdd", "SimdFloatAlu", "SimdFloatCmp", "SimdFloatDiv",
        "SimdFloatMatMultAcc", "SimdFloatMisc", "SimdFloatMult",
        "SimdFloatMultAcc", "SimdFloatReduceAdd", "SimdFloatReduceCmp",
        "SimdFloatSqrt", "SimdMatMultAcc", "SimdMisc", "SimdMult",
        "SimdMultAcc", "SimdPredAlu", "SimdReduceAdd", "SimdReduceAlu",
        "SimdReduceCmp", "SimdSha1Hash", "SimdSha1Hash2",
        "SimdSha256Hash", "SimdSha256Hash2", "SimdShaSigma2",
        "SimdShaSigma3", "SimdShift", "SimdSqrt",
    };
    static const std::vector<std::string_view> rv64gcNames = {
        "FloatAdd", "FloatCmp", "FloatCvt", "FloatDiv", "FloatMemRead",
        "FloatMemWrite", "FloatMisc", "FloatMult", "FloatMultAcc",
        "FloatSqrt", "IntAlu", "IntDiv", "IntMult", "MemRead",
        "MemWrite", "No_OpClass",
    };
    using Map = std::array<int16_t, enums::Num_OpClass>;
    const auto makeMap = [](const std::vector<std::string_view> &names) {
        Map result;
        result.fill(-1);
        for (size_t op = 0; op < result.size(); ++op) {
            const auto position = std::find(
                names.begin(), names.end(), enums::OpClassStrings[op]);
            if (position != names.end())
                result[op] = std::distance(names.begin(), position);
        }
        return result;
    };
    static const Map x86Map = makeMap(x86Names);
    static const Map aarch64Map = makeMap(aarch64Names);
    static const Map rv64gcMap = makeMap(rv64gcNames);
    const Map &map = isa == "x86_64" ? x86Map :
        (isa == "aarch64" ? aarch64Map : rv64gcMap);
    const size_t op = static_cast<size_t>(opClass);
    fatal_if(op >= map.size() || map[op] < 0,
             "GipsimTracer has no %s exec_type for gem5 OpClass %s",
             isa.c_str(), op < map.size() ? enums::OpClassStrings[op] :
                                            "invalid");
    return map[op];
}

/** 识别 workbegin，以便在其 handler 启用 ROI 时补入刚退休的记录。 */
bool
isWorkBeginEncoding(const std::string &isa,
                  const std::vector<uint8_t> &encoding)
{
    if (isa == "x86_64")
        return encoding.size() == 4 && encoding[0] == 0x0f &&
            encoding[1] == 0x04 && encoding[2] == 0x5a && encoding[3] == 0;
    if (encoding.size() != 4)
        return false;
    const uint32_t instruction = static_cast<uint32_t>(encoding[0]) |
        static_cast<uint32_t>(encoding[1]) << 8 |
        static_cast<uint32_t>(encoding[2]) << 16 |
        static_cast<uint32_t>(encoding[3]) << 24;
    return isa == "aarch64" ? instruction == 0xff5a0110u :
                              instruction == 0xb400007bu;
}

/** 返回一次 REP 字符串迭代应完成的架构访存数；非 REP 返回零。 */
unsigned
x86RepeatMemoryOperations(const std::vector<uint8_t> &encoding)
{
    size_t offset = 0;
    bool repeat = false;
    while (offset < encoding.size()) {
        uint8_t byte = encoding[offset];
        if (byte == 0xf2 || byte == 0xf3) {
            repeat = true;
            ++offset;
        } else if (byte == 0x26 || byte == 0x2e || byte == 0x36 ||
                   byte == 0x3e || byte == 0x64 || byte == 0x65 ||
                   byte == 0x66 || byte == 0x67 || byte == 0xf0 ||
                   (byte >= 0x40 && byte <= 0x4f)) {
            ++offset;
        } else {
            break;
        }
    }
    if (!repeat || offset >= encoding.size()) return 0;
    switch (encoding[offset]) {
      case 0xa4: case 0xa5: case 0xa6: case 0xa7: return 2;
      case 0x6c: case 0x6d: case 0x6e: case 0x6f:
      case 0xaa: case 0xab: case 0xac: case 0xad:
      case 0xae: case 0xaf: return 1;
      default: return 0;
    }
}

/** 从 RV64 A 扩展 encoding 读取 aq/rl，修正 synthetic fence 的歧义。 */
void
rv64gcAtomicOrdering(const std::vector<uint8_t> &encoding,
                     bool &acquire, bool &release)
{
    if (encoding.size() != 4) return;
    const uint32_t instruction =
        static_cast<uint32_t>(encoding[0]) |
        static_cast<uint32_t>(encoding[1]) << 8 |
        static_cast<uint32_t>(encoding[2]) << 16 |
        static_cast<uint32_t>(encoding[3]) << 24;
    if ((instruction & 0x7f) != 0x2f) return;
    acquire = acquire || (instruction & (1u << 26));
    release = release || (instruction & (1u << 25));
}

/** 判断 encoding 是否属于 RV64 A 扩展原子指令。 */
bool
rv64gcAtomicInstruction(const std::vector<uint8_t> &encoding)
{
    if (encoding.size() != 4) return false;
    const uint32_t instruction =
        static_cast<uint32_t>(encoding[0]) |
        static_cast<uint32_t>(encoding[1]) << 8 |
        static_cast<uint32_t>(encoding[2]) << 16 |
        static_cast<uint32_t>(encoding[3]) << 24;
    return (instruction & 0x7f) == 0x2f;
}

/** 识别 BSF/BSR 及其寄存器/内存形式；返回值 1..4，零表示不匹配。 */
uint8_t
x86BitScanKind(const std::vector<uint8_t> &encoding)
{
    size_t offset = 0;
    while (offset < encoding.size()) {
        const uint8_t byte = encoding[offset];
        if (byte == 0x26 || byte == 0x2e || byte == 0x36 ||
            byte == 0x3e || byte == 0x64 || byte == 0x65 ||
            byte == 0x66 || byte == 0x67 || byte == 0xf0 ||
            byte == 0xf2 || byte == 0xf3 ||
            (byte >= 0x40 && byte <= 0x4f)) {
            ++offset;
        } else {
            break;
        }
    }
    if (offset + 2 >= encoding.size() || encoding[offset] != 0x0f ||
        (encoding[offset + 1] != 0xbc && encoding[offset + 1] != 0xbd))
        return 0;
    const bool memory = (encoding[offset + 2] & 0xc0) != 0xc0;
    return (encoding[offset + 1] == 0xbd ? 3 : 1) + memory;
}

/** 判断 encoding 是否为 IRET 指令实例。 */
bool
x86Iret(const std::vector<uint8_t> &encoding)
{
    size_t offset = 0;
    while (offset < encoding.size()) {
        const uint8_t byte = encoding[offset];
        if (byte == 0x26 || byte == 0x2e || byte == 0x36 ||
            byte == 0x3e || byte == 0x64 || byte == 0x65 ||
            byte == 0x66 || byte == 0x67 || byte == 0xf0 ||
            byte == 0xf2 || byte == 0xf3 ||
            (byte >= 0x40 && byte <= 0x4f)) {
            ++offset;
        } else {
            break;
        }
    }
    return offset + 1 == encoding.size() && encoding[offset] == 0xcf;
}

#include "cpu/gipsim_tracer_x86_iret_paths.inc"

/** 从 IRET 前缀恢复 16/32/64 位操作数宽度。 */
unsigned
x86IretOperandSize(const std::vector<uint8_t> &encoding)
{
    unsigned size = 32;
    for (const uint8_t byte : encoding) {
        if (byte == 0x66)
            size = 16;
        else if (byte >= 0x48 && byte <= 0x4f && (byte & 8))
            size = 64;
        if (byte == 0xcf)
            break;
    }
    return size;
}

/** 从审计生成的 IRET shape 表构造指定动态路径。 */
std::vector<GipsimTracer::NormalizedMicroOp>
x86IretPath(unsigned operandSize, unsigned selector)
{
    const char *const *shapes = operandSize == 64 ? x86Iret64PathShapes :
                               operandSize == 16 ? x86Iret16PathShapes :
                                                   x86Iret32PathShapes;
    const size_t shapeCount = operandSize == 64 ?
        std::size(x86Iret64PathShapes) : operandSize == 16 ?
        std::size(x86Iret16PathShapes) : std::size(x86Iret32PathShapes);
    panic_if(selector >= shapeCount,
             "Invalid IRET path selector");
    const char *shape = shapes[selector];
    std::vector<GipsimTracer::NormalizedMicroOp> result;
    const size_t count = std::strlen(shape);
    result.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        const char token = shape[index];
        if (token == 'L')
            result.push_back({"load", "none"});
        else if (token == 'S')
            result.push_back({"store", "none"});
        else if (token == 'B')
            result.push_back({"none",
                index + 1 == count ? "unconditional" : "internal"});
        else
            result.push_back({"none", "none"});
    }
    return result;
}

/** 将实际退休的 IRET 微操作 shape 映射为已审计路径 selector。 */
int
x86IretSelector(const std::vector<uint8_t> &encoding,
                const std::vector<GipsimTracer::NormalizedMicroOp> &actual)
{
    std::string shape;
    shape.reserve(actual.size());
    for (const auto &microop : actual) {
        if (microop.memory == "load")
            shape += 'L';
        else if (microop.memory == "store")
            shape += 'S';
        else if (microop.control != "none")
            shape += 'B';
        else
            shape += 'C';
    }
    const unsigned operandSize = x86IretOperandSize(encoding);
    const char *const *shapes = operandSize == 64 ? x86Iret64PathShapes :
                               operandSize == 16 ? x86Iret16PathShapes :
                                                   x86Iret32PathShapes;
    const size_t shapeCount = operandSize == 64 ?
        std::size(x86Iret64PathShapes) : operandSize == 16 ?
        std::size(x86Iret16PathShapes) : std::size(x86Iret32PathShapes);
    for (size_t selector = 0; selector < shapeCount; ++selector) {
        if (shape == shapes[selector])
            return selector;
    }
    fatal("GipsimTracer observed an unknown IRET micro-op path '%s'",
          shape.c_str());
}

/** 需要按实际退休 shape 选择路径的 x86 指令族。 */
enum X86DynamicKind : uint8_t
{
    X86DynamicNone,
    X86DynamicCmpxchg8b,
    X86DynamicCmpxchg8bLocked,
    X86DynamicCmpxchg16b,
    X86DynamicCmpxchg16bLocked,
    X86DynamicJmpFar,
    X86DynamicLldtReg,
    X86DynamicLldtMem,
    X86DynamicMovSegReg,
    X86DynamicMovSegMem,
    X86DynamicRetFar,
};

#include "cpu/gipsim_tracer_x86_dynamic_paths.inc"

/** 一个 x86 动态指令族的只读 shape 表。 */
struct X86DynamicPathTable
{
    const char *const *shapes;
    size_t count;
};

/** 返回 kind（含 RIP-relative 位）对应的生成路径表。 */
X86DynamicPathTable
x86DynamicPathTable(uint8_t kind)
{
#define X86_PATH_TABLE(name) X86DynamicPathTable{name, std::size(name)}
    const bool ripRelative = kind & 0x80;
    kind &= 0x7f;
    switch (kind) {
      case X86DynamicCmpxchg8b:
        return ripRelative ? X86_PATH_TABLE(x86Cmpxchg8bRipPathShapes) :
                             X86_PATH_TABLE(x86Cmpxchg8bPathShapes);
      case X86DynamicCmpxchg8bLocked:
        return ripRelative ? X86_PATH_TABLE(x86Cmpxchg8bLockedRipPathShapes) :
                             X86_PATH_TABLE(x86Cmpxchg8bLockedPathShapes);
      case X86DynamicCmpxchg16b:
        return ripRelative ? X86_PATH_TABLE(x86Cmpxchg16bRipPathShapes) :
                             X86_PATH_TABLE(x86Cmpxchg16bPathShapes);
      case X86DynamicCmpxchg16bLocked:
        return ripRelative ? X86_PATH_TABLE(x86Cmpxchg16bLockedRipPathShapes) :
                             X86_PATH_TABLE(x86Cmpxchg16bLockedPathShapes);
      case X86DynamicJmpFar:
        return ripRelative ? X86_PATH_TABLE(x86JmpFarRipPathShapes) :
                             X86_PATH_TABLE(x86JmpFarPathShapes);
      case X86DynamicLldtReg: return X86_PATH_TABLE(x86LldtRegPathShapes);
      case X86DynamicLldtMem:
        return ripRelative ? X86_PATH_TABLE(x86LldtMemRipPathShapes) :
                             X86_PATH_TABLE(x86LldtMemPathShapes);
      case X86DynamicMovSegReg:
        return X86_PATH_TABLE(x86MovSegRegPathShapes);
      case X86DynamicMovSegMem:
        return ripRelative ? X86_PATH_TABLE(x86MovSegMemRipPathShapes) :
                             X86_PATH_TABLE(x86MovSegMemPathShapes);
      case X86DynamicRetFar: return X86_PATH_TABLE(x86RetFarPathShapes);
      default: return {nullptr, 0};
    }
#undef X86_PATH_TABLE
}

/** 从 encoding 分类动态 x86 指令族，并保留 RIP-relative 属性。 */
uint8_t
x86DynamicKind(const std::vector<uint8_t> &encoding)
{
    size_t offset = 0;
    uint8_t rex = 0;
    bool locked = false;
    bool address32 = false;
    while (offset < encoding.size()) {
        const uint8_t byte = encoding[offset];
        if (byte == 0xf0) {
            locked = true;
            ++offset;
        } else if (byte >= 0x40 && byte <= 0x4f) {
            rex = byte;
            ++offset;
        } else if (byte == 0x67) {
            address32 = true;
            ++offset;
        } else if (byte == 0x26 || byte == 0x2e || byte == 0x36 ||
                   byte == 0x3e || byte == 0x64 || byte == 0x65 ||
                   byte == 0x66 || byte == 0xf2 ||
                   byte == 0xf3) {
            ++offset;
        } else {
            break;
        }
    }
    if (offset >= encoding.size()) return X86DynamicNone;
    const uint8_t opcode = encoding[offset++];
    const auto withRipRelative = [address32](uint8_t kind, uint8_t modrm) {
        return uint8_t(kind | (!address32 && (modrm & 0xc7) == 0x05 ?
                                0x80 : 0));
    };
    if (opcode == 0xca || opcode == 0xcb) return X86DynamicRetFar;
    if (opcode == 0x8e && offset < encoding.size()) {
        return (encoding[offset] & 0xc0) == 0xc0 ?
            uint8_t(X86DynamicMovSegReg) :
            withRipRelative(X86DynamicMovSegMem, encoding[offset]);
    }
    if (opcode == 0xff && offset < encoding.size() &&
        ((encoding[offset] >> 3) & 7) == 5 &&
        (encoding[offset] & 0xc0) != 0xc0)
        return withRipRelative(X86DynamicJmpFar, encoding[offset]);
    if (opcode != 0x0f || offset >= encoding.size()) return X86DynamicNone;
    const uint8_t opcode2 = encoding[offset++];
    if (offset >= encoding.size()) return X86DynamicNone;
    const uint8_t modrm = encoding[offset];
    if (opcode2 == 0x00 && ((modrm >> 3) & 7) == 2) {
        return (modrm & 0xc0) == 0xc0 ? uint8_t(X86DynamicLldtReg) :
            withRipRelative(X86DynamicLldtMem, modrm);
    }
    if (opcode2 == 0xc7 && ((modrm >> 3) & 7) == 1 &&
        (modrm & 0xc0) != 0xc0) {
        const uint8_t kind = rex & 8 ?
            (locked ? X86DynamicCmpxchg16bLocked : X86DynamicCmpxchg16b) :
            (locked ? X86DynamicCmpxchg8bLocked : X86DynamicCmpxchg8b);
        return withRipRelative(kind, modrm);
    }
    return X86DynamicNone;
}

/** 从生成的 shape 表构造一条 x86 动态路径。 */
std::vector<GipsimTracer::NormalizedMicroOp>
x86DynamicPath(uint8_t kind, unsigned selector)
{
    const auto table = x86DynamicPathTable(kind);
    panic_if(selector >= table.count, "Invalid x86 dynamic path selector");
    const char *shape = table.shapes[selector];
    std::vector<GipsimTracer::NormalizedMicroOp> result;
    const size_t count = std::strlen(shape);
    result.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        const char token = shape[index];
        if (token == 'L')
            result.push_back({"load", "none"});
        else if (token == 'S')
            result.push_back({"store", "none"});
        else if (token == 'A')
            result.push_back({"atomic", "none"});
        else if (token == 'B') {
            const bool endpoint = index + 1 == count;
            const char *control = "internal";
            const uint8_t baseKind = kind & 0x7f;
            if (endpoint && (baseKind == X86DynamicJmpFar ||
                             baseKind == X86DynamicRetFar))
                control = "unconditional";
            result.push_back({"none", control});
        }
        else
            result.push_back({"none", "none"});
    }
    return result;
}

/** 将实际退休微操作 shape 映射到动态指令族的 selector。 */
int
x86DynamicSelector(uint8_t kind,
                   const std::vector<GipsimTracer::NormalizedMicroOp> &actual)
{
    std::string shape;
    shape.reserve(actual.size());
    for (const auto &microop : actual) {
        if (microop.memory == "load") shape += 'L';
        else if (microop.memory == "store") shape += 'S';
        else if (microop.memory == "atomic") shape += 'A';
        else if (microop.control != "none") shape += 'B';
        else shape += 'C';
    }
    const auto table = x86DynamicPathTable(kind);
    for (size_t selector = 0; selector < table.count; ++selector) {
        if (shape == table.shapes[selector]) return selector;
    }
    fatal("GipsimTracer observed unknown x86 dynamic path kind %u shape '%s'",
          kind, shape.c_str());
}

/** 返回 REP 指令族与 path selector 对应的规范 shape。 */
const char *
x86RepeatShape(const std::vector<uint8_t> &encoding, unsigned path)
{
    size_t offset = 0;
    static const char *cmps[] = {
        "CBC", "CBCCCCLLCCCCBC", "CBCCCCLLCCCCB", "LLCCCCB", "LLCCCCBC",
    };
    static const char *scas[] = {
        "CBC", "CBCCCCLCCCBC", "CBCCCCLCCCB", "LCCCB", "LCCCBC",
    };
    static const char *lods[] = {
        "CBC", "CBCCCCLCCBC", "CBCCCCLCCB", "LCCB", "LCCBC",
    };
    static const char *movs[] = {
        "CBC", "CBCCCCLSCCCBC", "CBCCCCLSCCCB", "LSCCCB", "LSCCCBC",
    };
    static const char *stos[] = {
        "CBC", "CBCCCCSCCBC", "CBCCCCSCCB", "SCCB", "SCCBC",
    };
    static const char *ins[] = {
        "CBCC", "CBCCCCCCCSCCBCC", "CBCCCCCCCSCCB", "CSCCB", "CSCCBCC",
    };
    static const char *outs[] = {
        "CBCC", "CBCCCCCCLCCCBCC", "CBCCCCCCLCCCB", "LCCCB", "LCCCBCC",
    };
    while (offset < encoding.size()) {
        const uint8_t byte = encoding[offset];
        if (byte == 0x26 || byte == 0x2e || byte == 0x36 ||
            byte == 0x3e || byte == 0x64 || byte == 0x65 ||
            byte == 0x66 || byte == 0x67 || byte == 0xf0 ||
            byte == 0xf2 || byte == 0xf3 ||
            (byte >= 0x40 && byte <= 0x4f)) ++offset;
        else break;
    }
    panic_if(offset >= encoding.size() || path >= 5,
             "Malformed REP decode path");
    switch (encoding[offset]) {
      case 0xa6: case 0xa7: return cmps[path];
      case 0xae: case 0xaf: return scas[path];
      case 0xac: case 0xad: return lods[path];
      case 0xa4: case 0xa5: return movs[path];
      case 0xaa: case 0xab: return stos[path];
      case 0x6c: case 0x6d: return ins[path];
      case 0x6e: case 0x6f: return outs[path];
      default: panic("Unsupported REP string opcode");
    }
}

/** 根据规范 shape 构造一条 REP 初始、迭代或终止路径。 */
std::vector<GipsimTracer::NormalizedMicroOp>
x86RepeatPath(const std::vector<uint8_t> &encoding, unsigned path)
{
    std::vector<GipsimTracer::NormalizedMicroOp> result;
    for (const char *token = x86RepeatShape(encoding, path); *token; ++token) {
        if (*token == 'L')
            result.push_back({"load", "none"});
        else if (*token == 'S')
            result.push_back({"store", "none"});
        else if (*token == 'B')
            result.push_back({"none", "internal"});
        else
            result.push_back({"none", "none"});
    }
    return result;
}

/** 识别仅访问 gem5 内部状态、没有 trace 架构访存的 x86 指令。 */
bool
x86InternalOnlyMemory(const std::vector<uint8_t> &encoding)
{
    size_t offset = 0;
    while (offset < encoding.size()) {
        const uint8_t byte = encoding[offset];
        if (byte == 0x26 || byte == 0x2e || byte == 0x36 ||
            byte == 0x3e || byte == 0x64 || byte == 0x65 ||
            byte == 0x66 || byte == 0x67 || byte == 0xf0 ||
            byte == 0xf2 || byte == 0xf3 ||
            (byte >= 0x40 && byte <= 0x4f)) {
            ++offset;
        } else {
            break;
        }
    }
    if (offset + 1 >= encoding.size() || encoding[offset] != 0x0f)
        return false;
    return encoding[offset + 1] == 0x30 || encoding[offset + 1] == 0x32;
}

} // anonymous namespace

uint32_t
GipsimTracer::mapExecType(enums::OpClass opClass) const
{
    return traceExecType(isa, opClass);
}

bool
GipsimTracer::isWorkBegin(const std::vector<uint8_t> &encoding) const
{
    return isWorkBeginEncoding(isa, encoding);
}

bool
GipsimTracer::isX86FarJump(uint8_t kind)
{
    return (kind & 0x7f) == X86DynamicJmpFar;
}

int
GipsimTracer::selectX86IretPath(const PendingInstruction &entry) const
{
    return x86IretSelector(entry.encoding, entry.microops);
}

int
GipsimTracer::selectX86DynamicPath(const PendingInstruction &entry) const
{
    return x86DynamicSelector(entry.x86DynamicKind, entry.microops);
}

void
GipsimTracer::beginPending(PendingInstruction &entry,
                          const GipsimTracerRecord &record,
                          const StaticInstPtr &architecturalInst)
{
    entry = PendingInstruction{};
    entry.thread = record.getThread();
    entry.pc = record.getPCState().instAddr();
    fatal_if(!record.getFetchPaddrValid() || record.getEncoding().empty(),
             "GipsimTracer missing executed fetch state at PC %#x", entry.pc);
    entry.ppc = record.getFetchPaddr();
    entry.encoding = record.getEncoding();
    if (isa == "x86_64") {
        entry.repeatMemoryOperations =
            x86RepeatMemoryOperations(entry.encoding);
        entry.bitScanKind = x86BitScanKind(entry.encoding);
        entry.iret = x86Iret(entry.encoding);
        entry.x86DynamicKind = x86DynamicKind(entry.encoding);
    } else {
        entry.branch = architecturalInst->isControl();
        if (isa == "rv64gc") {
            rv64gcAtomicOrdering(entry.encoding, entry.acquire,
                                 entry.release);
        }
        entry.unconditionalBranch = architecturalInst->isUncondCtrl();
        if (isa == "aarch64" && entry.encoding.size() == 4) {
            const uint32_t instruction =
                static_cast<uint32_t>(entry.encoding[0]) |
                static_cast<uint32_t>(entry.encoding[1]) << 8 |
                static_cast<uint32_t>(entry.encoding[2]) << 16 |
                static_cast<uint32_t>(entry.encoding[3]) << 24;
            entry.unconditionalBranch = entry.unconditionalBranch ||
                instruction == 0xd69f03e0u || instruction == 0xd6bf03e0u;
        } else if (isa == "rv64gc" && entry.encoding.size() == 4) {
            const uint32_t instruction =
                static_cast<uint32_t>(entry.encoding[0]) |
                static_cast<uint32_t>(entry.encoding[1]) << 8 |
                static_cast<uint32_t>(entry.encoding[2]) << 16 |
                static_cast<uint32_t>(entry.encoding[3]) << 24;
            entry.unconditionalBranch = entry.unconditionalBranch ||
                instruction == 0x30200073u || instruction == 0x10200073u;
        }
    }
    entry.conditionalMemory = architecturalInst->isStoreConditional() ||
                              architecturalInst->isDataPrefetch() ||
                              entry.repeatMemoryOperations != 0;
    entry.valid = true;
}

bool
GipsimTracer::appendRecord(PendingInstruction &entry,
                          const GipsimTracerRecord &record)
{
    const StaticInstPtr &inst = record.getStaticInst();
    const bool final = !inst->isMicroop() || inst->isLastMicroop();
    if (isa != "x86_64") {
        entry.branch = entry.branch || inst->isControl();
        entry.unconditionalBranch =
            entry.unconditionalBranch || inst->isUncondCtrl();
    } else if (inst->isControl() &&
               (final || inst->isIndirectCtrl() ||
                inst->getName() == "wrip")) {
        /* This is the same StaticInst classification consumed by
         * BaseSimpleCPU's branch predictor.  Non-terminal br controls remain
         * microcode-internal; wrip performs the architectural transfer even
         * when cleanup micro-ops follow it. */
        entry.branch = true;
        entry.unconditionalBranch = entry.unconditionalBranch ||
            inst->isUncondCtrl() || (inst->isIndirectCtrl() && !final);
    }
    entry.conditionalMemory = entry.conditionalMemory ||
        inst->isStoreConditional() || inst->isDataPrefetch() ||
        (inst->isMemRef() && !record.getPredicate());

    /* SVE/SME gather/scatter macroops contain one memory micro-op per
     * potential lane (or structure member).  Their generic instruction
     * predicate can remain true while gem5's separate memory-access
     * predicate suppresses the selected lane.  Preserve that execution-time
     * state in InstRecord instead of inferring it from a missing access. */
    const bool aarch64MemoryMicroop = isa == "aarch64" && inst->isMemRef();
    const auto &recordedMemory = record.getMemoryAccess();
    const bool suppressedPredicatedMemory = inst->isMemRef() &&
        (!record.getPredicate() || !record.getMemAccPredicate() ||
         (aarch64MemoryMicroop && !recordedMemory));

    std::optional<InstRecord::MemoryAccess> memory = recordedMemory;
    const bool hadMemoryAccess = memory.has_value();
    if (memory && isa == "x86_64") {
        auto &access = *memory;
        const auto segment = access.flags & X86ISA::SegmentFlagMask;
        if (segment == X86ISA::segment_idx::Hs ||
            segment == X86ISA::segment_idx::Tsl ||
            segment == X86ISA::segment_idx::Tsg ||
            segment == X86ISA::segment_idx::Ms ||
            segment == X86ISA::segment_idx::Tr ||
            segment == X86ISA::segment_idx::Idtr) {
            memory.reset();
        } else if ((access.paddr >> 60) ==
                   (X86ISA::PhysAddrPrefixLocalAPIC >> 60)) {
            /* gem5 routes each local APIC through a simulator-internal
             * physical prefix.  The trace contract exposes the x86
             * architectural APIC base instead of that routing address. */
            const X86ISA::LocalApicBase base =
                entry.thread->readMiscRegNoEffect(X86ISA::misc_reg::ApicBase);
            access.paddr = (Addr(base.base) << 12) |
                (access.paddr & (X86ISA::PhysAddrAPICRangeSize - 1));
        }
    }
    /* gem5's synthetic RISC-V fence micro-op carries both generic barrier
     * flags even when the architectural AMO has only aq or only rl.  For
     * opcode 0x2f the instruction bits are authoritative; otherwise those
     * generic flags continue to describe real FENCE/other-ISA ordering. */
    if (!(isa == "rv64gc" && rv64gcAtomicInstruction(entry.encoding))) {
        entry.release = entry.release || inst->isWriteBarrier();
        entry.acquire = entry.acquire || inst->isReadBarrier();
        if (memory) {
            const auto &access = *memory;
            if (inst->isWriteBarrier() &&
                access.type != InstRecord::MemoryAccess::Type::Read)
                entry.release = true;
            if (inst->isReadBarrier() &&
                access.type != InstRecord::MemoryAccess::Type::Write)
                entry.acquire = true;
        }
    }
    NormalizedMicroOp microop{"none", "none"};
    microop.predicatedMemory = aarch64MemoryMicroop;
    microop.inactiveMemory = suppressedPredicatedMemory;
    microop.execType = mapExecType(inst->opClass());
    if (inst->isMemRef() && inst->getName() != "cda" &&
        !suppressedPredicatedMemory &&
        !(isa == "x86_64" &&
          (x86InternalOnlyMemory(entry.encoding) ||
           (!memory && hadMemoryAccess)))) {
        microop.memory = inst->isStore() ? "store" : "load";
    } else if (inst->isControl()) {
        microop.control = entry.branch && final ?
            (entry.unconditionalBranch ? "unconditional" : "conditional") :
            "internal";
    }
    for (int index = 0; index < inst->numSrcRegs(); ++index) {
        const RegId &reg = inst->srcRegIdx(index);
        if (!appendTraceRegisters(microop.srcs, isa, reg) &&
            reg.classValue() != InvalidRegClass)
            microop.internalSrcs.push_back(internalRegisterKey(reg));
    }
    for (int index = 0; index < inst->numDestRegs(); ++index) {
        const RegId &reg = inst->destRegIdx(index);
        if (!appendTraceRegisters(microop.dsts, isa, reg) &&
            reg.classValue() != InvalidRegClass)
            microop.internalDsts.push_back(internalRegisterKey(reg));
    }
    /* An inactive predicated memory micro-op still retires as part of the
     * architectural instruction.  Preserve its register/exec dependencies,
     * but classify it as TRIVIAL so it neither consumes nor invents a memory
     * access.  This is the declared memory_count_0 path. */
    entry.microops.push_back(std::move(microop));
    const bool completedMemory = memory.has_value();
    if (entry.repeatMemoryOperations && completedMemory) {
        ++entry.currentRepeatMemoryOperations;
        if (entry.currentRepeatMemoryOperations ==
            entry.repeatMemoryOperations) {
            entry.currentRepeatMemoryOperations = 0;
        } else if (entry.currentRepeatMemoryOperations >
                   entry.repeatMemoryOperations) {
            fatal("too many REP memory operations at PC %#x", entry.pc);
        }
    }
    if (memory)
        entry.memory.push_back(std::move(*memory));
    if (entry.repeatMemoryOperations && inst->isControl() &&
        entry.currentRepeatMemoryOperations == 0 && !entry.memory.empty() &&
        entry.thread->pcState().branching()) {
        const int selector = entry.repeatIterationsEmitted == 0 ? 2 : 3;
        const bool limit = emitInstruction(
            entry, entry.memory, entry.pc, selector);
        ++entry.repeatIterationsEmitted;
        entry.memory.clear();
        entry.microops.clear();
        return limit;
    }
    return false;
}

void
GipsimTracer::finishPending(PendingInstruction &entry)
{
    if (!entry.valid) return;
    if (entry.branch && !entry.microops.empty() &&
        entry.microops.back().control == "none") {
        /* gem5 远转移 ROM 可在 wrip 后还有 eret。微操作序列不变，把唯一的
         * 架构预测/结果消费语义规范化到所选路径末端。 */
        entry.microops.back().control = entry.unconditionalBranch ?
            "unconditional" : "conditional";
    }
    std::unique_ptr<PCStateBase> nextPc(entry.thread->pcState().clone());
    nextPc->advance();
    bool limit = false;
    if (entry.repeatMemoryOperations) {
        if (entry.currentRepeatMemoryOperations)
            fatal("incomplete final REP iteration at PC %#x", entry.pc);
        const int selector = entry.repeatIterationsEmitted == 0 ?
            (entry.memory.empty() ? 0 : 1) : 4;
        limit = emitInstruction(entry, entry.memory, nextPc->instAddr(),
                                selector);
    } else {
        limit = emitInstruction(entry, entry.memory, nextPc->instAddr(), -1);
    }
    entry = PendingInstruction{};
    if (limit) reachInstructionLimit();
}


std::vector<GipsimTracer::NormalizedMicroOp>
GipsimTracer::selectedMicroops(const PendingInstruction &entry,
                              int selector) const
{
    std::vector<NormalizedMicroOp> observed = entry.microops;
    const size_t predicatedMemoryCount = std::count_if(
        observed.begin(), observed.end(),
        [](const auto &uop) { return uop.predicatedMemory; });
    if (predicatedMemoryCount > 1) {
        /* For lane/structure macroops, memory_count_N paths contain only the
         * N active transfer uops plus the fixed non-memory work.  A scalar
         * predicated load/store instead retains its sole inactive transfer as
         * a TRIVIAL uop, matching without_memory() in the description tool. */
        observed.erase(std::remove_if(
            observed.begin(), observed.end(),
            [](const auto &uop) { return uop.inactiveMemory; }),
            observed.end());
    }
    std::vector<NormalizedMicroOp> selected;
    if (entry.repeatMemoryOperations) {
        selected = x86RepeatPath(entry.encoding, selector);
    } else if (entry.bitScanKind) {
        /* BSF/BSR 的分支已经由实际退休的 ROM 微操作精确给出。这里不能
         * 按“寄存器/内存”硬编码长度：RIP-relative 形式还包含 rdip，固定
         * 模板会静默丢掉它。选择器只描述源为零与否，路径本身以实际退休
         * 序列为准。 */
        selected = observed;
    } else if (entry.iret) {
        selected = x86IretPath(x86IretOperandSize(entry.encoding), selector);
    } else if (entry.x86DynamicKind) {
        selected = x86DynamicPath(entry.x86DynamicKind, selector);
    } else {
        selected = observed;
        if (entry.conditionalMemory && selector == 0) {
            for (auto &uop : selected) {
                if (uop.memory != "none") {
                    uop.memory = "none";
                }
            }
        }
    }

    auto sameKind = [](const NormalizedMicroOp &left,
                       const NormalizedMicroOp &right) {
        if (left.memory != "none" || right.memory != "none")
            return left.memory == right.memory;
        return (left.control != "none") == (right.control != "none");
    };
    if (selected.size() == observed.size()) {
        for (size_t index = 0; index < selected.size(); ++index) {
            const auto typeName = selected[index].memory;
            const auto control = selected[index].control;
            selected[index] = observed[index];
            if (typeName != "none") selected[index].memory = typeName;
            if (control != "none") selected[index].control = control;
        }
    } else if (entry.repeatMemoryOperations && selector == 4) {
        /* The terminal REP path is a suffix of the retired micro-op stream.
         * Match it backwards so the synthetic terminal/fault slot cannot be
         * populated from an earlier loop-body arithmetic micro-op. */
        size_t cursor = observed.size();
        for (size_t index = selected.size(); index-- > 0;) {
            while (cursor != 0 &&
                   !sameKind(selected[index], observed[cursor - 1]))
                --cursor;
            if (cursor == 0)
                break;
            const auto typeName = selected[index].memory;
            const auto control = selected[index].control;
            selected[index] = observed[--cursor];
            if (typeName != "none") selected[index].memory = typeName;
            if (control != "none") selected[index].control = control;
            selected[index].successors.clear();
        }
    } else {
        size_t cursor = 0;
        for (auto &uop : selected) {
            while (cursor < observed.size() &&
                   !sameKind(uop, observed[cursor])) ++cursor;
            if (cursor == observed.size()) break;
            const auto typeName = uop.memory;
            const auto control = uop.control;
            uop = observed[cursor++];
            if (typeName != "none") uop.memory = typeName;
            if (control != "none") uop.control = control;
            uop.successors.clear();
        }
    }
    for (auto &uop : selected) {
        if (uop.control == "internal") uop.control = "none";
    }
    if (entry.conditionalMemory && selector == 0) {
        for (auto &uop : selected) {
            if (uop.memory != "none") {
                uop.memory = "none";
            }
        }
    }
    if (entry.branch && !selected.empty()) {
        selected.back().memory = "none";
        selected.back().control = entry.unconditionalBranch ?
            "unconditional" : "conditional";
    }
    for (auto &uop : selected) {
        std::sort(uop.srcs.begin(), uop.srcs.end());
        uop.srcs.erase(std::unique(uop.srcs.begin(), uop.srcs.end()),
                       uop.srcs.end());
        std::sort(uop.dsts.begin(), uop.dsts.end());
        uop.dsts.erase(std::unique(uop.dsts.begin(), uop.dsts.end()),
                       uop.dsts.end());
    }
    /* successors is reserved for dependencies which cannot travel through
     * architectural srcs/dsts.  Derive it from gem5's internal registers
     * after selecting the actual dynamic path, so path slicing cannot leave
     * stale relative offsets behind. */
    for (auto &uop : selected)
        uop.successors.clear();
    std::unordered_map<uint64_t, size_t> reachingDefinition;
    for (size_t consumer = 0; consumer < selected.size(); ++consumer) {
        std::set<size_t> producers;
        for (const uint64_t reg : selected[consumer].internalSrcs) {
            const auto producer = reachingDefinition.find(reg);
            if (producer != reachingDefinition.end())
                producers.insert(producer->second);
        }
        for (const size_t producer : producers)
            selected[producer].successors.push_back(consumer - producer);
        for (const uint64_t reg : selected[consumer].internalDsts)
            reachingDefinition[reg] = consumer;
    }
    for (auto &uop : selected) {
        std::vector<uint64_t>().swap(uop.internalSrcs);
        std::vector<uint64_t>().swap(uop.internalDsts);
    }
    return selected;
}

} // namespace gem5::trace
