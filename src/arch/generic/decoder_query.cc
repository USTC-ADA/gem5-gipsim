/*
 * 实现 DecoderQuery：读取“编码 ID + 指令字节”，调用 gem5 编译后的 ISA
 * decoder，展开宏指令及 x86 可达 microcode ROM，并把查询到的静态
 * micro-op 元数据写成 JSONL。该实现不执行指令，也不参与生产 trace。
 */

#include "arch/generic/decoder_query.hh"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "arch/arm/pcstate.hh"
#include "arch/generic/decoder.hh"
#include "arch/riscv/pcstate.hh"
#include "arch/x86/decoder.hh"
#include "arch/x86/insts/badmicroop.hh"
#include "arch/x86/insts/microldstop.hh"
#include "arch/x86/pcstate.hh"
#include "arch/x86/regs/misc.hh"
#include "base/logging.hh"
#include "cpu/static_inst.hh"
#include "enums/OpClass.hh"
#include "sim/sim_exit.hh"

namespace gem5
{

namespace
{

std::string
jsonString(const std::string &input)
{
    std::ostringstream output;
    output << '"';
    for (const unsigned char value : input) {
        switch (value) {
          case '"': output << "\\\""; break;
          case '\\': output << "\\\\"; break;
          case '\b': output << "\\b"; break;
          case '\f': output << "\\f"; break;
          case '\n': output << "\\n"; break;
          case '\r': output << "\\r"; break;
          case '\t': output << "\\t"; break;
          default:
            if (value < 0x20) {
                output << "\\u" << std::hex << std::setw(4)
                       << std::setfill('0') << static_cast<unsigned>(value)
                       << std::dec;
            } else {
                output << static_cast<char>(value);
            }
        }
    }
    output << '"';
    return output.str();
}

std::vector<uint8_t>
parseHex(const std::string &text)
{
    if (text.empty() || text.size() % 2)
        fatal("DecoderQuery received malformed byte string '%s'",
              text);
    std::vector<uint8_t> bytes;
    bytes.reserve(text.size() / 2);
    for (size_t offset = 0; offset < text.size(); offset += 2) {
        const std::string pair = text.substr(offset, 2);
        if (!std::isxdigit(static_cast<unsigned char>(pair[0])) ||
            !std::isxdigit(static_cast<unsigned char>(pair[1]))) {
            fatal("DecoderQuery received malformed byte string "
                  "'%s'", text);
        }
        bytes.push_back(static_cast<uint8_t>(std::stoul(pair, nullptr, 16)));
    }
    return bytes;
}

std::unique_ptr<PCStateBase>
newPCState(const std::string &isa_name)
{
    if (isa_name == "x86_64")
        return std::make_unique<X86ISA::PCState>(0);
    if (isa_name == "aarch64") {
        auto pc = std::make_unique<ArmISA::PCState>(0);
        pc->aarch64(true);
        pc->nextAArch64(true);
        return pc;
    }
    if (isa_name == "rv64gc")
        return std::make_unique<RiscvISA::PCState>(0, RiscvISA::RV64);
    fatal("DecoderQuery does not support ISA '%s'", isa_name);
}

StaticInstPtr
decode(InstDecoder *decoder, const std::string &isa_name,
       const std::vector<uint8_t> &bytes)
{
    decoder->reset();
    auto pc = newPCState(isa_name);
    size_t offset = 0;
    bool supplied = false;
    while (!decoder->instReady()) {
        // Some ISA decoders preserve their previous outOfBytes value in
        // reset(); a fresh, independent export item must still receive its
        // first fetch block.
        if (supplied && !decoder->needMoreBytes())
            fatal("DecoderQuery decoder stalled for ISA '%s'",
                  isa_name);
        const size_t chunk_size = decoder->moreBytesSize();
        std::memset(decoder->moreBytesPtr(), 0, chunk_size);
        const size_t available = offset < bytes.size() ?
            std::min(chunk_size, bytes.size() - offset) : 0;
        if (available)
            std::memcpy(decoder->moreBytesPtr(), bytes.data() + offset,
                        available);
        decoder->moreBytes(*pc, offset);
        supplied = true;
        offset += chunk_size;
        if (offset > bytes.size() + chunk_size)
            fatal("DecoderQuery exhausted bytes without decoding "
                  "ISA '%s'",
                  isa_name);
    }
    StaticInstPtr inst = decoder->decode(*pc);
    if (!inst)
        fatal("DecoderQuery decoder returned a null instruction "
              "for ISA '%s'",
              isa_name);
    return inst;
}

std::string
flags(const StaticInstPtr &inst)
{
    std::ostringstream output;
    inst->printFlags(output, ",");
    return output.str();
}

void
writeRegisters(std::ostream &output, const StaticInstPtr &inst, bool sources)
{
    const int count = sources ? inst->numSrcRegs() : inst->numDestRegs();
    output << '[';
    for (int index = 0; index < count; ++index) {
        if (index)
            output << ',';
        const RegId &reg = sources ? inst->srcRegIdx(index) :
                                     inst->destRegIdx(index);
        output << '[' << static_cast<int>(reg.classValue()) << ','
               << reg.index() << ']';
    }
    output << ']';
}

void
writeMicroop(std::ostream &output, const StaticInstPtr &inst, size_t index)
{
    output << "{\"index\":" << index
           << ",\"name\":" << jsonString(inst->getName())
           << ",\"disassembly\":" << jsonString(inst->disassemble(0))
           << ",\"op_class\":"
           << jsonString(enums::OpClassStrings[inst->opClass()])
           << ",\"flags\":" << jsonString(flags(inst))
           << ",\"mem_ref\":" << (inst->isMemRef() ? "true" : "false")
           << ",\"load\":" << (inst->isLoad() ? "true" : "false")
           << ",\"store\":" << (inst->isStore() ? "true" : "false")
           << ",\"atomic\":" << (inst->isAtomic() ? "true" : "false")
           << ",\"store_conditional\":"
           << (inst->isStoreConditional() ? "true" : "false")
           << ",\"control\":" << (inst->isControl() ? "true" : "false")
           << ",\"conditional_control\":"
           << (inst->isCondCtrl() ? "true" : "false")
           << ",\"unconditional_control\":"
           << (inst->isUncondCtrl() ? "true" : "false")
           << ",\"first\":" << (inst->isFirstMicroop() ? "true" : "false")
           << ",\"last\":" << (inst->isLastMicroop() ? "true" : "false")
           << ",\"src_regs\":";
    writeRegisters(output, inst, true);
    output << ",\"dst_regs\":";
    writeRegisters(output, inst, false);
    if (const auto *memory = dynamic_cast<const X86ISA::MemOp *>(inst.get())) {
        // Width of the active micro-op operand, not a cache transaction.
        const unsigned parts =
            dynamic_cast<const X86ISA::LdStSplitOp *>(inst.get()) ? 2 : 1;
        output << ",\"memory_bytes\":" << parts * memory->dataSize;
    }
    output << '}';
}

std::set<MicroPC>
x86RomTargets(const std::vector<StaticInstPtr> &microops)
{
    static const std::regex branchTarget(R"(\bbr\s+0x([0-9a-fA-F]+))");
    std::set<MicroPC> result;
    for (const auto &microop : microops) {
        std::smatch match;
        const std::string disassembly = microop->disassemble(0);
        if (std::regex_search(disassembly, match, branchTarget)) {
            const auto target = static_cast<MicroPC>(
                std::stoull(match[1].str(), nullptr, 16));
            if (target & 0x8000)
                result.insert(target);
        }
    }
    return result;
}

} // anonymous namespace

DecoderQuery::DecoderQuery(const Params &params)
    : SimObject(params), decoder(params.decoder), isaName(params.isa_name),
      inputFile(params.input_file), outputFile(params.output_file)
{
    if (isaName == "x86_64") {
        X86ISA::HandyM5Reg mode = 0;
        mode.mode = X86ISA::LongMode;
        mode.submode = X86ISA::SixtyFourBitMode;
        mode.cpl = 0;
        mode.defOp = 2;
        mode.altOp = 1;
        mode.defAddr = 3;
        mode.altAddr = 2;
        mode.stack = 3;
        decoder->as<X86ISA::Decoder>().setM5Reg(mode);
    }
}

void
DecoderQuery::startup()
{
    std::ifstream input(inputFile);
    std::ofstream output(outputFile, std::ios::out | std::ios::trunc);
    if (!input)
        fatal("DecoderQuery cannot open input '%s'", inputFile);
    if (!output)
        fatal("DecoderQuery cannot open output '%s'", outputFile);

    output << "{\"record\":\"header\",\"format\":"
           << "\"gem5-decoder-metadata-v2\",\"isa\":"
           << jsonString(isaName) << "}\n";

    std::string line;
    size_t count = 0;
    while (std::getline(input, line)) {
        if (line.empty() || line[0] == '#')
            continue;
        const size_t separator = line.find('\t');
        if (separator == std::string::npos)
            fatal("DecoderQuery input line lacks a tab: '%s'",
                  line);
        const std::string id = line.substr(0, separator);
        const std::string encoding = line.substr(separator + 1);
        StaticInstPtr inst = decode(decoder, isaName, parseHex(encoding));

        output << "{\"record\":\"decode\",\"id\":" << jsonString(id)
               << ",\"encoding\":" << jsonString(encoding)
               << ",\"name\":" << jsonString(inst->getName())
               << ",\"disassembly\":" << jsonString(inst->disassemble(0))
               << ",\"macroop\":" << (inst->isMacroop() ? "true" : "false")
               << ",\"flags\":" << jsonString(flags(inst))
               << ",\"microops\":[";

        bool first = true;
        bool terminated = true;
        std::vector<StaticInstPtr> decodedMicroops;
        if (!inst->isMacroop()) {
            writeMicroop(output, inst, 0);
            decodedMicroops.push_back(inst);
        } else {
            terminated = false;
            for (size_t upc = 0; upc < 4096; ++upc) {
                StaticInstPtr microop = inst->fetchMicroop(upc);
                if (isaName == "x86_64" &&
                    microop == X86ISA::badMicroop) {
                    terminated = true;
                    break;
                }
                if (!first)
                    output << ',';
                writeMicroop(output, microop, upc);
                decodedMicroops.push_back(microop);
                first = false;
                if (microop->isLastMicroop()) {
                    terminated = true;
                    break;
                }
            }
        }
        if (!terminated)
            fatal("DecoderQuery exceeded 4096 uops for '%s'", id);
        output << "]";
        if (isaName == "x86_64") {
            auto &x86Decoder = decoder->as<X86ISA::Decoder>();
            output << ",\"rom_blocks\":[";
            bool firstBlock = true;
            std::set<MicroPC> pendingTargets = x86RomTargets(decodedMicroops);
            std::set<MicroPC> emittedTargets;
            while (!pendingTargets.empty()) {
                const MicroPC entry = *pendingTargets.begin();
                pendingTargets.erase(pendingTargets.begin());
                if (!emittedTargets.insert(entry).second)
                    continue;
                if (!firstBlock)
                    output << ',';
                firstBlock = false;
                output << "{\"entry\":" << entry << ",\"microops\":[";
                bool firstRomMicroop = true;
                bool romTerminated = false;
                std::vector<StaticInstPtr> romMicroops;
                for (MicroPC upc = entry; upc < entry + 4096; ++upc) {
                    StaticInstPtr microop =
                        x86Decoder.fetchRomMicroop(upc, inst);
                    if (microop == X86ISA::badMicroop)
                        break;
                    if (!firstRomMicroop)
                        output << ',';
                    writeMicroop(output, microop, upc);
                    romMicroops.push_back(microop);
                    firstRomMicroop = false;
                    if (microop->isLastMicroop()) {
                        romTerminated = true;
                        break;
                    }
                }
                if (!romTerminated)
                    fatal("DecoderQuery did not find ROM "
                          "termination for '%s'",
                          id);
                for (const MicroPC target : x86RomTargets(romMicroops)) {
                    if (!emittedTargets.count(target))
                        pendingTargets.insert(target);
                }
                output << "]}";
            }
            output << ']';
        }
        output << "}\n";
        ++count;
    }
    output.close();
    inform("DecoderQuery decoded %d %s encodings into %s", count,
           isaName, outputFile);
    exitSimLoop("decoder query complete");
}

} // namespace gem5
