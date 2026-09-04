/*
 * DecoderQuery 是 decode-only 批量查询器。它把外部提供的指令编码交给
 * gem5 编译后的 ISA decoder，并返回 StaticInst/micro-op 元数据；它不执行
 * 指令、不采集退休 trace，也不是被仿真硬件配置的一部分。
 */

#ifndef __ARCH_GENERIC_DECODER_QUERY_HH__
#define __ARCH_GENERIC_DECODER_QUERY_HH__

#include <string>

#include "params/DecoderQuery.hh"
#include "sim/sim_object.hh"

namespace gem5
{

class InstDecoder;

/**
 * 供 gipsim ISA 描述生成器使用的 decode-only 批量查询对象。
 *
 * startup() 逐行读取“encoding ID + 指令字节”，调用 gem5 自己的 decoder，
 * 展开普通 macro-op 与可达的 x86 microcode ROM，并把查询结果写成 JSONL。
 * 它不会执行指令，也不属于被仿真硬件配置。
 */
class DecoderQuery : public SimObject
{
  public:
    PARAMS(DecoderQuery);

    /** 保存 decoder 与批量输入/输出参数，查询在 startup() 中执行。 */
    explicit DecoderQuery(const Params &params);

    /** 执行全部查询、写出结果后终止 decode-only 仿真。 */
    void startup() override;

  private:
    /** 接受批量查询的 gem5 ISA decoder。 */
    InstDecoder *decoder;
    /** x86_64、aarch64 或 rv64gc。 */
    const std::string isaName;
    /** 制表符分隔的 encoding ID 与十六进制字节输入。 */
    const std::string inputFile;
    /** JSONL 查询结果输出。 */
    const std::string outputFile;
};

} // namespace gem5

#endif // __ARCH_GENERIC_DECODER_QUERY_HH__
