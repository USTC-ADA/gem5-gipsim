"""声明向 gem5 编译后 ISA decoder 发起批量查询的 SimObject。

该对象只把外部提供的指令编码交给 decoder，并将 StaticInst/micro-op 元数据写成
JSONL；它不执行指令、不采集退休 trace，也不是被仿真硬件配置的一部分。
"""

from m5.objects.InstDecoder import InstDecoder
from m5.params import Param
from m5.SimObject import SimObject


class DecoderQuery(SimObject):
    type = "DecoderQuery"
    cxx_class = "gem5::DecoderQuery"
    cxx_header = "arch/generic/decoder_query.hh"

    decoder = Param.InstDecoder("gem5 ISA decoder used by the query")
    isa_name = Param.String("x86_64, aarch64, or rv64gc")
    input_file = Param.String("tab-separated encoding id and bytes")
    output_file = Param.String("JSON-lines decoder metadata output")
