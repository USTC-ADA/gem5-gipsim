"""声明生成 gipsim-microop-trace 目录的退休期 tracer。"""

from m5.objects.InstTracer import InstTracer
from m5.params import *


class GipsimTracer(InstTracer):
    type = "GipsimTracer"
    cxx_class = "gem5::trace::GipsimTracer"
    cxx_header = "cpu/gipsim_tracer.hh"

    trace_dir = Param.String("gipsim-trace", "ROI trace output directory")
    isa = Param.String("", "x86_64, aarch64, or rv64gc")
    num_cores = Param.Unsigned(1, "Number of traced CPU cores")
    max_instructions = Param.Counter(
        0,
        "Maximum total ROI trace instruction records; zero means unlimited",
    )
