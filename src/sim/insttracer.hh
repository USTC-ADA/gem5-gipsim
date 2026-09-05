/*
 * Copyright (c) 2014, 2017, 2020, 2023 Arm Limited
 * All rights reserved
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Copyright (c) 2001-2005 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __INSTRECORD_HH__
#define __INSTRECORD_HH__

#include <cassert>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "arch/generic/pcstate.hh"
#include "base/types.hh"
#include "cpu/inst_res.hh"
#include "cpu/inst_seq.hh"
#include "cpu/static_inst.hh"
#include "params/InstTracer.hh"
#include "sim/sim_object.hh"

namespace gem5
{

class ThreadContext;

namespace trace {

class InstRecord
{
  public:
    struct MemoryAccess
    {
        enum class Type
        {
            Read,
            Write,
            Atomic,
        };

        Addr vaddr;
        Addr paddr;
        Addr size;
        unsigned flags;
        Type type;
        /** Value returned by a load or AMO; empty for a plain store. */
        std::vector<uint8_t> readValue;
        /** Value written by a store or AMO; empty for a plain load. */
        std::vector<uint8_t> writtenValue;
        /** Enabled bytes in this logical access; empty means all enabled. */
        std::vector<bool> byteEnable;
    };

  protected:
    virtual void onFetchedInstruction() {}

    Tick when;

    // The following fields are initialized by the constructor and
    // thus guaranteed to be valid.
    ThreadContext *thread;
    // need to make this ref-counted so it doesn't go away before we
    // dump the record
    StaticInstPtr staticInst;
    std::unique_ptr<PCStateBase> pc;
    StaticInstPtr macroStaticInst;

    // The remaining fields are only valid for particular instruction
    // types (e.g, addresses for memory ops) or when particular
    // options are enabled (e.g., tracing full register contents).
    // Each data field has an associated valid flag to indicate
    // whether the data field is valid.

    /*** @defgroup mem
     * @{
     * Memory request information in the instruction accessed memory.
     * @see mem_valid
     */
    Addr addr = 0; ///< The address that was accessed
    Addr size = 0; ///< The size of the memory request
    unsigned flags = 0; ///< The flags that were assigned to the request.

    /** @} */

    /** @defgroup data
     * If this instruction wrote any data values they're recorded here
     * WARNING: Instructions are quite loose with with what they write
     * since many instructions write multiple values (e.g. destintation
     * register, flags, status, ...) This only captures the last write.
     * @TODO fix this and record all destintations that an instruction writes
     * @see data_status
     */
    union Data
    {
        ~Data() {}
        Data() {}
        uint64_t asInt = 0;
        double asDouble;
        InstResult asReg;
    } data;

    /** @defgroup fetch_seq
     * This records the serial number that the instruction was fetched in.
     * @see fetch_seq_valid
     */
    InstSeqNum fetch_seq = 0;

    /** @defgroup commit_seq
     * This records the instruction number that was committed in the pipeline
     * @see cp_seq_valid
     */
    InstSeqNum cp_seq = 0;

    /** @ingroup data
     * What size of data was written?
     */
    enum DataStatus
    {
        DataInvalid = 0,
        DataInt8 = 1,   // set to equal number of bytes
        DataInt16 = 2,
        DataInt32 = 4,
        DataInt64 = 8,
        DataDouble = 3,
        DataReg = 5
    } dataStatus = DataInvalid;

    /** @ingroup memory
     * Are the memory fields in the record valid?
     */
    bool mem_valid = false;

    /**
     * The completed logical memory access of this dynamic micro-op, if any.
     * A CPU may split that access into multiple internal transactions, but
     * those fragments are deliberately not exposed through InstRecord.  The
     * value is installed only after translation and after a conditional
     * access has been confirmed to occur.
     */
    std::optional<MemoryAccess> memoryAccess;

    /** @ingroup fetch_seq
     * Are the fetch sequence number fields valid?
     */
    bool fetch_seq_valid = false;
    /** @ingroup commit_seq
     * Are the commit sequence number fields valid?
     */
    bool cp_seq_valid = false;

    /** is the predicate for execution this inst true or false (not execed)?
     */
    bool predicate = true;

    /**
     * Is the instruction's memory access predicate true?  This is separate
     * from the generic execution predicate for vector memory micro-ops whose
     * instruction body executes while the selected lane performs no access.
     */
    bool memAccPredicate = true;

    /** Physical first byte address of the architectural instruction fetch. */
    Addr fetchPaddr = 0;
    bool fetchPaddrValid = false;
    std::vector<uint8_t> encoding;

    /**
     * Did the execution of this instruction fault? (requires ExecFaulting
     * to be enabled)
     */
    bool faulting = false;

  public:
    InstRecord(Tick _when, ThreadContext *_thread,
               const StaticInstPtr _staticInst, const PCStateBase &_pc,
               const StaticInstPtr _macroStaticInst=nullptr)
        : when(_when), thread(_thread), staticInst(_staticInst),
        pc(_pc.clone()), macroStaticInst(_macroStaticInst)
    {}

    virtual ~InstRecord()
    {
        if (dataStatus == DataReg)
            data.asReg.~InstResult();
    }

    void setWhen(Tick new_when) { when = new_when; }
    void
    setMem(Addr a, Addr s, unsigned f)
    {
        addr = a;
        size = s;
        flags = f;
        mem_valid = true;
    }

    void
    setMemoryAccess(Addr vaddr, Addr paddr, Addr size, unsigned flags,
                    MemoryAccess::Type type,
                    const uint8_t *read_value = nullptr,
                    const uint8_t *written_value = nullptr,
                    const std::vector<bool> &byte_enable = {})
    {
        assert(!memoryAccess.has_value());
        assert(byte_enable.empty() || byte_enable.size() == size);
        MemoryAccess access{vaddr, paddr, size, flags, type, {}, {},
                            byte_enable};
        if (read_value)
            access.readValue.assign(read_value, read_value + size);
        if (written_value)
            access.writtenValue.assign(written_value, written_value + size);
        memoryAccess = std::move(access);
    }

    template <typename T, size_t N>
    void
    setData(std::array<T, N> d)
    {
        data.asInt = d[0];
        dataStatus = (DataStatus)sizeof(T);
        static_assert(sizeof(T) == DataInt8 || sizeof(T) == DataInt16 ||
                      sizeof(T) == DataInt32 || sizeof(T) == DataInt64,
                      "Type T has an unrecognized size.");
    }

    void
    setData(uint64_t d)
    {
        data.asInt = d;
        dataStatus = DataInt64;
    }
    void
    setData(uint32_t d)
    {
        data.asInt = d;
        dataStatus = DataInt32;
    }
    void
    setData(uint16_t d)
    {
        data.asInt = d;
        dataStatus = DataInt16;
    }
    void
    setData(uint8_t d)
    {
        data.asInt = d;
        dataStatus = DataInt8;
    }

    void setData(int64_t d) { setData((uint64_t)d); }
    void setData(int32_t d) { setData((uint32_t)d); }
    void setData(int16_t d) { setData((uint16_t)d); }
    void setData(int8_t d)  { setData((uint8_t)d); }

    void
    setData(double d)
    {
        data.asDouble = d;
        dataStatus = DataDouble;
    }

    void
    setData(const RegClass &reg_class, RegVal val)
    {
        new(&data.asReg) InstResult(reg_class, val);
        switch (reg_class.type()) {
            case IntRegClass:
            case MiscRegClass:
            case CCRegClass:
                dataStatus = DataInt64;
                break;
            case FloatRegClass:
                dataStatus = DataDouble;
                break;
            default:
                dataStatus = DataReg;
                break;
        }
    }

    void
    setData(const RegClass &reg_class, const void *val)
    {
        new(&data.asReg) InstResult(reg_class, val);
        switch (reg_class.type()) {
            case IntRegClass:
            case MiscRegClass:
            case CCRegClass:
                dataStatus = DataInt64;
                break;
            case FloatRegClass:
                dataStatus = DataDouble;
                break;
            default:
                dataStatus = DataReg;
                break;
        }
    }

    void
    setFetchSeq(InstSeqNum seq)
    {
        fetch_seq = seq;
        fetch_seq_valid = true;
    }

    void
    setCPSeq(InstSeqNum seq)
    {
        cp_seq = seq;
        cp_seq_valid = true;
    }

    void setPredicate(bool val) { predicate = val; }
    void setMemAccPredicate(bool val) { memAccPredicate = val; }

    void
    setFetchPaddr(Addr value)
    {
        fetchPaddr = value;
        fetchPaddrValid = true;
    }

    void
    setFetchedInstruction(Addr paddr, std::vector<uint8_t> bytes)
    {
        setFetchPaddr(paddr);
        encoding = std::move(bytes);
        onFetchedInstruction();
    }

    void setFaulting(bool val) { faulting = val; }

    /*
     * Most tracers only request faulting records when ExecFaulting is
     * enabled.  Retirement tracers may additionally need a notification to
     * discard micro-ops already accumulated for a faulting macro-op.
     */
    virtual bool needsFaultNotification() const { return false; }

    virtual void dump() = 0;

  public:
    Tick getWhen() const { return when; }
    ThreadContext *getThread() const { return thread; }
    StaticInstPtr getStaticInst() const { return staticInst; }
    const PCStateBase &getPCState() const { return *pc; }
    StaticInstPtr getMacroStaticInst() const { return macroStaticInst; }

    Addr getAddr() const { return addr; }
    Addr getSize() const { return size; }
    unsigned getFlags() const { return flags; }
    bool getMemValid() const { return mem_valid; }
    const std::optional<MemoryAccess> &getMemoryAccess() const
    {
        return memoryAccess;
    }

    uint64_t getIntData() const { return data.asInt; }
    double getFloatData() const { return data.asDouble; }
    int getDataStatus() const { return dataStatus; }

    InstSeqNum getFetchSeq() const { return fetch_seq; }
    bool getFetchSeqValid() const { return fetch_seq_valid; }

    InstSeqNum getCpSeq() const { return cp_seq; }
    bool getCpSeqValid() const { return cp_seq_valid; }

    bool getFaulting() const { return faulting; }
    bool getPredicate() const { return predicate; }
    bool getMemAccPredicate() const { return memAccPredicate; }
    bool getFetchPaddrValid() const { return fetchPaddrValid; }
    Addr getFetchPaddr() const { return fetchPaddr; }
    const std::vector<uint8_t> &getEncoding() const { return encoding; }
};

/**
 * The base InstDisassembler class provides a one-API interface
 * to disassemble the instruction passed as a first argument.
 * It also provides a base implementation which is
 * simply calling the StaticInst::disassemble method, which
 * is the usual interface for disassembling
 * a gem5 instruction.
 */
class InstDisassembler : public SimObject
{
  public:
    InstDisassembler(const SimObjectParams &params)
      : SimObject(params)
    {}

    virtual std::string
    disassemble(StaticInstPtr inst,
                const PCStateBase &pc,
                const loader::SymbolTable *symtab) const
    {
        return inst->disassemble(pc.instAddr(), symtab);
    }
};

class InstTracer : public SimObject
{
  public:
    PARAMS(InstTracer);
    InstTracer(const Params &p)
      : SimObject(p), disassembler(p.disassembler)
    {}

    virtual ~InstTracer() {}

    /** ROI control invoked by simulation exit-event handlers. */
    virtual void startROI() {}
    virtual void endROI(const std::string &reason) {}

    virtual InstRecord *
        getInstRecord(Tick when, ThreadContext *tc,
                const StaticInstPtr staticInst, const PCStateBase &pc,
                const StaticInstPtr macroStaticInst=nullptr) = 0;

    std::string
    disassemble(StaticInstPtr inst,
                const PCStateBase &pc,
                const loader::SymbolTable *symtab=nullptr) const
    {
        return disassembler->disassemble(inst, pc, symtab);
    }

  private:
    InstDisassembler *disassembler;
};

} // namespace trace
} // namespace gem5

#endif // __INSTRECORD_HH__
