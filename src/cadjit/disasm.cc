module;

#include <capstone/capstone.h>
#include <rfl/json.hpp>

module cadjit;

import dxx.assert;
import dxx.cstd.fixed;
import std;

namespace assert = dxx::assert;

namespace cadjit {

using cs_reg_t = x86_reg;
using cs_op_t  = cs_x86_op;

static const std::map<cs_reg_t, std::optional<reg_t>> reg_map{
    { X86_REG_EAX,     reg_t::eax },
    { X86_REG_RBP,     reg_t::rbp },
    { X86_REG_RIP,     reg_t::rip },
    { X86_REG_XMM0,    reg_t::xmm0 },
    { X86_REG_XMM1,    reg_t::xmm1 },
    { X86_REG_XMM2,    reg_t::xmm2 },
    { X86_REG_XMM3,    reg_t::xmm3 },
    { X86_REG_INVALID, std::nullopt },
}; // <-- reg_map

value_t make_value(cs_op_t op, uptr rip) {
    assert::always(op.type != X86_OP_INVALID);

    switch (op.type) {
    case X86_OP_IMM:
        return imm_t{ .value = op.imm };
    case X86_OP_REG:
        return reg_map.at(op.reg).value();
    case X86_OP_MEM:
        return mem_t{
            .segment      = reg_map.at(op.mem.segment),
            .base         = reg_map.at(op.mem.base),
            .index        = reg_map.at(op.mem.index),
            .scale        = op.mem.scale,
            .displacement = op.mem.disp,

            .rip          = rip,
        };
    }
} // <-- make_value(op)


std::vector<code::Instruction> disassemble(const void* function) {
    csh handle;

    assert::always(cs_open(CS_ARCH_X86, CS_MODE_64, &handle)   == CS_ERR_OK);
    assert::always(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);

    std::vector<code::Instruction> ret{};

    auto cur = reinterpret_cast<const u8*>(function);
    cs_insn* insn;
    //uz count = 0;
    do {
        cs_disasm(handle, cur, 256, reinterpret_cast<u64>(cur), 1, &insn);

        if (options.debug) {
            std::println(
                "{:#08x} | {:#08x} | {} {}",
                reinterpret_cast<uptr>(cur),
                insn->address,
                insn->mnemonic,
                insn->op_str
            );
        }

        /*
        if (count == 3) {
            std::println("COUNT 3, grab rip-relative value");
            const auto ptr = reinterpret_cast<uptr>(cur) + insn->size + 0x24fc63;
            std::println("Grab value at {:#08x}: {}", ptr, *reinterpret_cast<const float*>(ptr));
        }
        */

        ret.emplace_back(
            code::Instruction{
                .address     = insn->address,
                .instruction = code::Misc{}
            }
        );
        auto& cur_inst = ret.back();

        const auto& x86 = insn->detail->x86;

        // rip points to the next instruction
        const uptr rip = insn->address + insn->size;

        switch (insn->id) {
        case X86_INS_MOVSS:
        case X86_INS_MOVAPS:
            assert::always(x86.op_count == 2);
            cur_inst.instruction = code::Move{
                .from = make_value(x86.operands[1], rip),
                .to   = make_value(x86.operands[0], rip),
            };
            break;
        case X86_INS_MOVD:
            assert::always(x86.op_count == 2);
            cur_inst.instruction = code::Move{
                .from = make_value(x86.operands[1], rip),
                .to   = make_value(x86.operands[0], rip),
            };
            break;
        case X86_INS_XOR: {
            // TODO: This can't possibly be the only case to XOR something with 0x80000000
            assert::always(x86.op_count == 2);
            const auto& op1 = x86.operands[1];
            if (op1.type == X86_OP_IMM && op1.imm == 0x80000000) {
                cur_inst.instruction = code::Mult{
                    .dest  = make_value(x86.operands[0], rip),
                    .other = imm_t{ std::bit_cast<u32>(-1.0f) },
                };
            }
            break;
        }
        case X86_INS_MULSS:
            assert::always(x86.op_count == 2);
            cur_inst.instruction = code::Mult{
                .dest  = make_value(x86.operands[0], rip),
                .other = make_value(x86.operands[1], rip),
            };
            break;
        case X86_INS_ADDSS:
            assert::always(x86.op_count == 2);
            cur_inst.instruction = code::Add{
                .dest  = make_value(x86.operands[0], rip),
                .other = make_value(x86.operands[1], rip),
            };
            break;
        case X86_INS_CALL:
            assert::always(x86.op_count == 1);
            cur_inst.instruction = code::Call{
                .target = make_value(x86.operands[0], rip),
            };
        }

        if (options.debug) {
            std::println("Written instruction: {}", rfl::json::write(cur_inst));
        }

        cur += insn->size;
        //++count;
    } while (insn->id != X86_INS_RET);

    return ret;
} // <-- vector<Instruction> disassemble(function)

} // <-- namespace cadjit
