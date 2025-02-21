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
    { X86_REG_RBP,     reg_t::rbp },
    { X86_REG_RIP,     reg_t::rip },
    { X86_REG_XMM0,    reg_t::xmm0 },
    { X86_REG_XMM1,    reg_t::xmm1 },
    { X86_REG_XMM2,    reg_t::xmm2 },
    { X86_REG_INVALID, std::nullopt },
}; // <-- reg_map

value_t make_value(cs_op_t op, uptr rip) {
    assert::always(op.type != X86_OP_INVALID);

    switch (op.type) {
    case X86_OP_IMM:
        return imm_t{ .value = 0xdeadbeef };
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


std::vector<code::instruction_t> disassemble(const void* function) {
    csh handle;

    assert::always(cs_open(CS_ARCH_X86, CS_MODE_64, &handle)   == CS_ERR_OK);
    assert::always(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);

    std::vector<code::instruction_t> ret{};

    auto cur = reinterpret_cast<const u8*>(function);
    cs_insn* insn;
    //uz count = 0;
    do {
        cs_disasm(handle, cur, 256, reinterpret_cast<u64>(cur), 1, &insn);

        std::println(
            "{:#08x} | {:#08x} | {} {}",
            reinterpret_cast<uptr>(cur),
            insn->address,
            insn->mnemonic,
            insn->op_str
        );

        /*
        if (count == 3) {
            std::println("COUNT 3, grab rip-relative value");
            const auto ptr = reinterpret_cast<uptr>(cur) + insn->size + 0x24fc63;
            std::println("Grab value at {:#08x}: {}", ptr, *reinterpret_cast<const float*>(ptr));
        }
        */

        ret.emplace_back(
            code::instruction_t{
                .address     = insn->address,
                .instruction = code::misc_t{}
            }
        );
        auto& cur_inst = ret.back();

        const auto& x86 = insn->detail->x86;

        // rip points to the next instruction
        const uptr rip = insn->address + insn->size;

        switch (insn->id) {
        case X86_INS_MOVSS:
            assert::always(x86.op_count == 2);
            cur_inst.instruction = code::move_t{
                .from = make_value(x86.operands[1], rip),
                .to   = make_value(x86.operands[0], rip),
            };
            break;
        case X86_INS_MULSS:
            assert::always(x86.op_count == 2);
            cur_inst.instruction = code::mult_t{
                .dest  = make_value(x86.operands[0], rip),
                .other = make_value(x86.operands[1], rip),
            };
            break;
        case X86_INS_ADDSS:
            assert::always(x86.op_count == 2);
            cur_inst.instruction = code::add_t{
                .dest  = make_value(x86.operands[0], rip),
                .other = make_value(x86.operands[1], rip),
            };
            break;
        }

        std::println("Written instruction: {}", rfl::json::write(cur_inst));

        cur += insn->size;
        //++count;
    } while (insn->id != X86_INS_RET);

    return ret;
} // <-- vector<instruction_t> disassemble(function)

#if 0
void function_disasm(void* func) {
    csh handle;

    namespace assert = dxx::assert;

    assert::always(cs_open(CS_ARCH_X86, CS_MODE_64, &handle)   == CS_ERR_OK);
    assert::always(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);

    std::println("DISASM {:#08x}", reinterpret_cast<uptr>(func));

    std::vector<pseudocode::instruction_t> decoded;

    auto* code = reinterpret_cast<const u8*>(func);
    cs_insn* insn;
    do {
        const auto count = cs_disasm(
            handle,
            code,
            256,
            reinterpret_cast<u64>(code),
            1,
            &insn
        );

        std::println(
            "{:#08x} | {:#08x} | {:#02x} | {} {}",
            reinterpret_cast<uptr>(code),
            insn->address,
            *reinterpret_cast<const u64*>(code),
            insn->mnemonic,
            insn->op_str
        );

        const auto& x86 = insn->detail->x86;

        static constexpr auto make_val = [] (auto op) -> pseudocode::value_t {
            using namespace pseudocode;

            assert::always(op.type != X86_OP_INVALID);

            switch (op.type) {
            case X86_OP_REG:
                switch (op.reg) {
                case X86_REG_XMM0:
                    return reg_t{ .reg = reg_t::xmm0 };
                default:
                    assert::always(false);
                }
            case X86_OP_IMM:
                return imm_t{ .value = 0xdeafbeef };
            case X86_OP_MEM:
                std::println("memory operand");
                std::println("    segment register {}", std::to_underlying(op.mem.segment));
                std::println("    base register    {}", std::to_underlying(op.mem.base));
                std::println("    index register   {}", std::to_underlying(op.mem.index));
                std::println("    scale            {}", op.mem.scale);
                std::println("    displacement     {}", op.mem.disp);
                return mem_t{};
            } // <-- switch (op.type)
        }; // <-- make_val(op)

        switch (insn->id) {
        using namespace pseudocode;
        case X86_INS_MOVSS: {
            std::println("move a single float");
            assert::always(x86.op_count == 2);

            decoded.emplace_back(
                move_s{
                    .from = make_val(x86.operands[1]),
                    .to   = make_val(x86.operands[0]),
                }
            );

            break;
        }
        case X86_INS_RET:
            decoded.emplace_back(ret_s{});
            break;
        default:
            decoded.emplace_back(misc_s{});
        }

        code += insn->size;
    } while (insn->id != X86_INS_RET);

    cs_close(&handle);

    return {};
} // <-- function_disasm(func)
#endif

} // <-- namespace cadjit
