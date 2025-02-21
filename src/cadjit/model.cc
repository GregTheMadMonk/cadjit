module;

#include <rfl/json.hpp>

module cadjit;

import dxx.assert;
import dxx.cstd.fixed;
import dxx.overload;
import std;

using namespace dxx::overload;
namespace assert = dxx::assert;

namespace cadjit {

model_t build_model(const std::vector<code::instruction_t>& algo) {
    model_t tokens{ { .token = reg_t::xmm0, .recent = false } };

    static constexpr imm_t zero{ std::bit_cast<u32>(0.0f) };
    
    static constexpr auto bottom_node = [] (const auto& node) {
        return node.left == nullptr && node.right == nullptr;
    }; // <-- bottom_node(node)

    for (const auto& inst : std::views::reverse(algo)) {
        const auto active = std::visit(
            overload{
                [] (const code::misc_t&) { return false; },
                [&tokens] (const code::move_t& mov) {
                    bool ret = false;
                    for (auto it = tokens.begin(); it != tokens.end(); ++it) {
                        auto& node = *it;
                        if (node.data.recent)   continue;
                        if (!bottom_node(node)) continue;

                        // Bottom leafs always contain values
                        assert::always(std::holds_alternative<value_t>(node.data.token));

                        const auto v = std::get<value_t>(node.data.token);
                        if (v != mov.to) continue;

                        tokens.push_node(it.ptr, { .token = mov.from,   .recent = true }, true);
                        tokens.push_node(it.ptr, { .token = zero, .recent = true }, false);
                        node.data.token = operator_t::add;

                        ret = true;
                    }
                    return ret;
                },
                [&tokens] (const code::mult_t& mul) {
                    bool ret = false;
                    for (auto it = tokens.begin(); it != tokens.end(); ++it) {
                        auto& node = *it;
                        if (node.data.recent)   continue;
                        if (!bottom_node(node)) continue;

                        assert::always(std::holds_alternative<value_t>(node.data.token));

                        const auto v = std::get<value_t>(node.data.token);
                        if (v != mul.dest) continue;

                        tokens.push_node(it.ptr, { .token = mul.dest,  .recent = true }, true);
                        tokens.push_node(it.ptr, { .token = mul.other, .recent = true }, false);
                        node.data.token = operator_t::multiply;

                        ret = true;
                    }
                    return ret;
                },
                [&tokens] (const code::add_t& add) {
                    bool ret = false;
                    for (auto it = tokens.begin(); it != tokens.end(); ++it) {
                        auto& node = *it;
                        if (node.data.recent)   continue;
                        if (!bottom_node(node)) continue;

                        assert::always(std::holds_alternative<value_t>(node.data.token));

                        const auto v = std::get<value_t>(node.data.token);
                        if (v != add.dest) continue;

                        tokens.push_node(it.ptr, { .token = add.dest,  .recent = true }, true);
                        tokens.push_node(it.ptr, { .token = add.other, .recent = true }, false);
                        node.data.token = operator_t::add;

                        ret = true;
                    }
                    return ret;
                },
            }, inst.instruction
        );

        if (active) {
            for (auto& node : tokens) node.data.recent = false;
        }
    }

    for (const auto& node : tokens) {
        std::println("{}", rfl::json::write(node.data.token));
    }

    return tokens;
} // <-- model_t build_model(algo)

float aad_model(const model_t& model, float x) {
    using node_ptr = decltype(model.get_root().get());
    std::map<node_ptr, std::pair<float, float>> derivatives;

    const auto bottom_uncalculated = [&derivatives] (const auto& node) {
        return (node.left == nullptr || derivatives.contains(node.left.get()))
            && (node.right == nullptr || derivatives.contains(node.right.get()));
    }; // <-- bottom_uncalculated(node)

    while (!derivatives.contains(model.get_root().get())) {
        for (auto it = model.begin(); it != model.end(); ++it) {
            const auto& node = *it;
            if (!bottom_uncalculated(node)) continue;

            assert::always(
                std::holds_alternative<value_t>(node.data.token)
                || (node.left != nullptr && node.right != nullptr)
            );

            const auto d = std::visit(
                overload{
                    [&node, &derivatives] (operator_t op) -> float {
                        const auto [ v1, d1 ] = derivatives.at(node.left.get());
                        const auto [ v2, d2 ] = derivatives.at(node.right.get());
                        switch (op) {
                        using enum operator_t;
                        case add:      return d1 + d2;
                        case multiply: return d1 * v2 + v1 * d2;
                        }
                    },
                    [] (value_t val) -> float {
                        if (!std::holds_alternative<reg_t>(val))      return 0.0f;
                        else if (std::get<reg_t>(val) == reg_t::xmm0) return 1.0f;
                        else                                          return 0.0f;
                    },
                }, node.data.token
            );

            const auto v = std::visit(
                overload{
                    [&node, &derivatives] (operator_t op) -> float {
                        const auto [ v1, d1 ] = derivatives.at(node.left.get());
                        const auto [ v2, d2 ] = derivatives.at(node.right.get());

                        switch (op) {
                        using enum operator_t;
                        case add:      return v1 + v2;
                        case multiply: return v1 * v2;
                        }
                    },
                    [&x] (value_t val) -> float {
                        return std::visit(
                            overload{
                                [&x] (const reg_t& reg) {
                                    if (reg == reg_t::xmm0) return x;
                                    else                    return 0.0f;
                                },
                                [] (const imm_t& imm) { return std::bit_cast<float>(imm.value); },
                                [] (const mem_t& mem) {
                                    assert::always(mem.base == reg_t::rip);

                                    const auto ptr = mem.rip + mem.displacement;
                                    return *reinterpret_cast<const float*>(ptr);
                                },
                            }, val
                        );
                    },
                }, node.data.token
            );

            derivatives.emplace(it.ptr.get(), std::pair{ v, d });
        }
    }

    // std::println("{}", derivatives.at(model.get_root().get()));

    return std::get<1>(derivatives.at(model.get_root().get()));
} // <-- float aad_model(model, x)

} // <-- namespace cadjit
