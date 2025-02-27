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

model_t build_model(const std::vector<code::Instruction>& algo) {
    model_t tokens{ { .token = reg_t::xmm0, .recent = false } };

    static constexpr imm_t zero{ std::bit_cast<u32>(0.0f) };
    static constexpr imm_t halfpi{ std::bit_cast<u32>(std::numbers::pi_v<float> / 2.0f) };
    
    static constexpr auto bottom_node = [] (const auto& node) {
        return node.left == nullptr && node.right == nullptr;
    }; // <-- bottom_node(node)

    for (const auto& inst : std::views::reverse(algo)) {
        const auto active = std::visit(
            overload{
                [] (const code::Misc&) { return false; },
                [&tokens] (const code::Move& mov) {
                    bool ret = false;
                    for (auto it = tokens.begin(); it != tokens.end(); ++it) {
                        auto& node = *it;
                        if (node.data.recent)   continue;
                        if (!bottom_node(node)) continue;

                        // Bottom leafs always contain values
                        assert::always(std::holds_alternative<value_t>(node.data.token));

                        const auto v = std::get<value_t>(node.data.token);
                        if (v != mov.to) continue;

                        node.data.token  = mov.from;
                        node.data.recent = true;

                        ret = true;
                    }
                    return ret;
                },
                [&tokens] (const code::Mult& mul) {
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
                [&tokens] (const code::Add& add) {
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
                [&tokens] (const code::Call& call) {
                    // Only support simple single-argument functions for now
                    // This means function maps xmm0->xmm0
                    bool ret = false;
                    for (auto it = tokens.begin(); it != tokens.end(); ++it) {
                        auto& node = *it;
                        if (node.data.recent)   continue;
                        if (!bottom_node(node)) continue;

                        assert::always(std::holds_alternative<value_t>(node.data.token));
                        const auto v = std::get<value_t>(node.data.token);
                        if (!std::holds_alternative<reg_t>(v) || std::get<reg_t>(v) != reg_t::xmm0) continue;

                        static const std::set exp_funcs{
                            reinterpret_cast<uptr>(std::expf),
                            reinterpret_cast<uptr>(std::expl),
                            reinterpret_cast<uptr>(static_cast<f32 (*)(f32)>(std::exp)),
                            reinterpret_cast<uptr>(static_cast<f64 (*)(f64)>(std::exp)),
                            reinterpret_cast<uptr>(static_cast<f32 (*)(f32)>(std::__1::__math::exp)),
                            reinterpret_cast<uptr>(static_cast<f64 (*)(f64)>(std::__1::__math::exp)),
                        };

                        static const std::set sin_funcs{
                            reinterpret_cast<uptr>(std::sinf),
                            reinterpret_cast<uptr>(std::sinl),
                            reinterpret_cast<uptr>(static_cast<f32 (*)(f32)>(std::sin)),
                            reinterpret_cast<uptr>(static_cast<f64 (*)(f64)>(std::sin)),
                            reinterpret_cast<uptr>(static_cast<f32 (*)(f32)>(std::__1::__math::sin)),
                            reinterpret_cast<uptr>(static_cast<f64 (*)(f64)>(std::__1::__math::sin)),
                        };

                        static const std::set cos_funcs{
                            reinterpret_cast<uptr>(std::cosf),
                            reinterpret_cast<uptr>(std::cosl),
                            reinterpret_cast<uptr>(static_cast<f32 (*)(f32)>(std::cos)),
                            reinterpret_cast<uptr>(static_cast<f64 (*)(f64)>(std::cos)),
                            reinterpret_cast<uptr>(static_cast<f32 (*)(f32)>(std::__1::__math::cos)),
                            reinterpret_cast<uptr>(static_cast<f64 (*)(f64)>(std::__1::__math::cos)),
                        };

                        const auto target = std::visit(
                            overload{
                                [] (reg_t) -> uptr { assert::always(false); return 0; },
                                [] (imm_t imm) -> uptr { return imm.value; },
                                [] (mem_t mem) -> uptr {
                                    assert::always(mem.base == reg_t::rip);
                                    return *reinterpret_cast<uptr*>(
                                        mem.rip + mem.displacement
                                    );
                                }
                            }, call.target
                        );

                        if (options.debug) {
                            std::println("call target: {}", target);
                            std::println("known functions with \"exp\" effect: {}", exp_funcs);
                        }

                        if (exp_funcs.contains(target)) {
                            tokens.push_node(it.ptr, { .token = reg_t::xmm0, .recent = true }, true );
                            tokens.push_node(it.ptr, { .token = zero,        .recent = true }, false);
                            node.data.token = operator_t::exp;
                        } else if (sin_funcs.contains(target)) {
                            tokens.push_node(it.ptr, { .token = reg_t::xmm0, .recent = true }, true );
                            tokens.push_node(it.ptr, { .token = zero,        .recent = true }, false);
                            node.data.token = operator_t::sin;
                        } else if (cos_funcs.contains(target)) {
                            tokens.push_node(it.ptr, { .token = reg_t::xmm0, .recent = true }, true );
                            tokens.push_node(it.ptr, { .token = zero,        .recent = true }, false);
                            node.data.token = operator_t::cos;
                        } else {
                            std::println(stderr, "Call to an unknown function");
                        }

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

    if (options.debug) {
        for (auto n_it = tokens.begin(); n_it != tokens.end(); ++n_it) {
            std::println(
                "{:{}} {}",
                "",
                n_it.depth * 3,
                rfl::json::write(n_it.ptr->data.token)
            );
        }
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
                        case exp:      return d1 * std::exp(v1);
                        case sin:      return  d1 * std::cos(v1);
                        case cos:      return -d1 * std::sin(v1);
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
                        case exp:      return std::exp(v1);
                        case sin:      return std::sin(v1);
                        case cos:      return std::cos(v1);
                        }
                    },
                    [&x] (value_t val) -> float {
                        return std::visit(
                            overload{
                                [&x] (const reg_t& reg) {
                                    if (reg == reg_t::xmm0) return x;
                                    else                    return 0.0f;
                                },
                                [] (const imm_t& imm) { return std::bit_cast<float>(static_cast<u32>(imm.value)); },
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
