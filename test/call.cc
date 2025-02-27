import test_utils;

namespace {

const unit_test exp{
    "/cadjit/call/known/exp", [] {
        const auto f = [] (f32 x) static { return std::expf(x); };
        const auto df = cj::Derivative(+f);
        for (auto x : X) test(is_close(df(x), f(x)));
    }
}; // <-- /cadjit/call/known/exp

const unit_test exp_scaled{
    "/cadjit/call/known/exp_scaled", [] {
        const auto f = [] (f32 x) static { return 2 * std::expf(3 * x); };
        const auto df = cj::Derivative(+f);
        for (auto x : X) test(is_close(df(x), 3 * f(x)));
    }
}; // <-- /cadjit/call/known/exp_scaled

const unit_test exp_composed{
    "/cadjit/call/known/exp_composed", [] {
        const auto f = [] (f32 x) static {
            return 2 * std::expf(3 * x) + 5 * std::exp(7 * x);
        }; // <-- f(x)
        const auto df = cj::Derivative(+f);
        for (auto x : X) test(is_close(df(x), 6 * std::exp(3 * x) + 35 * std::exp(7 * x)));
    }
}; // <-- /cadjit/call/known/exp_composed

const unit_test sin{
    "/cadjit/call/known/sin", [] {
        const auto df = cj::Derivative(+[] (f32 x) static { return std::sin(x); });
        for (auto x : X) test(is_close(df(x), std::cos(x)));
    }
}; // <-- /cadjit/call/known/sin

const unit_test cos{
    "/cadjit/call/known/cos", [] {
        const auto df = cj::Derivative(+[] (f32 x) static { return std::cos(x); });
        for (auto x : X) test(is_close(df(x), -std::sin(x)));
    }
}; // <-- /cadjit/call/known/cos

const unit_test trig{
    "/cadjit/call/known/trig", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static {
                return std::cos(x) * std::cos(x) - std::sin(x);
            }
        );

        for (auto x : X) {
            test(is_close(df(x), -2 * std::cos(x) * std::sin(x) - std::cos(x)));
        }
    }
}; // <-- /cadjit/call/known/trig

const unit_test trig_one{
    "/cadjit/call/known/trig_one", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static {
                return std::cos(x) * std::cos(x) + std::sin(x) * std::sin(x);
            }
        ); // <-- if math maths, this would always return one

        for (auto x : X) test(is_close(df(x), 0.0f));
    }
}; // <-- /cadjit/call/known/trig_one

const unit_test comosition{
    "/cadjit/call/known/composition", [] {
        const auto f = [] (f32 x) static {
            return std::exp(std::sin(5 * x + std::cos(-3 * x)));
        };
        const auto df = cj::Derivative{ +f };

        const auto etalon = [&f] (f32 x) {
            return f(x)
                 * std::cos(5 * x + std::cos(-3 * x))
                 * (5 + 3 * std::sin(-3 * x));
        };

        for (auto x : X) test(is_close(df(x), etalon(x)));
    }
}; // <-- /cadjit/call/known/composition

} // <-- anonymous namespace
