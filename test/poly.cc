import test_utils;

namespace {

const unit_test poly_linear_x{
    "/cadjit/poly/linear_x", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static { return x; }
        );
        for (f32 x : X) test(df(x) == 1);
    }
}; // <-- /cadjit/poly/linear_x

const unit_test poly_linear_10_x{
    "/cadjit/poly/linear_10_x", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static { return 10 * x; }
        );
        for (f32 x : X) test(df(x) == 10);
    }
}; // <-- /cadjit/poly/linear_10_x

const unit_test poly_po_2{
    "/cadjit/poly/power_2", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static { return x * x; }
        );
        for (f32 x : X) test(df(x) == 2 * x);
    }
}; // <-- /cadjit/poly/power_2

const unit_test poly_po_3{
    "/cadjit/poly/power_3", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static { return x * x * x; }
        );
        for (f32 x : X) test(is_close(df(x), 3 * x * x));
    }
}; // <-- /cadjit/poly/power_3

const unit_test poly_po_10{
    "/cadjit/poly/power_10", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static {
                return x * x * x * x * x * x * x * x * x * x;
            }
        );
        for (f32 x : X) test(is_close(df(x), 10 * std::powf(x, 9)));
    }
}; // <-- /cadjit/poly/power_10

const unit_test cubic{
    "/cadjit/poly/cubic", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static {
                return 9 * x * x * x + 12 * x * x + 5 * x + 7;
            }
        );
        for (f32 x : X) {
            test(is_close(df(x), 27 * x * x + 24 * x + 5));
        }
    }
}; // <-- /cadjit/poly/cubic

const unit_test negative_cubic{
    "/cadjit/poly/negative_cubic", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static {
                return -9 * x * x * x + 12 * x * x - 5 * x + 7;
            }
        );
        for (f32 x : X) {
            test(is_close(df(x), -27 * x * x + 24 * x - 5));
        }
    }
}; // <-- /cadjit/poly/negative_cubic

const unit_test negative_cubic_2{
    "/cadjit/poly/negative_cubic_2", [] {
        const auto df = cj::Derivative(
            +[] (f32 x) static {
                return 9 * x * x * x - 12 * x * x + 5 * x - 7;
            }
        );
        for (f32 x : X) {
            test(is_close(df(x), 27 * x * x - 24 * x + 5));
        }
    }
}; // <-- /cadjit/poly/negative_cubic_2

} // <-- anonymous namespace
