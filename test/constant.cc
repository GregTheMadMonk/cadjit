import test_utils;

namespace {

float const_one(float) { return 1; }
float const_two(float) { return 2; }

const unit_test constant_one{
    "/cadjit/constant/one", [] {
        const auto df = cadjit::Derivative(const_one);
        for (f32 x : X) test(df(x) == 0);
    }
}; // <-- /cadjit/constant/one

const unit_test constant_two{
    "/cadjit/constant/two", [] {
        const auto df = cadjit::Derivative(const_two);
        for (f32 x : X) test(df(x) == 0);
    }
}; // <-- /cadjit/constant/two

} // <-- anonymous namespace
