import test_utils;

import provider;

namespace {

const int dummy = [] {
    std::println("For dynamic tests using provider .so: {}", provider_name());
    return 0;
} ();

const unit_test f1{
    "/cadjit/dynamic/func1", [] {
        const auto df = cj::Derivative(func1);
        for (auto x : X) test(is_close(df(x), dfunc1(x)));
    }
}; // <-- /cadjit/dynamic/func1

const unit_test f2{
    "/cadjit/dynamic/func2", [] {
        const auto df = cj::Derivative(func2);
        for (auto x : X) test(is_close(df(x), dfunc2(x)));
    }
}; // <-- /cadjit/dynamic/func2

const unit_test f3{
    "/cadjit/dynamic/func3", [] {
        const auto df = cj::Derivative(func3);
        for (auto x : X) test(is_close(df(x), dfunc3(x)));
    }
}; // <-- /cadjit/dynamic/func3

const unit_test f4{
    "/cadjit/dynamic/func4", [] {
        const auto df = cj::Derivative(func4);
        for (auto x : X) test(is_close(df(x), dfunc4(x)));
    }
}; // <-- /cadjit/dynamic/func4

} // <-- anonymous namespace
