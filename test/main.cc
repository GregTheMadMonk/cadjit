import cadjit;
import dxx.assert;
import dxx.cstd.compat;
import dxx.cstd.fixed;
import dxx.cstd;
import provider;
import std;

constexpr std::array functions{ &func1, &func2, &func3, &func4 };

int main(int argc, char** argv) {
    std::println("Function provider: {}", provider_name());

    if (argc != 2) {
        std::println(stderr, "Usage: {} [0-{}]", argv[0], functions.size() - 1);
        return EXIT_FAILURE;
    }

    try {
        const auto f_idx = std::stol(argv[1]);
        const auto f = reinterpret_cast<const void*>(functions.at(f_idx));
        const auto result = cadjit::disassemble(f);

        const auto model = cadjit::build_model(result);

        for (float x = -3.0f; x <= 3.0f; x += 0.5f) {
            std::println("f({:5}) = {:8}  |  f'({:5}) = {:8}", x, functions.at(f_idx)(x), x, cadjit::aad_model(model, x));
        }
    } catch (const std::exception& e) {
        std::println(stderr, "ERROR: {}", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
