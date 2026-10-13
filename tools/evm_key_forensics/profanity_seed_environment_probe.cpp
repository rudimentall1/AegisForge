// Diagnostic probe for a disposable research environment.
// This is NOT the historical Profanity implementation and does NOT test or recover
// wallet keys. Observed samples and random_device::entropy() are not proofs of entropy.
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <random>
#include <set>
#include <string>

int main(int argc, char** argv) {
    unsigned long samples = 64;
    if (argc > 2) {
        std::cerr << "usage: profanity_seed_environment_probe [sample_count_1_to_10000]\n";
        return 2;
    }
    if (argc == 2) {
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(argv[1], &end, 10);
        if (end == argv[1] || *end != '\0' || parsed < 1 || parsed > 10000) {
            std::cerr << "sample_count_must_be_between_1_and_10000\n";
            return 2;
        }
        samples = parsed;
    }

    typedef std::random_device::result_type random_device_result_type;
    std::random_device rd;
    std::set<random_device_result_type> observed;
    for (unsigned long i = 0; i < samples; ++i) {
        observed.insert(rd());
    }

    std::cout << "{\n"
              << "  \"schema_version\": 1,\n"
              << "  \"probe\": \"std_random_device_environment_diagnostic\",\n"
              << "  \"historical_profanity_code_executed\": false,\n"
              << "  \"wallet_material_used\": false,\n"
              << "  \"random_device_result_type_bits\": "
              << (std::numeric_limits<random_device_result_type>::digits) << ",\n"
              << "  \"random_device_reported_entropy\": " << rd.entropy() << ",\n"
              << "  \"samples_requested\": " << samples << ",\n"
              << "  \"distinct_values_observed\": " << observed.size() << ",\n"
              << "  \"observations_are_entropy_proof\": false,\n"
              << "  \"compiler_family\": \"";
#if defined(__clang__)
    std::cout << "clang";
#elif defined(__GNUC__)
    std::cout << "gcc";
#elif defined(_MSC_VER)
    std::cout << "msvc";
#else
    std::cout << "unknown";
#endif
    std::cout << "\",\n"
              << "  \"cplusplus_macro\": " << __cplusplus << ",\n"
              << "  \"libstdcxx_version\": ";
#ifdef __GLIBCXX__
    std::cout << __GLIBCXX__;
#else
    std::cout << "null";
#endif
    std::cout << ",\n"
              << "  \"libcxx_version\": ";
#ifdef _LIBCPP_VERSION
    std::cout << _LIBCPP_VERSION;
#else
    std::cout << "null";
#endif
    std::cout << "\n}\n";
    return 0;
}
