#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

extern "C" int taproot_vanity_cuda_search(const std::uint8_t* seed,
                                           std::uint32_t seed_len,
                                           const char* prefix,
                                           std::uint64_t start_counter,
                                           std::uint64_t attempts);

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " <bc1p-prefix> <client-seed> <attempts>\n";
        return 64;
    }
    const std::string prefix = argv[1];
    const std::string seed_string = argv[2];
    const std::uint64_t attempts = std::stoull(argv[3]);
    const std::vector<std::uint8_t> seed(seed_string.begin(), seed_string.end());
    return taproot_vanity_cuda_search(seed.data(), static_cast<std::uint32_t>(seed.size()),
                                      prefix.c_str(), 0, attempts);
}
