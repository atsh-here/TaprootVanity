#include "taproot_vanity.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> bytes_from_string(const std::string& s) {
    return {s.begin(), s.end()};
}

void print_key(const taproot_vanity::TaprootKeyData& key) {
    std::cout << "privkey=" << taproot_vanity::hex(key.private_key) << '\n'
              << "internal_xonly_pubkey=" << taproot_vanity::hex(key.internal_xonly_pubkey) << '\n'
              << "taptweak=" << taproot_vanity::hex(key.tweak) << '\n'
              << "tweaked_privkey=" << taproot_vanity::hex(key.tweaked_private_key) << '\n'
              << "tweaked_xonly_pubkey=" << taproot_vanity::hex(key.tweaked_xonly_pubkey) << '\n'
              << "address=" << key.address << '\n';
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--self-test") {
            std::string error;
            if (!taproot_vanity::run_self_test(&error)) {
                std::cerr << error << '\n';
                return 1;
            }
            std::cout << "self-test passed\n";
            return 0;
        }

        if (argc == 3 && std::string(argv[1]) == "--key") {
            print_key(taproot_vanity::derive_taproot_key(taproot_vanity::parse_hex32(argv[2])));
            return 0;
        }

        if (argc == 5 && std::string(argv[1]) == "--search") {
            const std::string prefix = argv[2];
            const auto seed = bytes_from_string(argv[3]);
            const std::uint64_t attempts = std::stoull(argv[4]);
            const auto found = taproot_vanity::search_prefix(seed, prefix, 0, attempts);
            if (!found) {
                std::cerr << "no match in " << attempts << " attempts\n";
                return 2;
            }
            print_key(*found);
            return 0;
        }

        std::cerr << "usage:\n"
                  << "  " << argv[0] << " --self-test\n"
                  << "  " << argv[0] << " --key <32-byte-hex-private-key>\n"
                  << "  " << argv[0] << " --search <bc1p-prefix> <client-seed> <attempts>\n";
        return 64;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}
