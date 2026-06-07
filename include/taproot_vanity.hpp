#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace taproot_vanity {

struct TaprootKeyData {
    std::array<std::uint8_t, 32> private_key{};
    std::array<std::uint8_t, 32> internal_xonly_pubkey{};
    std::array<std::uint8_t, 32> tweak{};
    std::array<std::uint8_t, 32> tweaked_private_key{};
    std::array<std::uint8_t, 32> tweaked_xonly_pubkey{};
    std::string address;
};

std::array<std::uint8_t, 32> parse_hex32(const std::string& hex);
std::string hex(std::span<const std::uint8_t> bytes);
std::array<std::uint8_t, 32> seed_to_private_key(std::span<const std::uint8_t> seed,
                                                   std::uint64_t counter);
TaprootKeyData derive_taproot_key(const std::array<std::uint8_t, 32>& private_key);
std::optional<TaprootKeyData> search_prefix(std::span<const std::uint8_t> seed,
                                             const std::string& prefix,
                                             std::uint64_t start_counter,
                                             std::uint64_t max_attempts);
bool run_self_test(std::string* error);

}  // namespace taproot_vanity
