#include "taproot_vanity.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <cctype>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace taproot_vanity {
namespace {

constexpr char kBech32Alphabet[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr std::array<std::uint8_t, 32> kCurveOrder = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using GroupPtr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

[[nodiscard]] BnPtr make_bn() { return BnPtr(BN_new(), BN_free); }
[[nodiscard]] CtxPtr make_ctx() { return CtxPtr(BN_CTX_new(), BN_CTX_free); }
[[nodiscard]] GroupPtr make_group() {
    GroupPtr group(EC_GROUP_new_by_curve_name(NID_secp256k1), EC_GROUP_free);
    if (!group) throw std::runtime_error("failed to create secp256k1 group");
    EC_GROUP_set_point_conversion_form(group.get(), POINT_CONVERSION_COMPRESSED);
    return group;
}
[[nodiscard]] PointPtr make_point(const EC_GROUP* group) {
    PointPtr point(EC_POINT_new(group), EC_POINT_free);
    if (!point) throw std::runtime_error("failed to allocate EC point");
    return point;
}

std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> bytes) {
    std::array<std::uint8_t, 32> out{};
    SHA256(bytes.data(), bytes.size(), out.data());
    return out;
}

std::array<std::uint8_t, 32> tagged_hash_taptweak(std::span<const std::uint8_t> xonly) {
    const auto tag = sha256(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>("TapTweak"), 8));
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, tag.data(), tag.size());
    SHA256_Update(&ctx, tag.data(), tag.size());
    SHA256_Update(&ctx, xonly.data(), xonly.size());
    std::array<std::uint8_t, 32> out{};
    SHA256_Final(out.data(), &ctx);
    return out;
}

bool less_than_order(const std::array<std::uint8_t, 32>& v) {
    return std::lexicographical_compare(v.begin(), v.end(), kCurveOrder.begin(), kCurveOrder.end());
}

bool is_zero(const std::array<std::uint8_t, 32>& v) {
    return std::all_of(v.begin(), v.end(), [](std::uint8_t b) { return b == 0; });
}

std::array<std::uint8_t, 32> bn_to_32(const BIGNUM* bn) {
    std::array<std::uint8_t, 32> out{};
    if (BN_bn2binpad(bn, out.data(), out.size()) != static_cast<int>(out.size())) {
        throw std::runtime_error("failed to encode scalar");
    }
    return out;
}

BnPtr bn_from_32(const std::array<std::uint8_t, 32>& bytes) {
    BnPtr bn(BN_bin2bn(bytes.data(), bytes.size(), nullptr), BN_free);
    if (!bn) throw std::runtime_error("failed to parse scalar");
    return bn;
}

std::array<std::uint8_t, 32> point_xonly(const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx) {
    BnPtr x = make_bn();
    BnPtr y = make_bn();
    if (EC_POINT_get_affine_coordinates(group, point, x.get(), y.get(), ctx) != 1) {
        throw std::runtime_error("failed to read affine coordinates");
    }
    return bn_to_32(x.get());
}

bool point_y_is_odd(const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx) {
    BnPtr x = make_bn();
    BnPtr y = make_bn();
    if (EC_POINT_get_affine_coordinates(group, point, x.get(), y.get(), ctx) != 1) {
        throw std::runtime_error("failed to read affine coordinates");
    }
    return BN_is_odd(y.get()) == 1;
}

std::uint32_t bech32_polymod(const std::vector<std::uint8_t>& values) {
    std::uint32_t chk = 1;
    constexpr std::uint32_t generator[5] = {0x3b6a57b2U, 0x26508e6dU, 0x1ea119faU, 0x3d4233ddU, 0x2a1462b3U};
    for (const auto value : values) {
        const std::uint8_t top = chk >> 25U;
        chk = ((chk & 0x1ffffffU) << 5U) ^ value;
        for (int i = 0; i < 5; ++i) {
            if (((top >> i) & 1U) != 0U) chk ^= generator[i];
        }
    }
    return chk;
}

std::vector<std::uint8_t> hrp_expand(const std::string& hrp) {
    std::vector<std::uint8_t> out;
    out.reserve(hrp.size() * 2 + 1);
    for (const char c : hrp) out.push_back(static_cast<std::uint8_t>(c >> 5));
    out.push_back(0);
    for (const char c : hrp) out.push_back(static_cast<std::uint8_t>(c & 31));
    return out;
}

std::vector<std::uint8_t> convert_bits(const std::array<std::uint8_t, 32>& input) {
    std::vector<std::uint8_t> output;
    int acc = 0;
    int bits = 0;
    for (const auto value : input) {
        acc = (acc << 8) | value;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output.push_back(static_cast<std::uint8_t>((acc >> bits) & 31));
        }
    }
    if (bits > 0) output.push_back(static_cast<std::uint8_t>((acc << (5 - bits)) & 31));
    return output;
}

std::string encode_bech32m(const std::string& hrp, std::uint8_t witness_version,
                           const std::array<std::uint8_t, 32>& program) {
    std::vector<std::uint8_t> data{witness_version};
    auto payload = convert_bits(program);
    data.insert(data.end(), payload.begin(), payload.end());

    auto values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), 6, 0);
    const std::uint32_t polymod = bech32_polymod(values) ^ 0x2bc830a3U;

    std::string out = hrp + '1';
    for (const auto value : data) out += kBech32Alphabet[value];
    for (int i = 0; i < 6; ++i) {
        out += kBech32Alphabet[(polymod >> (5 * (5 - i))) & 31];
    }
    return out;
}

}  // namespace

std::array<std::uint8_t, 32> parse_hex32(const std::string& input) {
    std::string hexstr = input;
    if (hexstr.rfind("0x", 0) == 0 || hexstr.rfind("0X", 0) == 0) hexstr = hexstr.substr(2);
    if (hexstr.size() != 64) throw std::invalid_argument("expected 32-byte hex string");
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(std::stoul(hexstr.substr(i * 2, 2), nullptr, 16));
    }
    return out;
}

std::string hex(std::span<const std::uint8_t> bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto b : bytes) oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

std::vector<std::uint8_t> seed_from_user_string(const std::string& seed) {
    std::string hexstr = seed;
    if (hexstr.rfind("0x", 0) == 0 || hexstr.rfind("0X", 0) == 0) hexstr = hexstr.substr(2);
    const bool is_even_hex = !hexstr.empty() && (hexstr.size() % 2 == 0) &&
                             std::all_of(hexstr.begin(), hexstr.end(), [](unsigned char c) {
                                 return std::isxdigit(c) != 0;
                             });
    if (!is_even_hex) return {seed.begin(), seed.end()};

    std::vector<std::uint8_t> out(hexstr.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(std::stoul(hexstr.substr(i * 2, 2), nullptr, 16));
    }
    return out;
}


bool valid_taproot_prefix(const std::string& prefix) {
    if (prefix.rfind("bc1p", 0) != 0) return false;
    return std::all_of(prefix.begin() + 4, prefix.end(), [](char c) {
        return std::strchr(kBech32Alphabet, c) != nullptr;
    });
}

std::array<std::uint8_t, 32> seed_to_private_key(std::span<const std::uint8_t> seed,
                                                   std::uint64_t counter) {
    for (std::uint32_t round = 0; round < 1024; ++round) {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        static constexpr std::uint8_t domain[] = "TaprootVanity/seed-v1";
        SHA256_Update(&ctx, domain, sizeof(domain) - 1);
        SHA256_Update(&ctx, seed.data(), seed.size());
        for (int shift = 56; shift >= 0; shift -= 8) {
            const std::uint8_t b = static_cast<std::uint8_t>((counter >> shift) & 0xffU);
            SHA256_Update(&ctx, &b, 1);
        }
        const std::uint8_t r0 = static_cast<std::uint8_t>((round >> 24) & 0xffU);
        const std::uint8_t r1 = static_cast<std::uint8_t>((round >> 16) & 0xffU);
        const std::uint8_t r2 = static_cast<std::uint8_t>((round >> 8) & 0xffU);
        const std::uint8_t r3 = static_cast<std::uint8_t>(round & 0xffU);
        const std::uint8_t rb[] = {r0, r1, r2, r3};
        SHA256_Update(&ctx, rb, sizeof(rb));
        std::array<std::uint8_t, 32> candidate{};
        SHA256_Final(candidate.data(), &ctx);
        if (!is_zero(candidate) && less_than_order(candidate)) return candidate;
    }
    throw std::runtime_error("unable to derive valid private key from seed window");
}

TaprootKeyData derive_taproot_key(const std::array<std::uint8_t, 32>& private_key) {
    if (is_zero(private_key) || !less_than_order(private_key)) throw std::invalid_argument("invalid private key");

    TaprootKeyData data;
    data.private_key = private_key;
    const auto group = make_group();
    const auto ctx = make_ctx();
    BnPtr order = bn_from_32(kCurveOrder);
    BnPtr priv = bn_from_32(private_key);
    const auto public_point = make_point(group.get());
    if (EC_POINT_mul(group.get(), public_point.get(), priv.get(), nullptr, nullptr, ctx.get()) != 1) {
        throw std::runtime_error("failed to multiply generator");
    }

    BnPtr internal_priv = bn_from_32(private_key);
    if (point_y_is_odd(group.get(), public_point.get(), ctx.get())) {
        if (BN_sub(internal_priv.get(), order.get(), priv.get()) != 1) {
            throw std::runtime_error("failed to normalize internal scalar");
        }
        if (EC_POINT_invert(group.get(), public_point.get(), ctx.get()) != 1) {
            throw std::runtime_error("failed to normalize internal point");
        }
    }
    data.internal_xonly_pubkey = point_xonly(group.get(), public_point.get(), ctx.get());
    data.tweak = tagged_hash_taptweak(data.internal_xonly_pubkey);
    if (!less_than_order(data.tweak)) throw std::runtime_error("TapTweak scalar exceeds curve order");

    BnPtr tweak_bn = bn_from_32(data.tweak);
    BnPtr tweaked_priv = make_bn();
    if (BN_mod_add(tweaked_priv.get(), internal_priv.get(), tweak_bn.get(), order.get(), ctx.get()) != 1 ||
        BN_is_zero(tweaked_priv.get())) {
        throw std::runtime_error("invalid tweaked private key");
    }
    data.tweaked_private_key = bn_to_32(tweaked_priv.get());

    const auto tweak_point = make_point(group.get());
    if (EC_POINT_mul(group.get(), tweak_point.get(), tweak_bn.get(), nullptr, nullptr, ctx.get()) != 1) {
        throw std::runtime_error("failed to multiply tweak");
    }
    if (EC_POINT_add(group.get(), public_point.get(), public_point.get(), tweak_point.get(), ctx.get()) != 1 ||
        EC_POINT_is_at_infinity(group.get(), public_point.get()) == 1) {
        throw std::runtime_error("failed to add tweak point");
    }
    data.tweaked_xonly_pubkey = point_xonly(group.get(), public_point.get(), ctx.get());
    data.address = encode_bech32m("bc", 1, data.tweaked_xonly_pubkey);
    return data;
}

std::optional<TaprootKeyData> search_prefix(std::span<const std::uint8_t> seed,
                                             const std::string& prefix,
                                             std::uint64_t start_counter,
                                             std::uint64_t max_attempts) {
    for (std::uint64_t i = 0; i < max_attempts; ++i) {
        const auto key = seed_to_private_key(seed, start_counter + i);
        auto data = derive_taproot_key(key);
        if (data.address.rfind(prefix, 0) == 0) return data;
    }
    return std::nullopt;
}

bool run_self_test(std::string* error) {
    try {
        const auto key = parse_hex32("0000000000000000000000000000000000000000000000000000000000000001");
        const auto data = derive_taproot_key(key);
        const bool ok = hex(data.internal_xonly_pubkey) == "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" &&
                        hex(data.tweak) == "3cf5216d476a5e637bf0da674e50ddf55c403270dd36494dfcca438132fa30e7" &&
                        hex(data.tweaked_private_key) == "3cf5216d476a5e637bf0da674e50ddf55c403270dd36494dfcca438132fa30e8" &&
                        hex(data.tweaked_xonly_pubkey) == "da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21" &&
                        data.address == "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9";
        if (!ok && error != nullptr) {
            *error = "Taproot vector mismatch: x=" + hex(data.internal_xonly_pubkey) +
                     " tweak=" + hex(data.tweak) + " tweaked_priv=" + hex(data.tweaked_private_key) +
                     " tweaked_x=" + hex(data.tweaked_xonly_pubkey) + " address=" + data.address;
        }
        return ok;
    } catch (const std::exception& e) {
        if (error != nullptr) *error = e.what();
        return false;
    }
}

}  // namespace taproot_vanity
