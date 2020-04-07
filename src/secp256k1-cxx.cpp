#include "secp256k1-cxx.hpp"
#include "sha/sha2.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <vector>

/**
 * @brief Secp256K1::Secp256K1
 * creates pub/priv key pair
 */
Secp256K1::Secp256K1()
    : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))
{
    //get epoch time
    unsigned seed1 = std::chrono::system_clock::now().time_since_epoch().count();

    //generate random number for priv key
    std::seed_seq seed { seed1 };
    std::mt19937_64 eng(seed);
    std::string randString;
    for (int i = 0; i < 10; ++i) {
        randString += eng();
    }

    //generate SHA-256 (our priv key)
    std::vector<uint8_t> out;
    out.resize(32);
    sha256_Raw(reinterpret_cast<const uint8_t*>(randString.c_str()), randString.length(), &out[0]);

    assert(out.size() == 32);

    privKey = std::move(out);
    //verify priv key
    if (!verifyKey()) {
        throw Secp256K1Exception("Unable to create and verify key:  ");
    }

    std::cout << privKey.data();

    if (!createPublicKey()) {
        throw Secp256K1Exception("Unable to create publick key");
    }
}

/**
 * @brief verifies private key and generates corresponding public key
 * @param privateKey - in hexadecimal
 */
Secp256K1::Secp256K1(const std::string& privateKey)
{
    auto priv = Secp256K1::base16Decode(privateKey);

    //generate SHA-256 (our priv key)
    std::vector<uint8_t> out;
    out.resize(32);
    sha256_Raw(reinterpret_cast<const uint8_t*>(priv.c_str()), priv.length(), &out[0]);

    assert(out.size() == 32);

    privKey = std::move(out);
    //verify priv key
    if (!verifyKey()) {
        throw Secp256K1Exception("Unable to create and verify key:  ");
    }

    std::cout << privKey.data();

    if (!createPublicKey()) {
        throw Secp256K1Exception("Unable to create publick key");
    }
}

bool Secp256K1::verifyKey()
{
    return secp256k1_ec_seckey_verify(ctx, privKey.data());
}

bool Secp256K1::createPublicKey(bool compressed)
{
    // Calculate public key.
    secp256k1_pubkey pubkey;
    int ret = secp256k1_ec_pubkey_create(ctx, &pubkey, privKey.data());
    if (ret != 1) {
        return false;
    }

    // Serialize public key.
    size_t outSize = PUBLIC_KEY_SIZE;
    pubKey.resize(outSize);
    secp256k1_ec_pubkey_serialize(
        ctx, pubKey.data(), &outSize, &pubkey,
        compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    pubKey.resize(outSize);

    // Succeed.
    return true;
}

std::string Secp256K1::base16Decode(const std::string& input)
{
    const auto len = input.length();
    if (len & 1) {
        return "";
    }

    std::string output;
    output.reserve(len / 2);
    for (auto it = input.begin(); it != input.end();) {
        try {
            int hi = hexValue(*it++);
            int lo = hexValue(*it++);
            output.push_back(hi << 4 | lo);
        } catch (const std::invalid_argument& e) {
            throw e;
        }
    }
    return output;
}

int Secp256K1::hexValue(char hex_digit)
{
    switch (hex_digit) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return hex_digit - '0';

    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
        return hex_digit - 'A' + 10;

    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
        return hex_digit - 'a' + 10;
    }
    throw std::invalid_argument("bad hex_digit");
}
