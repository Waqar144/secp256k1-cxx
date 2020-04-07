#include "secp256k1-cxx.hpp"
#include "sha/sha2.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <vector>

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
