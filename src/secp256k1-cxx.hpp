#ifndef SECP256K1_CPP_H
#define SECP256K1_CPP_H

#include "libsecp256k1/include/secp256k1.h"

#include <stdexcept>
#include <stdint.h>
#include <vector>

class Secp256K1Exception : public std::runtime_error
{
public:
    Secp256K1Exception(const char* error) noexcept
        : std::runtime_error(error)
    {
    }

    // exception interface

    const char* what() const noexcept
    {
        return std::runtime_error::what();
    }
};

class Secp256K1
{
public:
    Secp256K1();
    ~Secp256K1();
    Secp256K1(const std::string& privateKey);
    std::vector<uint8_t> publicKey() const;
    std::vector<uint8_t> privateKey() const;
    std::string publicKeyHex() const;
    std::string privateKeyHex() const;

private:
    secp256k1_context* ctx = NULL;
    std::vector<uint8_t> pubKey;
    std::vector<uint8_t> privKey;
    static constexpr size_t PUBLIC_KEY_SIZE = 65;

    /** PRIVATE METHODS **/
    bool verifyKey();
    bool createPublicKey(bool compressed = false);
    static std::string base16Decode(const std::string& str);
    static int hexValue(char hex_digit);
    static std::string base16Encode(const std::string& input);
};

#endif
