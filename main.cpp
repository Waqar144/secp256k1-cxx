#include "src/secp256k1-cxx.hpp"
#include "src/sha/sha2.hpp"

#include <iostream>
#include <tuple>

using namespace std;

int main()
{
    std::string key = "f7c32876271e88dbb576d575170de7162aed93a398deec0f7fdb330bc3f49956";
    Secp256K1 p { key };
    std::cout << "Private key: " << p.privateKeyHex() << std::endl;
    std::cout << "Public key: " << p.publicKeyHex() << std::endl;

    std::string x = Secp256K1::base16Decode("de7761f8874d23d4e8f3f26f321ade560556c23c8d7c7c8227bfefaa83f2c485b511d12037bd1e1f9730f5cc031784e895d263f557793215c2f401f3cc5cfe2f");
    std::vector<uint8_t> res;

    bool suc;
    std::tie(res, suc) = p.Sign((const unsigned char*)x.c_str());
    if (suc) {
        std::cout << "\nsignature success";

        bool verified = Secp256K1::Verify((const uint8_t*)x.c_str(), res, p.publicKey());
        //        bool verified = p.Verify((const uint8_t*)x.c_str(), res);
        if (verified) {
            std::cout << "\nVerified!!!\n";
        }
    }
    return 0;
}
