#ifndef _W_ENCRYPTION_H_
#define _W_ENCRYPTION_H_

#include "Common.h"
#include "EncryptionAlgorithm.h"

namespace WTiger
{
    class DLLEXPORT Encryption
    {
    public:
        Encryption(AlgorithmType algo);
        ~Encryption();

    public:
        std::string Encrypt(const std::string& plaintext);
        std::string Encrypt(const char* plaintext);
        std::string Decrypt(const std::string& ciphertext);
        std::string Decrypt(const char* ciphertext);

    private:
        EncryptionAlgorithm* pAlgorithm;
        AlgorithmType algo;
    };
}

#endif