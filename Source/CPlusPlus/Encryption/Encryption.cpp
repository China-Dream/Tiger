#include "Encryption.h"

namespace WTiger
{
    Encryption::Encryption(AlgorithmType algo_)
        : algo(algo_)
    {
        switch (algo_)
        {
        case WTiger::AlgorithmType::MD5:
            pAlgorithm = new EncryptionMD5();
            break;
        case WTiger::AlgorithmType::DES:
            break;
        case WTiger::AlgorithmType::RSA:
            break;
        default:
            pAlgorithm = nullptr;
            break;
        }
    }

    Encryption::~Encryption()
    {
        if (pAlgorithm != nullptr)
        {
            delete pAlgorithm;
            pAlgorithm = nullptr;
        }
    }

    std::string Encryption::Encrypt(const std::string& plaintext)
    {
        return this->Encrypt(plaintext.c_str());
    }

    std::string Encryption::Encrypt(const char* plaintext)
    {
        if (pAlgorithm != nullptr)
        {
            return pAlgorithm->Encrypt(plaintext);
        }

        return std::string();
    }

    std::string Encryption::Decrypt(const std::string& cipertext)
    {
        return this->Decrypt(cipertext.c_str());
    }

    std::string Encryption::Decrypt(const char* cipertext)
    {
        if (pAlgorithm != nullptr)
        {
            return pAlgorithm->Decrypt(cipertext);
        }

        return std::string();
    }
}