#ifndef _ENCRYPTION_ALGORITHM_H_
#define _ENCRYPTION_ALGORITHM_H_

#include <string>

#include "Common.h"

namespace WTiger
{
    class EncryptionAlgorithm
    {
    public:
        EncryptionAlgorithm() = default;

    public:
        virtual std::string Encrypt(const std::string& plaintext) = 0;
        virtual std::string Encrypt(const char* plaintext) = 0;
        virtual std::string Decrypt(const std::string& ciphertext) = 0;
        virtual std::string Decrypt(const char* plaintext) = 0;

        AlgorithmType GetAlgorithmType()
        {
            return this->type;
        }

    protected:
        AlgorithmType type;
    };

    class EncryptionMD5 : public EncryptionAlgorithm
    {
        typedef unsigned int(*clac)(unsigned int X, unsigned int Y, unsigned int Z);

    public:
        EncryptionMD5();

    public:
        virtual std::string Encrypt(const std::string& plaintext);
        virtual std::string Encrypt(const char* plaintext);
        virtual std::string Decrypt(const std::string& ciphertext);
        virtual std::string Decrypt(const char* plaintext);

    private:
        inline static unsigned int F(unsigned int X, unsigned int Y, unsigned int Z)
        {
            return (X & Y) | ((~X) & Z);
        }
        inline static unsigned int G(unsigned int X, unsigned int Y, unsigned int Z)
        {
            return (X & Z) | (Y & (~Z));
        }
        inline static unsigned int H(unsigned int X, unsigned int Y, unsigned int Z)
        {
            return X ^ Y ^ Z;
        }
        inline static unsigned int I(unsigned int X, unsigned int Y, unsigned int Z)
        {
            return Y ^ (X | (~Z));
        }

        /*32位数循环左移实现函数*/
        void ROL(unsigned int &s, unsigned short cx);

        /*B\L互转，接收UINT类型*/
        void ltob(unsigned int &i);

        /*
        MD5循环计算函数，label=第几轮循环（1<=label<=4），lGroup数组=4个种子副本，M=数据（16组32位数指针）
        种子数组排列方式: --A--D--C--B--，即 lGroup[0]=A; lGroup[1]=D; lGroup[2]=C; lGroup[3]=B;
        */
        void AccLoop(unsigned short label, unsigned int *lGroup, void *M);

        /*接口函数，并执行数据填充*/
        std::string Process(const char* mStr);

    };

    class EncryptionRSA : public EncryptionAlgorithm
    {
    public:
        EncryptionRSA();

    public:
        virtual std::string Encrypt(const std::string& plaintext);
        virtual std::string Encrypt(const char* plaintext);
        virtual std::string Decrypt(const std::string& ciphertext);
        virtual std::string Decrypt(const char* plaintext);
    };
}

#endif