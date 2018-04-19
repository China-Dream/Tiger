#include "EncryptionAlgorithm.h"

#include <sstream>

using namespace WTiger;

EncryptionMD5::EncryptionMD5()
{
    type = AlgorithmType::MD5;
}

std::string EncryptionMD5::Encrypt(const std::string& plaintext)
{
    return this->Encrypt(plaintext.c_str());
}

std::string EncryptionMD5::Encrypt(const char* plaintext)
{
    return this->Process(plaintext);
}

std::string EncryptionMD5::Decrypt(const std::string& ciphertext)
{
    return std::string("");
}

std::string EncryptionMD5::Decrypt(const char* plaintext)
{
    return std::string("");
}

void EncryptionMD5::ROL(unsigned int &s, unsigned short cx)
{
    if (cx > 32)
    {
        cx %= 32;
    }

    s = (s << cx) | (s >> (32 - cx));
}

void EncryptionMD5::ltob(unsigned int &i)
{
    unsigned int tmp = i;
    unsigned char *psour = (unsigned char*)&tmp, *pdes = (unsigned char*)&i;
    pdes += 3;
    for (int i = 3; i >= 0; --i)
    {
        memcpy(pdes - i, psour + i, 1);
    }
}

void EncryptionMD5::AccLoop(unsigned short label, unsigned int *lGroup, void *M)
{
    unsigned int *i1, *i2, *i3, *i4, TAcc, tmpi = 0; //定义:4个指针； T表累加器
    const unsigned int rolarray[4][4] = {
        { 7, 12, 17, 22 },
        { 5, 9, 14, 20 },
        { 4, 11, 16, 23 },
        { 6, 10, 15, 21 }
    };//循环左移-位数表
    const unsigned short mN[4][16] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12 },
        { 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2 },
        { 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9 }
    };//数据坐标表
    const unsigned int *pM = static_cast<unsigned int*>(M);//转换类型为32位的Uint
    TAcc = ((label - 1) * 16) + 1; //根据第几轮循环初始化T表累加器
    clac clacArr[4] = { EncryptionMD5::F, EncryptionMD5::G, EncryptionMD5::H, EncryptionMD5::I }; //定义并初始化计算函数指针数组

    /*一轮循环开始（16组->16次）*/
    for (short i = 0; i < 16; ++i)
    {
        /*进行指针自变换*/
        i1 = lGroup + ((0 + i) % 4);
        i2 = lGroup + ((3 + i) % 4);
        i3 = lGroup + ((2 + i) % 4);
        i4 = lGroup + ((1 + i) % 4);

        /*第一步计算开始: A+F(B,C,D)+M[i]+T[i+1] 注:第一步中直接计算T表*/
        tmpi = (*i1 + clacArr[label - 1](*i2, *i3, *i4) + pM[(mN[label - 1][i])] + (unsigned int)(0x100000000UL * abs(sin((double)(TAcc + i)))));
        ROL(tmpi, rolarray[label - 1][i % 4]);//第二步:循环左移
        *i1 = *i2 + tmpi;//第三步:相加并赋值到种子
    }
}

/*接口函数，并执行数据填充*/
std::string EncryptionMD5::Process(const char* mStr)
{
    unsigned int mLen = strlen(mStr); //计算字符串长度
    if (mLen < 0) return 0;
    unsigned int FillSize = 448 - ((mLen * 8) % 512); //计算需填充的bit数
    unsigned int FSbyte = FillSize / 8; //以字节表示的填充数
    unsigned int BuffLen = mLen + 8 + FSbyte; //缓冲区长度或者说填充后的长度
    unsigned char *md5Buff = new unsigned char[BuffLen]; //分配缓冲区
    memcpy(md5Buff, mStr, mLen); //复制字符串到缓冲区

    /*数据填充开始*/
    md5Buff[mLen] = 0x80; //第一个bit填充1
    memset(&md5Buff[mLen + 1], 0, FSbyte - 1); //其它bit填充0，另一可用函数为FillMemory
    unsigned long long lenBit = mLen * 8ULL; //计算字符串长度，准备填充
    memcpy(&md5Buff[mLen + FSbyte], &lenBit, 8); //填充长度
    /*数据填充结束*/

    /*运算开始*/
    unsigned int LoopNumber = BuffLen / 64; //以16个字为一分组，计算分组数量
    unsigned int A = 0x67452301, B = 0x0EFCDAB89, C = 0x98BADCFE, D = 0x10325476;//初始4个种子，小端类型
    unsigned int lGroup[4] = { A, D, C, B}; //种子副本数组,并作为返回值返回
    for (unsigned int Bcount = 0; Bcount < LoopNumber; ++Bcount) //分组大循环开始
    {
        /*进入4次计算的小循环*/
        for (unsigned short Lcount = 0; Lcount < 4;)
        {
            AccLoop(++Lcount, lGroup, &md5Buff[Bcount * 64]);
        }
        /*数据相加作为下一轮的种子或者最终输出*/
        A = (lGroup[0] += A);
        B = (lGroup[3] += B);
        C = (lGroup[2] += C);
        D = (lGroup[1] += D);
    }
    /*转换内存中的布局后才能正常显示*/
    ltob(lGroup[0]);
    ltob(lGroup[1]);
    ltob(lGroup[2]);
    ltob(lGroup[3]);
    delete[] md5Buff; //清除内存并返回

    std::stringstream ss;
    for (int i = 0; i < 4; i++)
    {
        auto val = lGroup[i];
        for (int j = 0; j < sizeof(unsigned int)* 8 / 4; j++)
        {
            int m = val % 16;
            unsigned char c = m >= 9 ? 'A' + (m - 10) : '0' + m;
            ss << c;

            val = val >> 4;
        }
    }

    return ss.str();
}