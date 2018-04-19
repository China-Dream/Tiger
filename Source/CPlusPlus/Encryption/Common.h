#ifndef _WENCRYPTION_COMMON_H_
#define _WENCRYPTION_COMMON_H_

#ifdef _WINDLL
#define DLLEXPORT __declspec(dllexport) // Windows
#elif __GNUC__ >= 4
#define DLLEXPORT __attribute__ ((visibility ("default")))  // Android
#else
#define DLLEXPORT
#endif

namespace WTiger
{
    enum AlgorithmType
    {
        MD5,
        DES,
        RSA
    };
}

#endif