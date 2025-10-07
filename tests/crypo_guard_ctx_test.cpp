#include "crypto_guard_ctx.h"
#include <cstdlib>
#include <ctime>
#include <exception>
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

std::string randomString(size_t size) {
    srand(time(NULL));

    std::string str;
    str.resize(size);

    for (char &c : str) {
        c = (rand() % ('z' - '0' + 1)) + '0';
    }

    return str;
}

/*Простое сравнение исходной и расшифорованной строк*/
TEST(CryptoGuardCtx, STRAIGHT_COMPARE) {
    CryptoGuard::CryptoGuardCtx cryptoctx;
    const int STR_SIZE = 3333;

    std::string str = randomString(STR_SIZE);

    std::stringstream src(str);
    std::stringstream encrypted;
    std::stringstream decrypted;

    cryptoctx.EncryptFile(src, encrypted, "test");
    cryptoctx.DecryptFile(encrypted, decrypted, "test");

    EXPECT_EQ(src.str(), decrypted.str());
}

/*Сравнение контрольной суммы исходной и расшифрованной строк*/
TEST(CryptoGuardCtx, CHECKSUM_COMPARE) {
    CryptoGuard::CryptoGuardCtx cryptoctx;

    const int STR_SIZE = 32;

    std::string str = randomString(STR_SIZE);

    std::stringstream src(str);
    std::stringstream encrypted;
    std::stringstream decrypted;

    cryptoctx.EncryptFile(src, encrypted, "test");
    cryptoctx.DecryptFile(encrypted, decrypted, "test");

    src.seekg(0);
    decrypted.seekg(0);

    std::string srcCS = cryptoctx.CalculateChecksum(src);
    std::string decryptedCS = cryptoctx.CalculateChecksum(decrypted);

    EXPECT_EQ(src.str(), decrypted.str());
}

/*Выбрасывание исключения функцией шифрования при ошибке во входном потоке */
TEST(CryptoGuardCtx, INVALID_INPUT_STREAM_ENCRYPT) {
    CryptoGuard::CryptoGuardCtx cryptoctx;

    std::stringstream src;
    src.setstate(std::ios::failbit);

    std::stringstream encrypted;

    ASSERT_THROW(cryptoctx.EncryptFile(src, encrypted, "test"), std::invalid_argument);
}

/*Выбрасывание исключения функцией шифрования при ошибке в выходном потоке */
TEST(CryptoGuardCtx, INVALID_OUTPUT_STREAM_ENCRYPT) {
    CryptoGuard::CryptoGuardCtx cryptoctx;

    std::stringstream src;

    std::stringstream encrypted;
    encrypted.setstate(std::ios::failbit);

    ASSERT_THROW(cryptoctx.EncryptFile(src, encrypted, "test"), std::invalid_argument);
}

/*Выбрасывание исключения функцией дешифрования при ошибке во входном потоке */
TEST(CryptoGuardCtx, INVALID_INPUT_STREAM_DECRYPT) {
    CryptoGuard::CryptoGuardCtx cryptoctx;

    std::stringstream src;
    src.setstate(std::ios::failbit);

    std::stringstream decrypted;

    ASSERT_THROW(cryptoctx.DecryptFile(src, decrypted, "test"), std::invalid_argument);
}

/*Выбрасывание исключения функцией дешифрования при ошибке в выходном потоке */
TEST(CryptoGuardCtx, INVALID_OUTPUT_STREAM_DECRYPT) {
    CryptoGuard::CryptoGuardCtx cryptoctx;

    std::stringstream src;

    std::stringstream decrypted;
    decrypted.setstate(std::ios::failbit);

    ASSERT_THROW(cryptoctx.DecryptFile(src, decrypted, "test"), std::invalid_argument);
}

/*Выбрасывание исключения функцией расчёта контрольной суммы при ошибке в выходном потоке */
TEST(CryptoGuardCtx, INVALID_INPUT_STREAM_CHECKSUM) {
    CryptoGuard::CryptoGuardCtx cryptoctx;

    std::stringstream src;
    src.setstate(std::ios::failbit);

    ASSERT_THROW(cryptoctx.CalculateChecksum(src), std::invalid_argument);
}
