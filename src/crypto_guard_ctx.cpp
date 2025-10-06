
#include "crypto_guard_ctx.h"
#include <cstdint>
#include <ios>
#include <iostream>
#include <iterator>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    AesCipherParams CreateCipherParamsFromPassword(std::string_view password);

    void processFile(std::iostream &inStream, std::iostream &outStream, std::string_view password, int mode);

    std::string CalculateChecksum_(std::iostream &inStream) const;

private:
    AesCipherParams params;
    static constexpr int BLOCK_SIZE = 64 * 1024;
};

AesCipherParams CryptoGuardCtx::CryptoGuardCtx::Impl::CreateCipherParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Ошибка создания ключа\n"};
    }

    return params;
}

void CryptoGuardCtx::CryptoGuardCtx::Impl::processFile(std::iostream &inStream, std::iostream &outStream,
                                                       std::string_view password, int mode) {
    if (inStream.fail() || inStream.bad()) {
        throw std::invalid_argument(std::format("Ошибка во входном потоке\n"));
    }

    if (outStream.fail() || outStream.bad()) {
        throw std::invalid_argument(std::format("Ошибка в выходном потоке\n"));
    }

    if ((0 != mode) && (1 != mode)) {
        throw std::invalid_argument(std::format("mode должно быть равно 1 или 0 (mode={})\n", mode));
    }

    int ok = 0;

    params = CreateCipherParamsFromPassword(password);
    params.encrypt = mode;

    using evpSmartPtr =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

    evpSmartPtr ctx(EVP_CIPHER_CTX_new());

    // Инициализируем cipher
    ok = EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
    if (!ok) {
        std::string_view err(ERR_error_string(ERR_peek_last_error(), NULL));
        throw std::runtime_error(std::format("Ошибка инициализации openSSL: {}\n", err));
    }

    uint8_t outbuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint8_t inbuf[BLOCK_SIZE];
    int outLen;

    inStream.read(reinterpret_cast<char *>(inbuf), BLOCK_SIZE);
    std::streamsize inLen = inStream.gcount();
    while (inLen > 0) {
        ok = EVP_CipherUpdate(ctx.get(), outbuf, &outLen, const_cast<const uint8_t *>(inbuf), inLen);
        if (!ok) {
            std::string_view err(ERR_error_string(ERR_peek_last_error(), NULL));
            throw std::runtime_error(std::format("Ошибка openSSL при расчёте контрольной суммы: {}\n", err));
        }

        outStream.write(reinterpret_cast<char *>(outbuf), outLen);
        if (outStream.bad() || outStream.fail()) {
            throw std::runtime_error(std::format("Не удалось сделать запись в выходной поток\n"));
        }

        inStream.read(reinterpret_cast<char *>(inbuf), BLOCK_SIZE);
        inLen = inStream.gcount();
    }
    inStream.clear();

    ok = EVP_CipherFinal_ex(ctx.get(), outbuf, &outLen);
    if (!ok) {
        std::string_view err(ERR_error_string(ERR_peek_last_error(), NULL));
        throw std::runtime_error(std::format("Ошибка openSSL при финализации: ", err));
    }

    outStream.write(reinterpret_cast<char *>(outbuf), outLen);
    if (outStream.bad() || outStream.fail()) {
        throw std::runtime_error(std::format("Не удалось сделать запись в выходной поток\n"));
    }
}

std::string CryptoGuardCtx::CryptoGuardCtx::Impl::CalculateChecksum_(std::iostream &inStream) const {
    if (inStream.fail() || inStream.bad()) {
        throw std::invalid_argument(std::format("Ошибка во входном потоке\n"));
    }

    using evpMdctx = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

    evpMdctx ctx(EVP_MD_CTX_new());
    const EVP_MD *md;
    uint8_t inbuf[1024];
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
        std::string_view err(ERR_error_string(ERR_peek_last_error(), NULL));
        throw std::runtime_error(std::format("Ошибка openSSL при инициализации алгоритма SHA256: {}\n", err));
    }

    if (!EVP_DigestInit_ex2(ctx.get(), md, NULL)) {
        std::string_view err(ERR_error_string(ERR_peek_last_error(), NULL));
        throw std::runtime_error(std::format("Ошибка openSSL при инициализации дайджеста: {}\n", err));
    }

    inStream.read(reinterpret_cast<char *>(inbuf), 1024);
    std::streamsize inLen = inStream.gcount();
    while (inLen > 0) {
        if (!EVP_DigestUpdate(ctx.get(), inbuf, inLen)) {
            std::string_view err(ERR_error_string(ERR_peek_last_error(), NULL));
            throw std::runtime_error(std::format("Ошибка openSSL при расчёте контрольной суммы: {}\n", err));
        }

        inStream.read(reinterpret_cast<char *>(inbuf), 1024);
        inLen = inStream.gcount();
    }
    inStream.clear();

    if (!EVP_DigestFinal_ex(ctx.get(), md_value, &md_len)) {
        std::string_view err(ERR_error_string(ERR_peek_last_error(), NULL));
        throw std::runtime_error(std::format("Ошибка финализации контрольной суммы: {}\n", err));
    }

    /*Перевод контрольной суммы в строку*/
    std::stringstream outStringStream;
    for (size_t i = 0; i < md_len; i++) {
        outStringStream << std::uppercase << std::hex << static_cast<int>(md_value[i]);
    }
    std::string hex_string = outStringStream.str();

    return outStringStream.str();
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->processFile(inStream, outStream, password, 1);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->processFile(inStream, outStream, password, 0);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const {
    return pImpl_->CalculateChecksum_(inStream);
}

}  // namespace CryptoGuard
