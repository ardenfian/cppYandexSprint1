
#include "crypto_guard_ctx.h"
#include <cstdint>
#include <ios>
#include <iostream>
#include <iterator>
#include <memory>
#include <openssl/evp.h>
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

void EVP_CIPHER_CTX_free_warning(EVP_CIPHER_CTX *c) {
    std::cout << "EVP DELETER INVOKED\n";
    EVP_CIPHER_CTX_free(c);
}

class CryptoGuardCtx::Impl {
public:
    Impl() {
        OpenSSL_add_all_algorithms();

        params = CreateChiperParamsFromPassword("12341234");
        params.encrypt = 1;
    }

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    void EncryptFile_(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good() || !outStream.good()) {
            return;
        }

        // std::unique_ptr<EVP_CIPHER_CTX> ctx = std::make_unique() EVP_CIPHER_CTX_new();
        using evpSmartPtr =
            std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free_warning(ctx); })>;
        evpSmartPtr ctx(EVP_CIPHER_CTX_new());

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        uint8_t outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
        uint8_t inbuf[1024];
        int outLen;

        while (inStream.read(reinterpret_cast<char *>(inbuf), 1024)) {
            std::streamsize inLen = inStream.gcount();
            EVP_CipherUpdate(ctx.get(), outbuf, &outLen, const_cast<const uint8_t *>(inbuf), inLen);
            outStream.write(reinterpret_cast<char *>(outbuf), outLen);
        }

        EVP_CipherFinal_ex(ctx.get(), outbuf, &outLen);
        outStream.write(reinterpret_cast<char *>(outbuf), outLen);

#if 0
        // Обрабатываем первые N символов
        // std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
        // Обрабатываем оставшиеся символы
        // std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        inStream.read(char_type * s, streamsize n)
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        std::print("String encoded successfully. Result: '{}'\n\n", output);
#endif
        EVP_cleanup();
    }

    void DecryptFile_(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum_(std::iostream &inStream);

private:
    AesCipherParams params;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

}  // namespace CryptoGuard
