#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <exception>
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

using PO_OPT = CryptoGuard::ProgramOptions::COMMAND_TYPE;

void encryptFile(std::string inFile, std::string outFile, std::string password) {
    std::fstream fin(inFile, std::ios::binary | std::ios::in);
    std::fstream fout(outFile, std::ios::binary | std::ios::out);

    try {
        CryptoGuard::CryptoGuardCtx cipher;
        cipher.EncryptFile(fin, fout, password);
        fin.close();
        fout.close();
    } catch (const std::exception &e) {
        std::cout << e.what();
        return;
    }

    std::print("Шифрование завершено\n");
}

void decryptFile(std::string inFile, std::string outFile, std::string password) {
    std::fstream fin(inFile, std::ios::binary | std::ios::in);
    std::fstream fout(outFile, std::ios::binary | std::ios::out);

    try {
        CryptoGuard::CryptoGuardCtx cipher;
        cipher.DecryptFile(fin, fout, password);
        fin.close();
        fout.close();
    } catch (std::exception &e) {
        std::cout << e.what();
        return;
    }
    std::print("Дешифрование завершено\n");
}

void calcCS(std::string inFile) {
    std::fstream fin(inFile, std::ios::binary | std::ios::in);
    std::string checksum;

    try {
        CryptoGuard::CryptoGuardCtx cipher;
        checksum = cipher.CalculateChecksum(fin);
    } catch (std::exception &e) {
        std::cout << e.what();
        return;
    }
    std::print("Контрольная сумма {}: 0x{}\n", inFile, checksum);
}

int main(int argc, char *argv[]) {
    CryptoGuard::ProgramOptions opts;
    bool ok = opts.Parse(argc, argv);
    if (!ok) {
        return 0;
    }

    switch (opts.GetCommand()) {
    case PO_OPT::CHECKSUM:
        calcCS(opts.GetInputFile());
        break;
    case PO_OPT::ENCRYPT:
        encryptFile(opts.GetInputFile(), opts.GetOutputFile(), opts.GetPassword());
        break;
    case PO_OPT::DECRYPT:
        decryptFile(opts.GetInputFile(), opts.GetOutputFile(), opts.GetPassword());
        break;
    default:
        break;
    }

    return 0;
}
