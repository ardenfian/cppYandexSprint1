#include "cmd_options.h"
#include <iostream>
#include <string>

using namespace boost;
namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Доступные опции") {
    desc_.add_options()("help", "список доступных опций")("command", po::value<std::string>(&strCommand)->required(),
                                                          "команда encrypt, decrypt или checksum")(
        "input", po::value<std::string>(&inputFile_)->required(), "путь до входного файла")(
        "output", po::value<std::string>(&outputFile_)->required(), "путь до выходного файла")(
        "password", po::value<std::string>(&password_)->required(), "пароль для шифрования и дешифрования");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    command_ = COMMAND_TYPE::UNKNOWN;
    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc_), vm);

        if (vm.count("help") || !vm.size()) {
            std::cout << desc_ << "\n";
            return 1;
        }

        std::string strCmd = vm["command"].as<std::string>();
        command_ = strToCmd(strCmd);
        password_ = vm["password"].as<std::string>();
        inputFile_ = vm["input"].as<std::string>();
        outputFile_ = vm["output"].as<std::string>();

        po::notify(vm);
    } catch (const po::error &e) {
        std::cout << e.what() << std::endl;
        return 0;
    }

    return 1;
}

ProgramOptions::COMMAND_TYPE ProgramOptions::strToCmd(const std::string str) {
    COMMAND_TYPE cmd = ProgramOptions::COMMAND_TYPE::UNKNOWN;

    try {
        cmd = commandMapping_.at(str);
    } catch (const std::exception &e) {
    }

    return cmd;
}

}  // namespace CryptoGuard
