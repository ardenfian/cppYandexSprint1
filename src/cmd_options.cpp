#include "cmd_options.h"
#include <boost/exception/exception.hpp>
#include <boost/program_options/errors.hpp>
#include <boost/throw_exception.hpp>
#include <iostream>
#include <string>

using namespace boost;
namespace po = boost::program_options;

namespace CryptoGuard {

// clang-format off
/* clang-format делает такую конструкцию плохо читаемой*/
ProgramOptions::ProgramOptions() : desc_("Доступные опции") {
    desc_.add_options()("help", "список доступных опций")
                       ("command",  po::value<std::string>(),  "команда encrypt, decrypt или checksum")
                       ("input",    po::value<std::string>(&inputFile_),  "путь до входного файла")
                       ("output",   po::value<std::string>(&outputFile_), "путь до выходного файла")
                       ("password", po::value<std::string>(&password_),   "пароль для шифрования или дешифрования");
}
// clang-format on

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;

    try {
        po::parsed_options parsed = po::command_line_parser(argc, argv).options(desc_).allow_unregistered().run();

        po::store(parsed, vm);
        po::notify(vm);

        /*При наличии help выводим справку независимо от других аргументов */
        if (vm.count("help") || !vm.size()) {
            std::cerr << desc_ << "\n";
            return 1;
        }

        /*Проверка на неизвестные аргументы командной строки*/
        std::vector<std::string> unknownArgs = po::collect_unrecognized(parsed.options, po::include_positional);
        if (!unknownArgs.empty()) {
            std::string wrongOpts;
            for (auto str : unknownArgs) {
                wrongOpts += str + " ";
            }
            return fail(std::format("Недопустимые аргументы командной строки: {}", wrongOpts));
        }

        /*Опция command обязательна (если не указана опция help) */
        if (!vm.count("command")) {
            return fail("Отсутствует опция command");
        }
        std::string strCmd = vm["command"].as<std::string>();
        command_ = strToCmd(strCmd);

        /*Опция input также обязательна для всех команд */
        if (!vm.count("input")) {
            return fail("Отсутствует опция input");
        }
        inputFile_ = vm["input"].as<std::string>();

        if (COMMAND_TYPE::UNKNOWN == command_) {
            return fail(std::format("Неизвестная команда {}", strCmd));

        } else if (COMMAND_TYPE::CHECKSUM == command_) {
            /*Если команда checksum, то разрешена только опция --input*/
            for (auto opt : vm) {
                if ("input" != opt.first && "command" != opt.first) {
                    return fail("Команда checksum принимает только опцию input");
                }
            }

        } else {
            if (!vm.count("output")) {
                return fail("Отсутствует опция output");
            }

            if (!vm.count("password")) {
                return fail("Отсутствует опция password");
            }

            outputFile_ = vm["output"].as<std::string>();
            password_ = vm["password"].as<std::string>();
        }

    } catch (const po::unknown_option &e) {
        return fail(std::format("Неизвестная опция {}", e.get_option_name()));
    } catch (const po::multiple_occurrences &e) {
        return fail(std::format("Опция {} не может быть указана более одного раза", e.get_option_name()));
    } catch (const std::exception &e) {
        return fail(std::format("Ошибка распознавания аргументов: {}", e.what()));
    }

    return 1;
}

ProgramOptions::COMMAND_TYPE ProgramOptions::strToCmd(const std::string str) {
    COMMAND_TYPE cmd = ProgramOptions::COMMAND_TYPE::UNKNOWN;

    try {
        cmd = commandMapping_.at(str);
    } catch (const std::exception &e) {
        cmd = COMMAND_TYPE::UNKNOWN;
    }

    return cmd;
}

bool ProgramOptions::fail(const std::string msg) {
    std::cerr << msg << "\n";
    std::cerr << desc_;
    return false;
}
}  // namespace CryptoGuard
