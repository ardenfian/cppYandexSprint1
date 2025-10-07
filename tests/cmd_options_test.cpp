#include "cmd_options.h"

#include <cstdio>
#include <gtest/gtest.h>
#include <string>

typedef CryptoGuard::ProgramOptions::COMMAND_TYPE PO_TYPE;

/* Вспомогательная функция для парсинга аргументов.
   Принимает inputStr - строку с аргументами командной строки.
   Возвращает std<pair>, где
   first  - количество аргументов,
   second - unique_ptr на массив указателей char* на сами аргументы */
std::pair<int, std::unique_ptr<char *[]>> getArgs(std::string &inputStr) {
    if (inputStr.empty())
        return {0, nullptr};

    std::vector<char *> tokens;

    size_t start = inputStr.find_first_not_of(' ', 0);

    while (start != std::string::npos) {
        tokens.push_back(&inputStr.data()[start]);
        size_t end = inputStr.find(' ', start);

        if (end != std::string::npos)
            inputStr[end++] = '\0';

        start = inputStr.find_first_not_of(' ', end);
    }

    std::pair<int, std::unique_ptr<char *[]>> res;
    res.first = tokens.size();
    res.second = std::make_unique<char *[]>(tokens.size());

    for (size_t i = 0; i < tokens.size(); i++)
        res.second[i] = tokens[i];

    return res;
}

/*Валидная команда encrypt*/
TEST(ProgramOption, VALID_ENCRYPT) {
    testing::internal::CaptureStderr();

    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command encrypt --input /path/to/input/file --output "
                       "/path/to/output/file --password !@#$";
    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    testing::internal::GetCapturedStderr();

    EXPECT_TRUE(ok);
    EXPECT_EQ(PO_TYPE::ENCRYPT, opts.GetCommand());
    EXPECT_EQ("/path/to/input/file", opts.GetInputFile());
    EXPECT_EQ("/path/to/output/file", opts.GetOutputFile());
    EXPECT_EQ("!@#$", opts.GetPassword());
}

/*Валидная команда decrypt*/
TEST(ProgramOption, VALID_DECRYPT) {
    testing::internal::CaptureStderr();
    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command decrypt --input /path/to/input/file --output "
                       "/path/to/output/file --password !@#$";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    testing::internal::GetCapturedStderr();

    EXPECT_TRUE(ok);
    EXPECT_EQ(PO_TYPE::DECRYPT, opts.GetCommand());
    EXPECT_EQ("/path/to/input/file", opts.GetInputFile());
    EXPECT_EQ("/path/to/output/file", opts.GetOutputFile());
    EXPECT_EQ("!@#$", opts.GetPassword());
}

/*Проверка на неизвестные аргументы командной строки*/
TEST(ProgramOption, UNKNOWN_ARGS) {
    testing::internal::CaptureStderr();
    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command checksum --input /path/to/input/file EXTRA_ARG";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    testing::internal::GetCapturedStderr();

    EXPECT_FALSE(ok);
}

/*Проверка опции help */
TEST(ProgramOption, HELP) {
    testing::internal::CaptureStderr();

    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --help --command checksum --input /path/to/file";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    testing::internal::GetCapturedStderr();

    EXPECT_TRUE(ok);
}

/*Отсутствие опции command */
TEST(ProgramOption, COMMAND_OPTION_MISSING) {
    testing::internal::CaptureStderr();

    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --input /path/to/input/file --output "
                       "/path/to/output/file --password !@#$";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    testing::internal::GetCapturedStderr();

    EXPECT_FALSE(ok);
}

/*Проверка наличия обязательной опции input*/
TEST(ProgramOption, INPUT_OPTION_MISSING) {
    testing::internal::CaptureStderr();

    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command checksum --output "
                       "/path/to/output/file --password !@#$";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    testing::internal::GetCapturedStderr();

    EXPECT_FALSE(ok);
}

/*Проверка отсутствия опций кроме input при команде checksum*/
TEST(ProgramOption, CHECKSUM_EXTRA_OPT) {
    testing::internal::CaptureStderr();

    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command checksum --input /path/to/input/file --password !@#$";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    testing::internal::GetCapturedStderr();

    EXPECT_FALSE(ok);
}

/*Неизвестная опция*/
TEST(ProgramOption, UNKNOWN_OPTION) {
    testing::internal::CaptureStderr();

    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command encrypt --input /path/to/input/file --output "
                       "/path/to/output/file --password !@#$ --UNKNOWN_OPT";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    testing::internal::GetCapturedStderr();

    EXPECT_FALSE(ok);
}

/*Одна опция указана дважды*/
TEST(ProgramOption, MULTIPLE_OPT) {
    testing::internal::CaptureStderr();

    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command encrypt --input /path/to/input/file --input "
                       "/path/to/input/file_2 --password !@#$";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    testing::internal::GetCapturedStderr();

    EXPECT_FALSE(ok);
}
