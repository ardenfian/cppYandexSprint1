#include "cmd_options.h"

#include <cstdio>
#include <gtest/gtest.h>
#include <string>

typedef CryptoGuard::ProgramOptions::COMMAND_TYPE PO_TYPE;

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

TEST(ProgramOptions, VALID_OPTIONS) {
    CryptoGuard::ProgramOptions opts;
    std::string args =
        "programName --command encrypt --input /path/to/input/file --output /path/to/output/file --password !@#$";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    EXPECT_TRUE(ok);
}

TEST(ProgramOptions, ENCRYPT_COMMAND) {
    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command encrypt --input /path/to/input/file --output "
                       "/path/to/output/file --password !@#$";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    EXPECT_TRUE(ok);
    EXPECT_EQ(PO_TYPE::ENCRYPT, opts.GetCommand());
    EXPECT_EQ("/path/to/input/file", opts.GetInputFile());
    EXPECT_EQ("/path/to/output/file", opts.GetOutputFile());
    EXPECT_EQ("!@#$", opts.GetPassword());
}

TEST(ProgramOptions, UNKNOWN_OPTION) {
    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command encrypt --input /path/to/input/file --output "
                       "/path/to/output/file --password !@#$ --verbose";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    EXPECT_FALSE(ok);
}

TEST(ProgramOptions, MISSING_OPTION) {
    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --input /path/to/input/file --output "
                       "/path/to/output/file --password !@#$";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    EXPECT_FALSE(ok);
}

TEST(ProgramOptions, UNKNOWN_CMD) {
    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --command INVALIDCMD --input /path/to/input/file --output "
                       "/path/to/output/file --password !@#$";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    EXPECT_TRUE(ok);
    EXPECT_EQ(PO_TYPE::UNKNOWN, opts.GetCommand());
}

TEST(ProgramOptions, HELP) {
    CryptoGuard::ProgramOptions opts;
    std::string args = "programName --help";

    auto rawOpts = getArgs(args);
    bool ok = opts.Parse(rawOpts.first, rawOpts.second.get());

    EXPECT_TRUE(ok);
}
