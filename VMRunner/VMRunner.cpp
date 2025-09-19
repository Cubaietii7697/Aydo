#include <cstdlib>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>
#include <format>
#include <string_view>

#include "Constants.hpp"

static void printBanner(bool isClosing = false) {
    std::string bannerStr(BANNER);
    std::vector<std::string> lines;
    std::stringstream ss(bannerStr);
    std::string line;

    while (std::getline(ss, line)) {
        lines.push_back(line);
    }

    if (isClosing) {
        for (size_t i = lines.size() - 1; i < lines.size(); i--) {
            system("cls");

            for (size_t j = 0; j <= i; j++) {
                std::cout << lines[j] << std::endl;
            }

            Sleep(50);
        }
        system("cls");
    } else {
        for (size_t i = 0; i < lines.size(); i++) {
            system("cls");

            for (size_t j = 0; j <= i; j++) {
                std::cout << lines[j] << std::endl;
            }

            Sleep(50);
        }
    }
}

static void executeAndWait(const std::string &command) {
    STARTUPINFOA si = {sizeof(STARTUPINFOA)};
    PROCESS_INFORMATION pi;

    std::string cmdCopy = command;

    if (CreateProcessA(
            nullptr,
            &cmdCopy[0],
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &si,
            &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cerr << "Failed to execute command: " << command << std::endl;
        std::cerr << "Error: " << GetLastError() << std::endl;
    }
}

static std::string generateId(const std::string &prefix, const unsigned int length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9);

    std::string id;
    for (int i = 0; i < length; i++) {
        id += std::to_string(dis(gen));
    }

    return prefix + id;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <sandbox_id>" << std::endl;
        return EXIT_FAILURE;
    }

    std::string sandboxId(argv[1]);

    printBanner();

    std::string analysisVmPath(ANALYSIS_VM_PATH);
    std::string sandboxesDirectoryPath(SANDBOXES_DIRECTORY_PATH);
    std::string vmRunPath(VM_RUN_PATH);

    std::string sandboxPath = std::format("{}\\{}\\{}.vmx",
                                           sandboxesDirectoryPath,
                                           sandboxId,
                                           sandboxId);

    std::string vmRunCommand = std::format("{}{} clone {} {} linked -cloneName={}",
                                           vmRunPath,
                                           " ",
                                           analysisVmPath,
                                           sandboxPath,
                                           sandboxId);
    executeAndWait(vmRunCommand);

    std::string vmRunCommand2 = std::format("{}{} start {}",
                                            vmRunPath,
                                            " ",
                                            sandboxPath);
    executeAndWait(vmRunCommand2);

    printBanner(true);

    return EXIT_SUCCESS;
}