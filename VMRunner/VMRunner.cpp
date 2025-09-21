#include <cstdlib>
#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>

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

            Sleep(ANIMATION_SLEEP_TIME_MS);
        }
        system("cls");
    } else {
        for (size_t i = 0; i < lines.size(); i++) {
            system("cls");

            for (size_t j = 0; j <= i; j++) {
                std::cout << lines[j] << std::endl;
            }

            Sleep(ANIMATION_SLEEP_TIME_MS);
        }
    }
}

static void executeAndWait(const std::string &command) {
    STARTUPINFOA si = {sizeof(STARTUPINFOA)};
    PROCESS_INFORMATION pi;

    std::string cmdCopy = command;

    if (CreateProcessA(
            nullptr,     // Application name
            &cmdCopy[0], // Command line
            nullptr,     // Process handle not inheritable
            nullptr,     // Thread handle not inheritable
            FALSE,       // Set handle inheritance to FALSE
            0,           // No creation flags
            nullptr,     // Use parent's environment block
            nullptr,     // Use parent's starting directory
            &si,         // Pointer to STARTUPINFO structure
            &pi)) {      // Pointer to PROCESS_INFORMATION structure
        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cerr << "Failed to execute command: " << command << std::endl;
        std::cerr << "Error: " << GetLastError() << std::endl;
    }
}

int main(int argc, char *argv[]) {
    // We expect args to be: <executable path> <sandbox_id>.
    // argv[0] is the executable path.
    // argv[1] is the sandbox id.
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
