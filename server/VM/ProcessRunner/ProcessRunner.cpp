#include <windows.h>

#include <chrono>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <winnt.h>

#include "Utils.hpp"

constexpr std::string_view DEFAULT_WORKING_DIRECTORY = ".";
constexpr unsigned int CHECK_INTERVAL_MS = 250;

int main(int argc, char *argv[]) {
  // Get the program to execute:
  // argv[0] is the current executable path
  // argv[1] is the program to execute
  // argv[2] is the DLL to inject
  // argv[3] is the working directory (optional)
  // argv[4...N] is the arguments to pass to the program (optional)
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <program> <dll_to_inject> <working_directory?> <arguments?>" << std::endl;

    return EXIT_FAILURE;
  }

  std::string program(argv[1]);
  std::string dllToInject(argv[2]);
  std::string workingDirectory{DEFAULT_WORKING_DIRECTORY};
  std::vector<std::string> arguments;
  if (argc > 4) {
    arguments.reserve(static_cast<std::size_t>(argc - 4));
  }

  if (argc > 3) {
    workingDirectory = argv[3];
  }

  if (argc > 4) {
    arguments.assign(argv + 4, argv + argc);
  }

  std::string argumentsString = Utils::vectorStringToString(arguments, " ");

  std::cout << "Executing `" << program << "` in `" << workingDirectory << "` with arguments `" << argumentsString << "`" << std::endl;

  // Wait until the program file exists
  std::cout << "Waiting for program to exist..." << std::endl;
  while (!Utils::doesFileExist(program)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_INTERVAL_MS));
  }

  // Run the program in suspended mode (so we can attach to it)
  std::cout << "Program exists, running in suspended mode..." << std::endl;

  STARTUPINFOA startupInfo;
  PROCESS_INFORMATION processInfo;

  ZeroMemory(&startupInfo, sizeof(startupInfo));
  startupInfo.cb = sizeof(startupInfo);
  ZeroMemory(&processInfo, sizeof(processInfo));

  std::string cmdLine = program + " " + argumentsString;

  if (!Utils::createSuspendedProcess(cmdLine, workingDirectory, startupInfo, processInfo)) {
    std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;

    return EXIT_FAILURE;
  }

  std::cout << "Process created in suspended mode. Injecting DLL..." << std::endl;

  // Inject the DLL
  if (!Utils::injectDll(processInfo.hProcess, dllToInject)) {
    std::cerr << "Failed to inject DLL" << std::endl;
    TerminateProcess(processInfo.hProcess, EXIT_FAILURE);

    return EXIT_FAILURE;
  }

  std::cout << "DLL injected successfully. Resuming process..." << std::endl;

  ResumeThread(processInfo.hThread);
  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);

  return EXIT_SUCCESS;
}