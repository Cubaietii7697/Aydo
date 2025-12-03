#include <chrono>
#include <filesystem>
#include <format>
#include <iostream>
#include <string>
#include <thread>

#include "Constants.hpp"
#include "LogName.hpp"
#include "Utills.hpp"

int main(int argc, char *argv[]) {
  // Args: <exe> <sandbox_id> <payload_host_path> [runTimeSec]
  if (argc < 3 || argc > 4) {
    std::cerr << "Usage: " << argv[0] << " <sandbox_id> <virus_path> [runTime]" << std::endl;
    return EXIT_FAILURE;
  }
  Utills::printBanner();
  const std::string sandboxId(argv[1]);
  const std::filesystem::path suspiciousHostPath(argv[2]);
  const int runTimeSec = (argc == 4) ? std::atoi(argv[3]) : DEFUALT_TIME_CHECK;

  const auto vmRunPath = std::string(VM_RUN_PATH);
  const auto baseVmx = std::string(ANALYSIS_VM_PATH);
  const auto dirSand = std::string(SANDBOXES_DIRECTORY_PATH);
  const std::filesystem::path hostShared(HOST_FOLDER_PATH);

  // Per-sandbox VMX path (quoted for vmrun)
  const std::string sandboxVmxRaw = std::format(R"({}\{}\{}.vmx)", dirSand, sandboxId, sandboxId);
  const std::string sandboxVmx = Utills::ensureQuoted(sandboxVmxRaw);

  // Host target for the final log
  std::error_code ec;
  std::filesystem::create_directories(hostShared, ec);

  // Resolve host paths we will copy from
  const std::string pmHostAbs = std::filesystem::absolute(std::string(PM_FILE_PATH)).string();
  const std::string dllinjectorHostAbs = std::filesystem::absolute(std::string(DLL_INJECTOR_FILE_PATH)).string();
  const std::string processRunnerHostAbs = std::filesystem::absolute(std::string(PROCCES_RUNNER_FILE_PATH)).string();
  const std::string suspiciousHostAbs = std::filesystem::absolute(suspiciousHostPath).string();

  // Guest paths
  const auto guestWorkDir = std::string(SUSPICIOUS_WORKDIR_GUEST);
  const auto guestPmPath = std::string(PM_FILE_PATH_GUEST);
  const auto guestDllinjectorPath = std::string(DLL_INJECTOR_FILE_PATH_GUEST);
  const auto guestProcessRunnerPath = std::string(PROCCES_RUNNER_FILE_PATH_GUEST);
  const std::string guestSuspectedFilePath =
      (std::filesystem::path(guestWorkDir) /
       std::filesystem::path(suspiciousHostPath).filename())
          .string();

  const std::string guestLogPath =
      (std::filesystem::path(GUEST_SHARED_DIR) / std::filesystem::path(SHARE_FILE_NAME)).string();

  const std::string hostLogPath =
      (hostShared / std::filesystem::path(SHARE_FILE_NAME)).string();
  std::cout << "[1.0/6] Clone linked VM" << std::endl;
  {
    if (!std::filesystem::exists(sandboxVmxRaw)) {
      const std::string cmd = std::format(
          R"({} -T ws clone {} {} linked -cloneName={})",
          vmRunPath,
          baseVmx,
          sandboxVmx,
          sandboxId);

      int rc = Utills::executeAndWaitRC(cmd);
      if (rc != 0) {
        std::cerr << "\tFAIL clone rc=" << rc << std::endl;
        return EXIT_FAILURE;
      }
    }
  }

  std::cout << "[1.1/6] Start VM" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws start {})", vmRunPath, sandboxVmx);
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL start rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[1.2/6] Wait for VMware Tools" << std::endl;
  if (!Utills::waitForTools(vmRunPath, sandboxVmx)) {
    std::cerr << "\tFAIL: VMware Tools not ready" << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "[2.0/6] Create guest work dir: " << guestWorkDir << std::endl;
  {
    const std::string existsCmd = std::format(
        R"({} -T ws -gu {} -gp {} directoryExistsInGuest {} {})",
        vmRunPath,
        std::string(GUEST_USER),
        std::string(GUEST_PASS),
        sandboxVmx,
        Utills::ensureQuoted(guestWorkDir));

    int existsRc = Utills::executeAndWaitRC(existsCmd);

    if (existsRc != 0) {
      const std::string createCmd = std::format(
          R"({} -T ws -gu {} -gp {} createDirectoryInGuest {} {})",
          vmRunPath,
          std::string(GUEST_USER),
          std::string(GUEST_PASS),
          sandboxVmx,
          Utills::ensureQuoted(guestWorkDir));

      int createRc = Utills::executeAndWaitRC(createCmd);
      if (createRc != 0) {
        std::cerr << "\tFAIL createDirectory rc=" << createRc
                  << " (directory does not exist and cannot be created)"
                  << std::endl;
        Utills::closeVM(vmRunPath, sandboxVmx);
        return EXIT_FAILURE;
      }
    }
  }
  /************************** copy files *******************************/
  std::cout << "[2.1/6] Copy monitor -> guest" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx,
                                        Utills::ensureQuoted(pmHostAbs),
                                        Utills::ensureQuoted(guestPmPath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL copy monitor rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }
  std::cout << "[2.2/6] Copy suspicious -> guest" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx,
                                        Utills::ensureQuoted(suspiciousHostAbs),
                                        Utills::ensureQuoted(guestSuspectedFilePath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL copy payload rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }
  std::cout << "[2.3/6] Copy dllinjector -> guest" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx,
                                        Utills::ensureQuoted(dllinjectorHostAbs),
                                        Utills::ensureQuoted(guestDllinjectorPath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL copy payload rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }
  std::cout << "[2.4/6] Copy processRunner -> guest" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx,
                                        Utills::ensureQuoted(processRunnerHostAbs),
                                        Utills::ensureQuoted(guestProcessRunnerPath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL copy payload rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  /************************** start mointor *******************************/
  std::cout << "[3.0/6] Start monitor in guest" << std::endl;
  {
    const std::string cmd = std::format(
        R"({} -T ws -gu {} -gp {} runProgramInGuest {} -noWait  {} {} {}{})",
        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
        sandboxVmx,
        Utills::ensureQuoted(guestPmPath),
        Utills::ensureQuoted(guestSuspectedFilePath),
        Utills::ensureQuoted(guestLogPath),
        (runTimeSec > 0 ? std::format(" {}", runTimeSec) : std::string{}));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL run monitor rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[3.1/6] Start Process Runner in guest" << std::endl;
  {
    const std::string cmd = std::format(
        R"({} -T ws -gu {} -gp {} runProgramInGuest  {} -noWait {} {} {} {})",
        vmRunPath,
        std::string(GUEST_USER),
        std::string(GUEST_PASS),
        sandboxVmx,
        Utills::ensureQuoted(guestProcessRunnerPath),
        Utills::ensureQuoted(guestSuspectedFilePath),
        Utills::ensureQuoted(guestDllinjectorPath),
        Utills::ensureQuoted(guestWorkDir));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL run payload rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[4/6] Let payload run for " << runTimeSec << "s" << std::endl;
  std::this_thread::sleep_for(std::chrono::seconds(runTimeSec));

  std::cout << "[5/6] Copy log guest->host" << std::endl;
  {
    std::cout << "\tExpected guest DB path: " << guestLogPath << std::endl;
    std::cout << "\tExpected host  DB path: " << hostLogPath << std::endl;

    if (std::filesystem::exists(hostLogPath)) {
      std::cout << "\tDB file exists on host." << std::endl;
    } else {
      std::cerr << "\tWARN: DB file NOT found on host path: "
                << hostLogPath << std::endl;
    }
  }

  if (bool rs = Utills::closeVM(vmRunPath, sandboxVmx); !rs) {
    std::wcerr << "Something went wrong with stop." << std::endl;
    Utills::printBanner(true);
    return EXIT_FAILURE;
  }

  std::cout << "Done." << std::endl;
  Utills::printBanner(true);
}
