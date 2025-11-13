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
  const std::string suspiciousHostAbs = std::filesystem::absolute(suspiciousHostPath).string();

  // Guest paths
  const auto guestWorkDir = std::string(SUSPICIOUS_FILE_PATH);
  const auto guestPmPath = std::string(PM_FILE_PATH_GUEST);
  const std::string guestPayloadPath =
      (std::filesystem::path(guestWorkDir) / std::filesystem::path(suspiciousHostPath).filename()).string();

  const std::string guestLogPath = R"(C:\Temp\pm_log.csv)";
  const std::string hostLogPath =
      (hostShared / LogName::makeLogFileName(sandboxId, "pm_log", "log")).string();
  std::cout << "[1/12] Clone linked VM" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws clone {} {} linked -cloneName={})",
                                        vmRunPath, baseVmx, sandboxVmx, sandboxId);
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL clone rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[2/12] Start VM" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws start {})", vmRunPath, sandboxVmx);
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL start rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[3/12] Wait for VMware Tools" << std::endl;
  if (!Utills::waitForTools(vmRunPath, sandboxVmx)) {
    std::cerr << "\tFAIL: VMware Tools not ready" << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "[4/12] Create guest work dir: " << guestWorkDir << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} createDirectoryInGuest {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx, Utills::ensureQuoted(guestWorkDir));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL createDirectory rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[5/12] Copy monitor -> guest" << std::endl;
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

  std::cout << "[6/12] Copy payload -> guest" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx,
                                        Utills::ensureQuoted(suspiciousHostAbs),
                                        Utills::ensureQuoted(guestPayloadPath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL copy payload rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[7/12] Start monitor in guest" << std::endl;
  {
    const std::string cmd = std::format(
        R"({} -T ws -gu {} -gp {} runProgramInGuest {} -noWait  {} {} {}{})",
        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
        sandboxVmx,
        Utills::ensureQuoted(guestPmPath),
        Utills::ensureQuoted(guestPayloadPath),
        Utills::ensureQuoted(guestLogPath),
        (runTimeSec > 0 ? std::format(" {}", runTimeSec) : std::string{}));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL run monitor rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[8/12] Start payload in guest" << std::endl;
  {
    const std::string cmd = std::format(
        R"({} -T ws -gu {} -gp {} runProgramInGuest  {} -noWait {})",
        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
        sandboxVmx, Utills::ensureQuoted(guestPayloadPath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL run payload rc=" << rc << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[9/12] Let payload run for " << runTimeSec << "s" << std::endl;
  std::this_thread::sleep_for(std::chrono::seconds(runTimeSec));

  std::cout << "[10/12] Copy log guest->host" << std::endl;
  {
    const std::string cmd = std::format(
        R"({} -T ws -gu {} -gp {} CopyFileFromGuestToHost {} {} {})",
        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
        sandboxVmx,
        Utills::ensureQuoted(guestLogPath),
        Utills::ensureQuoted(hostLogPath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tWARN: copy log rc=" << rc << std::endl;
    } // non-fatal
    else {
      std::cout << "\tLog copied to: " << hostLogPath << std::endl;
    }
  }
  // did or didnt work to stop vm
  bool rs = false;
  std::cout << "[11/12] Stop VM (soft)" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws stop {} soft)", vmRunPath, sandboxVmx);
    rs = Utills::executeAndWaitRC(cmd);
    std::this_thread::sleep_for(std::chrono::seconds(STEPS_INTERVAL_S));
  }

  std::cout << "[12/12] Stop VM (hard)" << std::endl;
  {
    const std::string cmd = std::format(R"({} -T ws stop {} hard)", vmRunPath, sandboxVmx);
    rs = rs || Utills::executeAndWaitRC(cmd);
  }

  if (!rs) {
    std::wcerr << "Something went wrong with stop." << std::endl;
    Utills::printBanner(true);
    return EXIT_FAILURE;
  }
  std::cout << "Done." << std::endl;
  Utills::printBanner(true);
}
