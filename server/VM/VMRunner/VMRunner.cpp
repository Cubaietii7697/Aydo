#include <chrono>
#include <filesystem>
#include <format>
#include <iostream>
#include <string>
#include <thread>
#include <utility>

#include "Constants.hpp"
#include "LogName.hpp"
#include "Utills.hpp"

class ScopedStepTimer {
 public:
  explicit ScopedStepTimer(std::string label)
      : label_(std::move(label)),
        start_(std::chrono::steady_clock::now()) {}

  ~ScopedStepTimer() {
    const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_);
    std::cout << "    [timing] " << label_ << ": "
              << elapsedMs.count() << "ms" << std::endl;
  }

 private:
  std::string label_;
  std::chrono::steady_clock::time_point start_;
};

int main(int argc, char *argv[]) {
  // Args: <exe> <sandbox_id> <payload_host_path> [runTimeSec]
  if (argc < 3 || argc > 4) {
    std::cerr << "Usage: " << argv[0] << " <sandbox_id> <virus_path> [runTime]" << std::endl;
    return EXIT_FAILURE;
  }
  //Utills::printBanner();
  const std::string sandboxId(argv[1]);
  const std::filesystem::path suspiciousHostPath(argv[2]);
  const int runTimeSec = (argc == 4) ? std::atoi(argv[3]) : DEFUALT_TIME_CHECK;

  const auto vmRunPath = std::string(VM_RUN_PATH);
  const auto baseVmx = std::string(ANALYSIS_VM_PATH);
  const auto dirSand = std::string(SANDBOXES_DIRECTORY_PATH);

  std::filesystem::path guestSharedPath(GUEST_SHARED_DIR);
  guestSharedPath = guestSharedPath.lexically_normal();
  const std::string sharedFolderName = guestSharedPath.filename().string();

  // Per-sandbox VMX path (quoted for vmrun)
  const std::string sandboxVmxRaw =
      std::format(R"({}\{}\{}.vmx)", dirSand, sandboxId, sandboxId);
  const std::string sandboxVmx = Utills::ensureQuoted(sandboxVmxRaw);

  const std::filesystem::path vmDir = std::filesystem::path(sandboxVmxRaw).parent_path();
  const std::filesystem::path hostShared = vmDir / "shared";

  if (!std::filesystem::exists(hostShared)) {
    std::error_code ec2;
    std::filesystem::create_directories(hostShared, ec2);
    if (ec2) {
      std::cerr << "\tFAIL create host shared dir '" << hostShared.string()
                << "': " << ec2.message() << std::endl;
      return EXIT_FAILURE;
    }
  }

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
  const auto totalStart = std::chrono::steady_clock::now();
  std::cout << "[1.0/7] Clone linked VM & configure shared folder" << std::endl;
  {
    ScopedStepTimer timer("clone/configure shared folder");
    // Create linked clone if it does not exist yet
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

    // Reconfigure the VM's shared folder.
    // Remove any existing share name.
    // Add a new folder.
    if (!sharedFolderName.empty()) {
      {
        const std::string cmd = std::format(
            R"({} -T ws removeSharedFolder {} {})",
            vmRunPath,
            sandboxVmx,
            sharedFolderName);
        // ignore rc � folder may not exist yet
        (void)Utills::executeAndWaitRC(cmd);
      }

      {
        const std::string cmd = std::format(
            R"({} -T ws addSharedFolder {} {} {})",
            vmRunPath,
            sandboxVmx,
            sharedFolderName,
            Utills::ensureQuoted(hostShared.string()));
        int rc = Utills::executeAndWaitRC(cmd);
        if (rc != 0) {
          std::cerr << "\tFAIL addSharedFolder rc=" << rc << std::endl;
          return EXIT_FAILURE;
        }
      }
    } else {
      std::cerr << "\tFAIL: could not derive shared folder name from GUEST_SHARED_DIR='"
                << GUEST_SHARED_DIR << "'" << std::endl;
      return EXIT_FAILURE;
    }
  }

  std::cout << "[1.1/7] Start VM" << std::endl;
  {
    ScopedStepTimer timer("start VM");
    const std::string cmd = std::format(
        R"({} -T ws start {} {})",
        vmRunPath,
        sandboxVmx,
        VM_START_MODE);
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL start rc=" << rc << std::endl;
      Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
      return EXIT_FAILURE;
    }
  }

  std::cout << "[1.2/7] Wait for VMware Tools (" << VM_TOOLS_MAX_RETRIES
            << " retries x " << VM_TOOLS_SLEEP_MS << "ms)" << std::endl;
  {
    ScopedStepTimer timer("wait for VMware Tools");
    if (!Utills::waitForTools(
            vmRunPath,
            sandboxVmx,
            static_cast<int>(VM_TOOLS_MAX_RETRIES),
            static_cast<int>(VM_TOOLS_SLEEP_MS))) {
      std::cerr << "\tFAIL: VMware Tools not ready" << std::endl;
      return EXIT_FAILURE;
    }
  }

  // Shared folders must be enabled on a powered-on VM for the guest
  std::cout << "[1.3/7] Enable shared folders in guest" << std::endl;
  {
    ScopedStepTimer timer("enable shared folders");
    const std::string enableCmd = std::format(
        R"({} -T ws enableSharedFolders {})",
        vmRunPath,
        sandboxVmx);
    int rc = Utills::executeAndWaitRC(enableCmd);
    if (rc != 0) {
      std::cerr << "\tWARN enableSharedFolders rc=" << rc
                << " (shared folders may already be enabled)" << std::endl;
    }

    // Verify that the shared folder path is actually visible in the guest
    const std::string checkCmd = std::format(
        R"({} -T ws -gu {} -gp {} directoryExistsInGuest {} {})",
        vmRunPath,
        std::string(GUEST_USER),
        std::string(GUEST_PASS),
        sandboxVmx,
        Utills::ensureQuoted(std::string(GUEST_SHARED_DIR)));

    int checkRc = Utills::executeAndWaitRC(checkCmd);
    if (checkRc != 0) {
      std::cerr << "\tFAIL: shared folder '" << GUEST_SHARED_DIR
                << "' is not accessible inside the guest (rc=" << checkRc << ")"
                << std::endl;
      Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
      return EXIT_FAILURE;
    }
  }

  std::cout << "[2.0/7] Create guest work dir: " << guestWorkDir << std::endl;
  {
    ScopedStepTimer timer("create guest work dir");
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
        Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
        return EXIT_FAILURE;
      }
    }
  }
  /************************** copy files *******************************/
  std::cout << "[2.1/7] Copy monitor -> guest" << std::endl;
  {
    ScopedStepTimer timer("copy monitor");
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx,
                                        Utills::ensureQuoted(pmHostAbs),
                                        Utills::ensureQuoted(guestPmPath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL copy monitor rc=" << rc << std::endl;
      Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
      return EXIT_FAILURE;
    }
  }
  std::cout << "[2.2/7] Copy suspicious -> guest" << std::endl;
  {
    ScopedStepTimer timer("copy suspicious payload");
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx,
                                        Utills::ensureQuoted(suspiciousHostAbs),
                                        Utills::ensureQuoted(guestSuspectedFilePath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL copy payload rc=" << rc << std::endl;
      Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
      return EXIT_FAILURE;
    }
  }
  std::cout << "[2.3/7] Copy dllinjector -> guest" << std::endl;
  {
    ScopedStepTimer timer("copy DLL injector");
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx,
                                        Utills::ensureQuoted(dllinjectorHostAbs),
                                        Utills::ensureQuoted(guestDllinjectorPath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL copy payload rc=" << rc << std::endl;
      Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
      return EXIT_FAILURE;
    }
  }
  std::cout << "[2.4/7] Copy processRunner -> guest" << std::endl;
  {
    ScopedStepTimer timer("copy process runner");
    const std::string cmd = std::format(R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
                                        vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
                                        sandboxVmx,
                                        Utills::ensureQuoted(processRunnerHostAbs),
                                        Utills::ensureQuoted(guestProcessRunnerPath));
    int rc = Utills::executeAndWaitRC(cmd);
    if (rc != 0) {
      std::cerr << "\tFAIL copy payload rc=" << rc << std::endl;
      Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
      return EXIT_FAILURE;
    }
  }

  /************************** start mointor *******************************/
  std::cout << "[3.0/7] Start monitor in guest" << std::endl;
  {
    ScopedStepTimer timer("start monitor");
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
      Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
      return EXIT_FAILURE;
    }
  }

  std::cout << "[3.1/7] Start Process Runner in guest" << std::endl;
  {
    ScopedStepTimer timer("start process runner");
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
      Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
      return EXIT_FAILURE;
    }
  }

  std::cout << "[4/7] Let payload run for " << runTimeSec << "s" << std::endl;
  {
    ScopedStepTimer timer("payload runtime window");
    std::this_thread::sleep_for(std::chrono::seconds(runTimeSec));
  }

  std::cout << "[5/7] Copy log guest->host" << std::endl;
  {
    ScopedStepTimer timer("verify shared log availability");
    std::cout << "\tExpected guest DB path: " << guestLogPath << std::endl;
    std::cout << "\tExpected host  DB path: " << hostLogPath << std::endl;

    if (std::filesystem::exists(hostLogPath)) {
      std::cout << "\tDB file exists on host." << std::endl;
    } else {
      std::cerr << "\tWARN: DB file NOT found on host path: "
                << hostLogPath << std::endl;
      Utills::closeVM(vmRunPath, sandboxVmx, sandboxId);
      return EXIT_FAILURE;
    }
  }

  std::cout << "[6/7] Shutdown VM" << std::endl;
  {
    ScopedStepTimer timer("shutdown VM");
    if (!Utills::closeVM(vmRunPath, sandboxVmx, sandboxId)) {
      std::wcerr << "Something went wrong with stop." << std::endl;
      Utills::printBanner(true);
      return EXIT_FAILURE;
    }
  }

  const auto totalElapsedMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - totalStart);
  std::cout << "[7/7] Total VM workflow time: "
            << totalElapsedMs.count() << "ms" << std::endl;
  std::cout << "Done." << std::endl;
  Utills::printBanner(true);
  return EXIT_SUCCESS;
}
