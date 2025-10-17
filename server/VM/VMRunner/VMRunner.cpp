#include <chrono>
#include <filesystem>
#include <format>
#include <string>
#include <thread>

#include "Utills.hpp"

static inline std::string ensureQuoted(std::string s) {
  if (!s.empty() && s.front() == '"' && s.back() == '"')
    return s;
  return std::format(R"("{}")", s);
}

int main(int argc, char *argv[]) {
  // <executable> <sandbox_id> <virus_path> [runTimeSec]
  if (argc < 3 || argc > 4) {
    std::cerr << "Usage: " << argv[0] << " <sandbox_id> <virus_path> [runTime]\n";
    return EXIT_FAILURE;
  }

  const std::string sandboxId(argv[1]);
  const std::string suspiciousHostPath(argv[2]);
  const int runTimeSec = (argc == 4) ? std::atoi(argv[3]) : 60;

  Utills::printBanner();

  const auto vmRunPath = std::string(VM_RUN_PATH);
  const auto baseVmx = std::string(ANALYSIS_VM_PATH);
  const auto dirSandboxes = std::string(SANDBOXES_DIRECTORY_PATH);
  const auto hostShared = std::string(HOST_FOLDER_PATH);

  const std::string sandboxVmxRaw = std::format(R"({}\{}\{}.vmx)", dirSandboxes, sandboxId, sandboxId);
  const std::string sandboxVmx = ensureQuoted(sandboxVmxRaw);

  // 1) Clone linked VM
  const std::string cmdClone = std::format(R"({} clone {} {} linked -cloneName={})",
                                           vmRunPath, baseVmx, sandboxVmx, sandboxId);
  Utills::executeAndWait(cmdClone);

  // 2) Start VM
  const std::string cmdStart = std::format(R"({} start {})", vmRunPath, sandboxVmx);
  Utills::executeAndWait(cmdStart);

  // 3) Wait for VMware Tools
  std::cout << "Waiting for VMware Tools...\n";
  if (!Utills::waitForTools(vmRunPath, sandboxVmx)) {
    std::cerr << "VMware Tools did not start in time. Aborting.\n";
    Utills::printBanner(true);
    return EXIT_FAILURE;
  }

  // 4) Add and enable shared folder (use a *folder name*, not a file name)
  const std::string cmdAddShare = std::format(R"({} addSharedFolder {} {} {})",
                                              vmRunPath, sandboxVmx,
                                              std::string("hostshare"),
                                              ensureQuoted(hostShared));
  Utills::executeAndWait(cmdAddShare);

  const std::string cmdEnableShare = std::format(R"({} enableSharedFolders {})",
                                                 vmRunPath, sandboxVmx);
  Utills::executeAndWait(cmdEnableShare);

  // 5) Copy ProcessMonitor (PM) into guest
  const auto guestPmPath = std::string(PM_FILE_PATH_INSIDE_VM);
  const std::string cmdCopyPM = std::format(
      R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
      vmRunPath,
      std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx,
      ensureQuoted(std::string(PM_FILE_PATH)),
      ensureQuoted(guestPmPath));
  Utills::executeAndWait(cmdCopyPM);

  // 6) Copy suspicious file into guest
  const std::string guestSuspiciousPath = std::format(R"(C:\Users\{}\Desktop\payload.bin)", std::string(GUEST_USER));
  const std::string cmdCopySusp = std::format(
      R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
      vmRunPath,
      std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx,
      ensureQuoted(suspiciousHostPath),
      ensureQuoted(guestSuspiciousPath));
  Utills::executeAndWait(cmdCopySusp);

  // 7) Build shared log path inside the guest via VMware Shared Folders
  const std::string sharedLogGuestPath = R"(\\vmware-host\Shared Folders\hostshare\logs.log)";

  // 8) Run ProcessMonitor inside guest with args: <payloadPath> <logPath> [runTimeSec]
  std::string cmdRunPM = std::format(
      R"({} -T ws -gu {} -gp {} runProgramInGuest {} -activeWindow -interactive {} {} {})",
      vmRunPath,
      std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx,
      ensureQuoted(guestPmPath),
      ensureQuoted(guestSuspiciousPath),
      ensureQuoted(sharedLogGuestPath));
  if (runTimeSec > 0) {
    cmdRunPM = std::format("{} {}", cmdRunPM, runTimeSec);
  }
  Utills::executeAndWait(cmdRunPM);

  // wait 3 second using treads
  std::this_thread::sleep_for(std::chrono::seconds(3));

  // 9) Run Suspicious inside guest
  const std::string cmdRunSuspicious = std::format(
      R"({} -T ws -gu {} -gp {} runProgramInGuest {} -activeWindow -interactive {})",
      vmRunPath,
      std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx,
      ensureQuoted(guestSuspiciousPath));

  Utills::executeAndWait(cmdRunSuspicious);

  // 10) Close banner
  Utills::printBanner(true);
  return EXIT_SUCCESS;
}
