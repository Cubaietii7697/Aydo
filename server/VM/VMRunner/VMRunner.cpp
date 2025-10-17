#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <thread>

#include "Utills.hpp"

static inline std::string ensureQuoted(std::string s) {
  if (!s.empty() && s.front() == '"' && s.back() == '"')
    return s;
  return std::format(R"("{}")", s);
}

static inline std::string psQuote(std::string s) {
  // PowerShell single-quote escaping
  for (size_t pos = 0; (pos = s.find('\'', pos)) != std::string::npos; pos += 2)
    s.insert(pos, 1, '\'');
  return std::format("'{}'", s);
}

int main(int argc, char *argv[]) {
  // <executable> <sandbox_id> <virus_path> [runTimeSec]
  if (argc < 3 || argc > 4) {
    std::cerr << "Usage: " << argv[0] << " <sandbox_id> <virus_path> [runTime]\n";
    return EXIT_FAILURE;
  }

  const std::string sandboxId(argv[1]);
  const std::filesystem::path suspiciousHostPath(argv[2]);
  const int runTimeSec = (argc == 4) ? std::atoi(argv[3]) : DEFUALT_TIME_CHECK;

  Utills::printBanner();

  const std::string vmRunPath = std::string(VM_RUN_PATH);
  const std::string baseVmx = std::string(ANALYSIS_VM_PATH);
  const std::string dirSandboxes = std::string(SANDBOXES_DIRECTORY_PATH);
  const std::filesystem::path hostShared(HOST_FOLDER_PATH);

  // Resolve the per-sandbox VMX path
  const std::string sandboxVmxRaw = std::format(R"({}\{}\{}.vmx)", dirSandboxes, sandboxId, sandboxId);
  const std::string sandboxVmx = ensureQuoted(sandboxVmxRaw);

  std::cout << "[1/15] Ensuring host shared folder exists: " << hostShared << "\n";
  if (!std::filesystem::exists(hostShared)) {
    std::error_code ec;
    std::filesystem::create_directories(hostShared, ec);
    if (ec) {
      std::cerr << "Failed to create host share: " << hostShared << " (" << ec.message() << ")\n";
      return EXIT_FAILURE;
    }
  }

  std::cout << "[2/15] Cloning linked VM if needed...\n";
  const std::string cmdClone = std::format(R"({} -T ws clone {} {} linked -cloneName={})",
                                           vmRunPath, baseVmx, sandboxVmx, sandboxId);
  Utills::executeAndWait(cmdClone);

  std::cout << "[3/15] Starting VM...\n";
  const std::string cmdStart = std::format(R"({} -T ws start {})", vmRunPath, sandboxVmx);
  Utills::executeAndWait(cmdStart);

  std::cout << "[4/15] Waiting for VMware Tools...\n";
  if (!Utills::waitForTools(vmRunPath, sandboxVmx)) {
    std::cerr << "VMware Tools did not start in time. Aborting.\n";
    Utills::printBanner(true);
    return EXIT_FAILURE;
  }

  std::cout << "[5/15] Enabling shared folders...\n";
  const std::string cmdEnableShare = std::format(R"({} -T ws enableSharedFolders {})",
                                                 vmRunPath, sandboxVmx);
  Utills::executeAndWait(cmdEnableShare);

  std::cout << "[6/15] Adding shared folder alias '" << SHARED_FOLDER_NAME << "' -> " << hostShared << " ...\n";
  const std::string cmdAddShare = std::format(R"({} -T ws addSharedFolder {} {} {} -writable)",
                                              vmRunPath, sandboxVmx,
                                              std::string(SHARED_FOLDER_NAME),
                                              ensureQuoted(hostShared.string()));
  Utills::executeAndWait(cmdAddShare);

  std::cout << "[7/15] Sleeping " << BOOTUP_SLEEP_TIME_S << "s to let the guest settle...\n";
  std::this_thread::sleep_for(std::chrono::seconds(BOOTUP_SLEEP_TIME_S));

  std::cout << "[8/15] Creating working directory in guest: " << FILE_PATH_INSIDE << "\n";
  const std::string cmdMkWorkDir = std::format(
      R"({} -T ws -gu {} -gp {} createDirectoryInGuest {} {})",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(std::string(FILE_PATH_INSIDE)));
  Utills::executeAndWait(cmdMkWorkDir);

  std::cout << "[9/15] Validating host files...\n";
  if (!std::filesystem::exists(std::string(PM_FILE_PATH))) {
    std::cerr << "Host file missing: " << PM_FILE_PATH << "\n";
    return EXIT_FAILURE;
  }
  const std::string pmHostAbs = std::filesystem::absolute(std::string(PM_FILE_PATH)).string();
  const std::string suspiciousHostAbs = std::filesystem::absolute(suspiciousHostPath).string();
  if (!std::filesystem::exists(suspiciousHostAbs)) {
    std::cerr << "Host file missing: " << suspiciousHostAbs << "\n";
    return EXIT_FAILURE;
  }

  std::cout << "[10/15] Copying monitor into guest...\n";
  const auto guestPmPath = std::string(PM_FILE_PATH_INSIDE_VM);
  const std::string cmdCopyPM = std::format(
      R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(pmHostAbs), ensureQuoted(guestPmPath));
  Utills::executeAndWait(cmdCopyPM);

  std::cout << "[10.1/15] Verifying monitor exists in guest...\n";
  Utills::executeAndWait(std::format(
      R"({} -T ws -gu {} -gp {} fileExistsInGuest {} {})",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(guestPmPath)));

  std::cout << "[11/15] Copying payload into guest...\n";
  const std::string guestSuspiciousPath =
      (std::filesystem::path(std::string(FILE_PATH_INSIDE)) /
       std::filesystem::path(suspiciousHostPath).filename())
          .string();
  const std::string cmdCopySusp = std::format(
      R"({} -T ws -gu {} -gp {} CopyFileFromHostToGuest {} {} {})",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(suspiciousHostAbs), ensureQuoted(guestSuspiciousPath));
  Utills::executeAndWait(cmdCopySusp);

  std::cout << "[11.1/15] Verifying payload exists in guest...\n";
  Utills::executeAndWait(std::format(
      R"({} -T ws -gu {} -gp {} fileExistsInGuest {} {})",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(guestSuspiciousPath)));

  std::cout << "[12/15] Building shared log path...\n";
  const std::string sharedLogGuestPath = std::format(
      R"(\\vmware-host\Shared Folders\{}\{})",
      std::string(SHARED_FOLDER_NAME),
      std::string(LOG_FILE_NAME));

  const std::string pmStdoutGuestPath = std::format(
      R"(\\vmware-host\Shared Folders\{}\pm_stdout.txt)",
      std::string(SHARED_FOLDER_NAME));

  // guest-side temp stdout
  const std::string pmStdoutGuestLocal = R"(C:\Temp\pm_stdout.txt)";
  const std::string pmStdoutHostPath = (hostShared / "pm_stdout.txt").string();

  std::cout << "[12.5/15] Probing shared-folder write via local->host copy...\n";

  // Use copy NUL (no spaces in the path, so no extra quoting headaches)
  // IMPORTANT: wrap the entire command after /C in quotes
  const std::string probeLocalCmd = std::format(
      R"({} -T ws -gu {} -gp {} runProgramInGuest {} {} /Q /D /C "copy /Y NUL C:\Temp\pm_stdout.txt >NUL 2>&1")",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(R"(C:\Windows\System32\cmd.exe)"));
  Utills::executeAndWait(probeLocalCmd);

  // Now copy that file out to the host (this will fail if the line above didn’t actually create it)
  const std::string probeCopyOut = std::format(
      R"({} -T ws -gu {} -gp {} CopyFileFromGuestToHost {} {} {})",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(pmStdoutGuestLocal), ensureQuoted(pmStdoutHostPath));
  Utills::executeAndWait(probeCopyOut);

  std::cout << "[13/15] Starting monitor in guest (payload + log, runTime=" << runTimeSec << "s)...\n";

  const std::string pmExe = std::string(PM_FILE_PATH_INSIDE_VM);
  const std::string payload = guestSuspiciousPath;
  const std::string logCsv = sharedLogGuestPath;
  const std::string timeArg = (runTimeSec > 0 ? std::format(" {}", runTimeSec) : std::string{});

  // Build one clean command string that cmd.exe will execute as a whole
  const std::string fullCmd = std::format(
      R"("{}" "{}" "{}"{} 1> C:\Temp\pm_stdout.txt 2>&1)",
      pmExe, payload, logCsv, timeArg);

  // Pass it to cmd.exe with /C "…"
  const std::string cmdRunPM = std::format(
      R"({} -T ws -gu {} -gp {} runProgramInGuest {} {} /Q /D /C "{}")",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(R"(C:\Windows\System32\cmd.exe)"),
      fullCmd);
  Utills::executeAndWait(cmdRunPM);

  // Pull stdout to host so you actually see what PM complained about
  const std::string copyStdoutOut = std::format(
      R"({} -T ws -gu {} -gp {} CopyFileFromGuestToHost {} {} {})",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(pmStdoutGuestLocal), ensureQuoted(pmStdoutHostPath));
  Utills::executeAndWait(copyStdoutOut);

  std::cout << "[14/15] Launching payload in guest...\n";
  const std::string cmdRunSuspicious = std::format(
      R"({} -T ws -gu {} -gp {} runProgramInGuest {} {})",
      vmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(guestSuspiciousPath));
  Utills::executeAndWait(cmdRunSuspicious);

  std::cout << "[14.5/15] Letting it run for " << runTimeSec << "s...\n";
  std::this_thread::sleep_for(std::chrono::seconds(runTimeSec));

  std::cout << "[15/15] Shutting down VM (soft, then hard)...\n";
  const std::string cmdStopSoft = std::format(R"({} -T ws stop {} soft)", vmRunPath, sandboxVmx);
  Utills::executeAndWait(cmdStopSoft);
  std::this_thread::sleep_for(std::chrono::seconds(ANIMATION_SLEEP_TIME_S));
  const std::string cmdStopHard = std::format(R"({} -T ws stop {} hard)", vmRunPath, sandboxVmx);
  Utills::executeAndWait(cmdStopHard);

  Utills::printBanner(true);
  return EXIT_SUCCESS;
}
