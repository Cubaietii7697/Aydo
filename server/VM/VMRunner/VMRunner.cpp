#include "Utills.hpp"

int main(int argc, char *argv[]) {
  // We expect args to be: <executable path> <sandbox_id>.
  // argv[0] is the executable path.
  // argv[1] is the sandbox id.
  // argv[2] is the time for ETW
  if (argc < 2 || argc > 3) {
    std::cerr << "Usage: " << argv[0] << " <sandbox_id> [runTime]" << std::endl;
    return EXIT_FAILURE;
  }

  std::string sandboxId(argv[1]);
  const int time = (argc == 3) ? atoi(argv[2]) : 0;

  Utills::printBanner();

  std::string analysisVmPath(ANALYSIS_VM_PATH);
  std::string sandboxesDirectoryPath(SANDBOXES_DIRECTORY_PATH);
  std::string vmRunPath(VM_RUN_PATH);

  const std::string sandboxPath = std::format("{}\\{}\\{}.vmx",
                                              sandboxesDirectoryPath,
                                              sandboxId,
                                              sandboxId);

  const std::string vmRunCommand = std::format("{} clone {} {} linked -cloneName={}",
                                               vmRunPath,
                                               analysisVmPath,
                                               sandboxPath,
                                               sandboxId);
  Utills::executeAndWait(vmRunCommand);

  const std::string vmRunCommandAddShare = std::format("{} addSharedFolder {} {} \"{}\"",
                                                       vmRunPath,
                                                       sandboxPath,
                                                       SHARE_FILE_NAME,
                                                       HOST_FOLDER_PATH);
  Utills::executeAndWait(vmRunCommandAddShare);

  std::string vmRunCommandEnableShare = std::format("{} enableSharedFolders {}",
                                                    vmRunPath,
                                                    sandboxPath);
  Utills::executeAndWait(vmRunCommandEnableShare);

  std::string vmRunCommand2 = std::format("{} start {}",
                                          vmRunPath,
                                          sandboxPath);
  Utills::executeAndWait(vmRunCommand2);

  std::cout << "Waiting for VMware Tools..." << std::endl;
  if (!Utills::waitForTools(vmRunPath, sandboxPath)) {
    std::cerr << "VMware Tools did not start in time. Aborting." << std::endl;
    return EXIT_FAILURE;
  }

  std::string copyCmd = std::format(
      R"("{}" -T ws -gu {} -gp {} CopyFileFromHostToGuest "{}" "{}" "{}")",
      VM_RUN_PATH,
      GUEST_USER,
      GUEST_PASS,
      sandboxPath,
      PM_FILE_PATH,
      PM_FILE_PATH_GUEST);
  Utills::executeAndWait(copyCmd);

  std::string runCmd = std::format(
      R"("{}" -T ws -gu {} -gp {} runProgramInGuest "{}" -activeWindow -interactive "{}" "{}" "{}")",
      VM_RUN_PATH,
      GUEST_USER,
      GUEST_PASS,
      sandboxPath,
      PM_FILE_PATH_GUEST,
      SUSPICIOUS_FILE_PATH,
      SHARE_FILE_NAME);
  if (time) {
    runCmd = std::format("{} {}", runCmd, time);
  }
  Utills::executeAndWait(runCmd);

  std::string runCmdPlot = std::format(
      R"("{}" -T ws -gu {} -gp {} runProgramInGuest "{}" -activeWindow -interactive "{}")",
      VM_RUN_PATH,
      GUEST_USER,
      GUEST_PASS,
      sandboxPath,
      SUSPICIOUS_FILE_PATH);
  Utills::executeAndWait(runCmdPlot);

  Utills::printBanner(true);
}
