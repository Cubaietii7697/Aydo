#include "VmRunner.hpp"

#include <cstdlib>
#include <filesystem>
#include <format>

#include <drogon/drogon.h>

#include "../Constants.hpp"
#include "Generic.hpp"

namespace Utils::VmRunner {

bool startVm(const std::string &sandboxId,
             const std::filesystem::path &payloadHostPath,
             int runtimeSeconds) {
  const std::filesystem::path vmRunnerPathFs(Constants::VMRUNNER_PATH);
  const std::filesystem::path resolvedVmRunnerPath =
      vmRunnerPathFs.is_absolute() ? vmRunnerPathFs
                                   : std::filesystem::absolute(vmRunnerPathFs);

  if (!std::filesystem::exists(resolvedVmRunnerPath)) {
    LOG_ERROR << "VMRunner path does not exist: " << resolvedVmRunnerPath.string();
    return false;
  }

  const std::string vmRunnerPath = resolvedVmRunnerPath.string();
  const std::string payloadPath =
      std::filesystem::absolute(payloadHostPath).string();
  // On Windows, cmd.exe strips leading/trailing quotes when the first char is a quote.
  // Wrapping the entire command in quotes fixes this behavior.
  const std::string innerCmd = std::format(
      R"({} {} {} {})",
      Utils::Generic::quoteIfNeeded(vmRunnerPath),
      sandboxId,
      Utils::Generic::quoteIfNeeded(payloadPath),
      runtimeSeconds);
  const std::string cmd = std::format(R"(cmd /c "{}")", innerCmd);

  LOG_INFO << "Launching VMRunner: " << cmd;
  const int rc = std::system(cmd.c_str());
  if (rc != 0) {
    LOG_ERROR << "VMRunner failed with exit code " << rc
              << " (sandboxId=" << sandboxId << ")";
    return false;
  }

  LOG_INFO << "VMRunner completed successfully (sandboxId=" << sandboxId << ")";
  return true;
}

} // namespace Utils::VmRunner
