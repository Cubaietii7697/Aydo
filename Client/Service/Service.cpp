#include "Service.hpp"

#include <stdexcept>

static PROCESS_NOTIFY_INFO *as_proc_info(const std::unique_ptr<ResultData> &p) {
  return dynamic_cast<PROCESS_NOTIFY_INFO *>(p.get());
}

Service::~Service() {
  shutdown();
}

bool Service::init() {
  if (m_km) {
    return true;
  }

  m_km = KernelCommunication::instance();

  if (!m_km->initKernel()) {
    m_km = nullptr;

    return false;
  }

  return true;
}

void Service::shutdown() {
  if (!m_km) {
    return;
  }

  m_km->shutdown();
}

std::wstring Service::toExeName(const std::wstring &input) {
  std::filesystem::path p(input);

  return p.has_filename() ? p.filename().wstring() : input;
}

std::optional<ProcessStartEvent>
Service::waitForStart(const std::wstring &exeName) {
  if (!m_km && !init()) {
    return std::nullopt;
  }

  const std::wstring name = toExeName(exeName);
  auto [status, payload] = m_km->sendRequest(RequestType::WaitForProcessStart, name);
  if (status != ResponseStatus::success || !payload) {
    return std::nullopt;
  }

  auto const *info = as_proc_info(payload);
  if (!info) {
    return std::nullopt;
  }

  ProcessStartEvent ev{info->ProcessId, info->ImageFileName};

  return ev;
}

void Service::watch(const std::wstring &exeName,
                    std::atomic<bool> &stopFlag,
                    const std::function<void(const ProcessStartEvent &)> &onEvent) {
  if (!m_km && !init())
    return;

  const std::wstring name = toExeName(exeName);
  while (!stopFlag.load(std::memory_order_relaxed)) {
    auto [status, payload] = m_km->sendRequest(RequestType::WaitForProcessStart, name);
    if (stopFlag.load(std::memory_order_relaxed))
      break;
    if (status != ResponseStatus::success || !payload)
      break;

    auto const *info = as_proc_info(payload);
    if (!info)
      break;

    onEvent(ProcessStartEvent{info->ProcessId, info->ImageFileName});
  }
}

KillResult Service::killByPid(DWORD pid) {
  using enum KillStatus;
  if (!m_km && !init()) {
    return {.status = Error};
  }

  std::set<DWORD> pids{pid};
  if (auto failures = Utils::killProcces(pids, *m_km); !failures.empty()) {
    return {.status = PartialFailure, .failures = std::move(failures)};
  }

  return {.status = Ok};
}

KillResult Service::killByExe(const std::wstring &exeOrPath) {
  using enum KillStatus;
  if (!m_km && !init()) {
    return {.status = Error};
  }

  auto pids = findPids(exeOrPath);
  if (pids.empty()) {
    return {.status = NotFound};
  }

  if (auto failures = Utils::killProcces(pids, *m_km); !failures.empty()) {
    return {.status = PartialFailure, .failures = std::move(failures)};
  }

  return {.status = Ok};
}

std::set<DWORD> Service::findPids(const std::wstring &exeOrPath) const {
  return Utils::findProcess(exeOrPath);
}
