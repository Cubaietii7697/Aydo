#include "UserBlock.hpp"

#include <new>
#include <windows.h>
#include <algorithm>

#include "ProviderProfiles.hpp"
#include "UserBlockConstants.hpp"
#include "Utils.hpp"

UserBlock::UserBlock(const std::wstring &userSessionName)
    : m_sessionName(userSessionName) {}

bool UserBlock::s_tryParseGuidString(const wchar_t *s, GUID &out) {
  if (!s || !*s) {
    return false;
  }

  std::wstring t = s;
  t = Utils::trim(t);

  if (!t.empty() && t.front() != L'{') {
    t = L"{" + t + L"}";
  }

  return SUCCEEDED(CLSIDFromString(t.c_str(), &out));
}

bool UserBlock::s_tryResolveProviderGuidByName(const wchar_t *name, GUID &out) {
  if (!name || !*name) {
    return false;
  }

  ULONG size = 0;
  auto status = TdhEnumerateProviders(nullptr, &size);
  if (status != ERROR_INSUFFICIENT_BUFFER) {
    return false;
  }

  std::unique_ptr<BYTE[]> buf(new (std::nothrow) BYTE[size]);
  if (!buf) {
    return false;
  }

  auto info = reinterpret_cast<PROVIDER_ENUMERATION_INFO *>(buf.get());
  status = TdhEnumerateProviders(info, &size);
  if (status != ERROR_SUCCESS) {
    return false;
  }

  for (ULONG i = 0; i < info->NumberOfProviders; ++i) {
    auto const &pi = info->TraceProviderInfoArray[i];
    auto pname = reinterpret_cast<const wchar_t *>(
        reinterpret_cast<const BYTE *>(info) + pi.ProviderNameOffset);
    if (_wcsicmp(pname, name) == 0) {
      out = pi.ProviderGuid;

      return true;
    }
  }
  return false;
}

void UserBlock::addProvider(const wchar_t *name,
                            UCHAR level,
                            ULONGLONG any,
                            ULONGLONG all) {
  (void)_addProviderByName(name, level, any, all);
}

void UserBlock::addProvider(const GUID &id,
                            UCHAR level,
                            ULONGLONG any,
                            ULONGLONG all) {
  auto p = std::make_unique<krabs::provider<>>(id);
  p->level(level);
  if (any) {
    p->any(any);
  }

  if (all) {
    p->all(all);
  }
  m_providers.emplace_back(std::move(p));
}

void UserBlock::addApiCallsProvider(UCHAR level,
                                    ULONGLONG any,
                                    ULONGLONG all) {
  addAnalystProviders(level, any, all);
}

void UserBlock::addAnalystProviders(UCHAR level,
                                    ULONGLONG any,
                                    ULONGLONG all) {
  m_providers.clear();
  m_providerStats = UserProviderEnableStats{};

  for (const auto *providerName : ProviderProfiles::getAnalystUserProviders()) {
    ++m_providerStats.requested;
    if (ProviderProfiles::isForbiddenProvider(providerName)) {
      ++m_providerStats.unresolved;
      _logMissingProviderOnce(providerName);
      continue;
    }

    if (_addProviderByName(providerName, level, any, all)) {
      ++m_providerStats.resolved;
      continue;
    }

    ++m_providerStats.unresolved;
    _logMissingProviderOnce(providerName);
  }
}

UserProviderEnableStats UserBlock::getProviderEnableStats() const {
  return m_providerStats;
}

void UserBlock::start(Callback on_event) {
  stop();

  m_trace = std::make_unique<krabs::user_trace>(m_sessionName.c_str());

  m_cb = std::move(on_event);
  m_providerStats.enabled = 0;
  m_providerStats.failed_enable = 0;

  for (auto const &p : m_providers) {
    try {
      p->add_on_event_callback(m_cb);
      m_trace->enable(*p);
      ++m_providerStats.enabled;
    } catch (...) {
      ++m_providerStats.failed_enable;
    }
  }

  m_thread = std::thread([this] {
    try {
      m_trace->start();
    } catch (...) {
    }
  });
}

void UserBlock::stop() {
  if (m_trace) {
    m_trace->stop();
  }
  if (m_thread.joinable()) {
    m_thread.join();
  }
  m_trace.reset();
  m_cb = Callback{};
}

bool UserBlock::stopWithDeadline(const Deadline &deadline) {
  if (m_trace) {
    m_trace->stop();
  }

  bool ok = true;
  if (m_thread.joinable()) {
    const auto rem = deadline.remaining_ms();
    const DWORD waitMs = static_cast<DWORD>(std::clamp<long long>(rem.count(), UserBlockConstants::MIN_WAIT_MS, UserBlockConstants::MAX_WAIT_MS));
    const HANDLE h = reinterpret_cast<HANDLE>(m_thread.native_handle());
    const DWORD res = WaitForSingleObject(h, waitMs);
    if (res == WAIT_OBJECT_0) {
      m_thread.join();
    } else {
      OutputDebugStringA(UserBlockConstants::TIMEOUT_DETACH_MSG);
      m_thread.detach();
      ok = false;
    }
  }

  m_trace.reset();
  m_cb = Callback{};
  return ok;
}

bool UserBlock::_addProviderByName(const wchar_t *name,
                                   UCHAR level,
                                   ULONGLONG any,
                                   ULONGLONG all) {
  GUID gid{};
  if (s_tryParseGuidString(name, gid) || s_tryResolveProviderGuidByName(name, gid)) {
    addProvider(gid, level, any, all);
    return true;
  }
  return false;
}

void UserBlock::_logMissingProviderOnce(const wchar_t *name) {
  if (!name || !*name) {
    return;
  }
  std::wstring providerName{name};
  if (m_loggedMissingProviders.contains(providerName)) {
    return;
  }
  m_loggedMissingProviders.insert(providerName);

  std::string msg = "UserBlock: provider unavailable or not registered (continuing): ";
  msg += Utils::narrow_utf8(providerName);
  msg += "\n";
  OutputDebugStringA(msg.c_str());
}
