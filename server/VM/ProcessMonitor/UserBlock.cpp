#include "UserBlock.hpp"
#include <algorithm>
#include <cwctype>
#include <ranges>
#include <string_view>

UserBlock::UserBlock(const std::wstring &userSessionName)
    : m_sessionName(userSessionName) {}

std::wstring_view UserBlock::trim(std::wstring_view x) {
  auto is_space = [](wchar_t ch) {
    return std::iswspace(static_cast<wint_t>(ch)) != 0;
  };

  // first non-space
  auto first = std::ranges::find_if_not(x, is_space);
  if (first == x.end()) {
    return {};
  }

  // last non-space
  auto r = x | std::views::reverse;
  auto rpos = std::ranges::find_if_not(r, is_space); // iterator into the reversed view
  auto last = rpos.base();                           // convert back to forward iterator

  return {std::to_address(first), static_cast<size_t>(last - first)};
}

bool UserBlock::try_parse_guid_string(const wchar_t *s, GUID &out) {
  if (!s || !*s) {
    return false;
  }

  std::wstring t = s;
  t = trim(t);

  if (!t.empty() && t.front() != L'{') {
    t = L"{" + t + L"}";
  }

  return SUCCEEDED(CLSIDFromString(t.c_str(), &out));
}

bool UserBlock::try_resolve_provider_guid_by_name(const wchar_t *name, GUID &out) {
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

void UserBlock::add_provider(const wchar_t *name,
                             UCHAR level,
                             ULONGLONG any,
                             ULONGLONG all) {
  GUID gid{};
  if (try_parse_guid_string(name, gid) || try_resolve_provider_guid_by_name(name, gid)) {
    add_provider(gid, level, any, all);

    return;
  }
}
void UserBlock::add_provider(const GUID &id,
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

void UserBlock::add_api_calls_provider(UCHAR level,
                                       ULONGLONG any,
                                       ULONGLONG all) {
  add_provider(L"Microsoft-Windows-DNS-Client", level, any, all);
  add_provider(L"Microsoft-Windows-WinHTTP", level, any, all);
  add_provider(L"Microsoft-Windows-WMI-Activity", level, any, all);
  add_provider(L"Microsoft-Windows-PowerShell", level, any, all);
  add_provider(L"Microsoft-Windows-DotNETRuntime", level, any, all);
  add_provider(L"Microsoft-Windows-Kernel-Audit-API-Calls", level, any, all);
}

void UserBlock::start(Callback on_event) {
  stop();

  m_trace = std::make_unique<krabs::user_trace>(m_sessionName.c_str());

  m_cb = std::move(on_event);

  for (auto const &p : m_providers) {
    try {
      p->add_on_event_callback(m_cb);
      m_trace->enable(*p);
    } catch (...) {
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
