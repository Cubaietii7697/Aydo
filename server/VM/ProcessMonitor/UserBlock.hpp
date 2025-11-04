#pragma once
#include <krabs.hpp>
#include <memory>
#include <thread>
#include <vector>

class UserBlock {
public:
  using Callback = std::function<void(const EVENT_RECORD &, const krabs::trace_context &)>;
  explicit UserBlock(const std::wstring &userSessionName);
  void start(Callback on_event);
  void stop();

  void addApiCallsProvider(UCHAR level,
                           ULONGLONG any,
                           ULONGLONG all);

  void addProvider(const wchar_t *name,
                   UCHAR level,
                   ULONGLONG any,
                   ULONGLONG all);

  void addProvider(const GUID &id,
                   UCHAR level,
                   ULONGLONG any,
                   ULONGLONG all);

private:
  static bool tryParseGuidString(const wchar_t *s, GUID &out);
  static bool tryResolveProviderGuidByName(const wchar_t *name, GUID &out);

private:
  std::unique_ptr<krabs::user_trace> m_trace;
  std::vector<std::unique_ptr<krabs::provider<>>> m_providers;
  std::wstring m_sessionName;
  std::thread m_thread;
  Callback m_cb;
};
