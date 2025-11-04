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

  void add_api_calls_provider(UCHAR level,
                              ULONGLONG any,
                              ULONGLONG all);

  void add_provider(const wchar_t *name,
                    UCHAR level,
                    ULONGLONG any,
                    ULONGLONG all);

  void add_provider(const GUID &id,
                    UCHAR level,
                    ULONGLONG any,
                    ULONGLONG all);

private:
  static bool try_parse_guid_string(const wchar_t *s, GUID &out);
  static bool try_resolve_provider_guid_by_name(const wchar_t *name, GUID &out);
  static std::wstring_view trim(std::wstring_view x);

private:
  std::unique_ptr<krabs::user_trace> m_trace;
  std::vector<std::unique_ptr<krabs::provider<>>> m_providers;
  std::wstring m_sessionName;
  std::thread m_thread;
  Callback m_cb;
};
