#include "pch.h"
#include <krabs.hpp>
#include <cwctype>
#include <initializer_list>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

namespace Utils {

std::wstring trimWs(std::wstring s);
std::wstring toLower(std::wstring s);
std::wstring widenUtf8(const std::string &s);
std::wstring composeEvent(const krabs::schema &s);

std::string inferCategory(const std::wstring &providerW,
                          const std::wstring &taskW);
void setIfFound(nlohmann::json &dst, const char *key, const nlohmann::json &src,
                std::initializer_list<const char *> names);

std::wstring_view trim(std::wstring_view x);

nlohmann::json normalizeProto(const nlohmann::json &props);

nlohmann::json extractNet(const nlohmann::json &props);

std::string ntStatusToText(const nlohmann::json &v);

nlohmann::json extractDns(const nlohmann::json &props);

nlohmann::json extractFile(const nlohmann::json &props,
                           const std::wstring &task,
                           const std::wstring &opname);

typedef BOOL(WINAPI *IsWow64Process2_t)(HANDLE, USHORT *, USHORT *);
int resolveBitness(HANDLE h);
std::string narrow_utf8(const std::wstring &w);

nlohmann::json bestEffortProcFromPid(DWORD pid);

nlohmann::json normUintOrNull(ULONG v);

unsigned long long ts100nsFromLargeInteger(const LARGE_INTEGER &ts);
std::string getHostName();
std::string iso8601FromLargeIntegerTimestamp(const LARGE_INTEGER &ts);
std::string guidToString(const GUID &g);
} // namespace Utils
