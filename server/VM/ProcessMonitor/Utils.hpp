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
std::wstring TrimWs(std::wstring s);
std::wstring ToLower(std::wstring s);

std::wstring ComposeEvent(const krabs::schema &s);

std::string InferCategory(const std::wstring &providerW,
                          const std::wstring &taskW);
void SetIfFound(nlohmann::json &dst, const char *key, const nlohmann::json &src,
                std::initializer_list<const char *> names);

nlohmann::json NormalizeProto(const nlohmann::json &props);

nlohmann::json ExtractNet(const nlohmann::json &props);

std::string NtstatusToText(const nlohmann::json &v);

nlohmann::json ExtractDns(const nlohmann::json &props);

nlohmann::json ExtractFile(const nlohmann::json &props,
                           const std::wstring &task,
                           const std::wstring &opname);

typedef BOOL(WINAPI *IsWow64Process2_t)(HANDLE, USHORT *, USHORT *);
int ResolveBitness(HANDLE h);
std::string narrow_utf8(const std::wstring &w);

nlohmann::json BestEffortProcFromPid(DWORD pid);

nlohmann::json NormUintOrNull(ULONG v);

unsigned long long ts100nsFromLargeInteger(const LARGE_INTEGER &ts);
std::string getHostName();
std::string iso8601FromLargeIntegerTimestamp(const LARGE_INTEGER &ts);
std::string guidToString(const GUID &g);
} // namespace Utils
