#include "ProviderProfiles.hpp"

namespace ProviderProfiles {

static constexpr std::array<const wchar_t *, g_ANALYST_USER_PROVIDER_COUNT> s_ANALYST_USER_PROVIDERS = {
    L"Microsoft-Windows-Kernel-Audit-API-Calls",
    L"Microsoft-Windows-Threat-Intelligence",
    L"Microsoft-Windows-TaskScheduler",
    L"Microsoft-Windows-Services",
    L"Microsoft-Windows-WMI-Activity",
    L"Microsoft-Windows-PowerShell",
    L"Microsoft-Windows-Bits-Client",
    L"Microsoft-Windows-CodeIntegrity",
    L"Microsoft-Windows-Windows Defender",
    L"Microsoft-Windows-DNS-Client",
    L"Microsoft-Windows-WinHTTP",
};

const std::array<const wchar_t *, g_ANALYST_USER_PROVIDER_COUNT> &getAnalystUserProviders() {
  return s_ANALYST_USER_PROVIDERS;
}

bool isForbiddenProvider(std::wstring_view providerName) {
  return providerName.find(L"Sysmon") != std::wstring_view::npos ||
         providerName.find(L"sysmon") != std::wstring_view::npos;
}

} // namespace ProviderProfiles
