#pragma once
#include <krabs.hpp>

struct UserBlock {
  krabs::user_trace trace{L"AydoUserTrace"};

  // TODO: fix providers ots kernel not user
  krabs::provider<> apiCalls{L"Microsoft-Windows-Kernel-Audit-API-Calls"};
  krabs::provider<> dns{L"Microsoft-Windows-DNS-Client"};
  krabs::provider<> winhttp{L"Microsoft-Windows-WinHTTP"};
  krabs::provider<> wmi{L"Microsoft-Windows-WMI-Activity"};
  krabs::provider<> powershell{L"Microsoft-Windows-PowerShell"};
  krabs::provider<> dotnet{L"Microsoft-Windows-DotNETRuntime"};
};
