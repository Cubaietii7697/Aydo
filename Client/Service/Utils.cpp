#define NOMINMAX
#include "Utils.hpp"

#include <cwctype>
#include <fstream>
#include <psapi.h>
#include <softpub.h>
#include <vector>
#include <wintrust.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include "Errors.hpp"

using namespace Utils::Const;

std::vector<uint8_t> Utils::readFile(const std::string &path) {
  std::ifstream file(path, std::ios::binary);

  if (!file) {
    throw Errors::FailedToOpenFileException();
  }

  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

bool Utils::is_nt_device_path(const std::wstring &p) {
  return p.rfind(L"\\Device\\", 0) == 0 || p.rfind(L"\\??\\", 0) == 0;
}

// check if its a standard dos path (c:\windows and not \??\c:\windows)
bool Utils::is_dos_path(const std::wstring &p) {
  return p.size() > 2 && std::iswalpha(static_cast<unsigned char>(p[0])) &&
         p[1] == L':' && (p[2] == L'\\' || p[2] == L'/');
}

std::wstring Utils::device_to_dos_path(const std::wstring &devicePath) {
  if (devicePath.empty())
    return devicePath;

  // Fast path: \??\C:\Windows\...  -> C:\Windows\...
  if (devicePath.rfind(L"\\??\\", 0) == 0 && devicePath.size() >= 4) {
    return devicePath.substr(4);
  }

  // Map \Device\HarddiskVolumeX to a DOS drive letter
  wchar_t drives[kDriveStringsBufChars] = {0};
  DWORD len = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives) - 1), drives);
  for (wchar_t const *p = drives; p && *p; p += wcslen(p) + 1) {
    // p is like "C:\"
    const std::wstring dosRoot = p;                  // "C:\"
    const std::wstring drive = dosRoot.substr(0, 2); // "C:"
    wchar_t target[kDosDeviceTargetBufChars] = {0};
    if (QueryDosDeviceW(drive.c_str(), target, static_cast<DWORD>(std::size(target) - 1))) {
      // target may contain multiple null-terminated strings; we only need the first mapping
      std::wstring dev = target; // e.g. \Device\HarddiskVolume3
      if (!dev.empty() && devicePath.rfind(dev, 0) == 0) {
        return drive + devicePath.substr(dev.size());
      }
    }
  }
  // No mapping found; return as-is.
  return devicePath;
}

std::optional<std::wstring> Utils::resolve_from_image_only(const std::wstring &imageFromDriver) {
  if (imageFromDriver.empty())
    return std::nullopt;
  if (is_dos_path(imageFromDriver))
    return imageFromDriver;
  if (is_nt_device_path(imageFromDriver))
    return device_to_dos_path(imageFromDriver);

  // Base name like "foo.exe" cannot be resolved uniquely without PID.
  return std::nullopt;
}

std::optional<std::wstring> Utils::full_image_path_from_pid(DWORD pid) {
  // Prefer QueryFullProcessImageNameW (requires PROCESS_QUERY_LIMITED_INFORMATION)
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (h) {
    DWORD sz = kMaxUnicodePathChars; // max per docs
    if (std::wstring buf(sz, L'\0'); QueryFullProcessImageNameW(h, 0, buf.data(), &sz)) {
      buf.resize(sz);
      CloseHandle(h);
      return buf;
    }
    CloseHandle(h);
  }

  // Fallback: PSAPI device-style path
  h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (h) {
    if (wchar_t wbuf[MAX_PATH *kPsapiPathReserveMultiplier] = {0}; GetProcessImageFileNameW(h, wbuf, static_cast<DWORD>(std::size(wbuf)))) {
      CloseHandle(h);
      return device_to_dos_path(wbuf);
    }
    CloseHandle(h);
  }

  return std::nullopt;
}

std::wstring Utils::resolve_process_path(DWORD pid, const std::wstring &imageFromDriver) {
  if (auto s = resolve_from_image_only(imageFromDriver)) {
    return *s; // already a normalized DOS path
  }
  if (auto p = full_image_path_from_pid(pid)) {
    return *p; // best-effort from the OS
  }

  // Last resort: return whatever the driver gave us (likely a base name).
  return imageFromDriver;
}

std::string Utils::wstring_to_utf8(const std::wstring &w) {
  if (w.empty())
    return {};
  int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                               nullptr, 0, nullptr, nullptr);
  if (sz <= 0)
    return {};
  std::string out(static_cast<size_t>(sz), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                      out.data(), sz, nullptr, nullptr);
  return out;
}

std::string Utils::computeSHA256(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file)
    return "";

  auto hasher = Botan::HashFunction::create_or_throw("SHA-256");
  std::vector<uint8_t> buf(64 * 1024);

  while (file) {
    file.read(reinterpret_cast<char *>(buf.data()), buf.size());
    std::streamsize bytesRead = file.gcount();
    if (bytesRead > 0)
      hasher->update(buf.data(), static_cast<size_t>(bytesRead));
  }

  return Botan::hex_encode(hasher->final());
}

double Utils::calculateEntropy(const std::vector<int> &countedBytes, const std::streamsize totalLength) {
  double entropy = 0.0;
  double temp;

  for (int i = 0; i < 256; i++) {
    temp = countedBytes[i] / static_cast<double>(totalLength);

    if (temp > 0.0)
      entropy += temp * fabs(log2(temp));
  }

  return entropy;
}

bool Utils::isWindowsSigned(const std::string &path) {
  // Convert UTF-8 path to wide string
  int sz = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
  if (sz <= 0)
    return false;

  std::wstring wpath(static_cast<size_t>(sz), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), sz);
  wpath.resize(sz - 1); // Remove null terminator from size

  // Set up WinTrust file info structure
  WINTRUST_FILE_INFO fileInfo = {};
  fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
  fileInfo.pcwszFilePath = wpath.c_str();
  fileInfo.hFile = nullptr;
  fileInfo.pgKnownSubject = nullptr;

  // Set up WinTrust data structure
  WINTRUST_DATA winTrustData = {};
  winTrustData.cbStruct = sizeof(WINTRUST_DATA);
  winTrustData.pPolicyCallbackData = nullptr;
  winTrustData.pSIPClientData = nullptr;
  winTrustData.dwUIChoice = WTD_UI_NONE;              // No UI
  winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; // Skip revocation check for performance
  winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
  winTrustData.pFile = &fileInfo;
  winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
  winTrustData.hWVTStateData = nullptr;
  winTrustData.pwszURLReference = nullptr;
  winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL; // Use cache only for better performance
  winTrustData.dwUIContext = 0;

  // GUID for WinVerifyTrust action (WINTRUST_ACTION_GENERIC_VERIFY_V2)
  GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

  // Verify the signature
  LONG status = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

  // Clean up state data
  winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

  // Return true only if the signature is valid and trusted
  return status == ERROR_SUCCESS;
}
