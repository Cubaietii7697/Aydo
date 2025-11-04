#include "Utils.hpp"

std::wstring Utils::TrimWs(std::wstring s) {
  auto is_space = [](wchar_t c) { return c == L' ' || c == L'\t' || c == L'\n' || c == L'\r'; };
  size_t b = 0;
  size_t e = s.size();
  while (b < e && is_space(s[b])) {
    ++b;
  }

  while (e > b && is_space(s[e - 1])) {
    --e;
  }

  return s.substr(b, e - b);
}

std::wstring Utils::ToLower(std::wstring s) {
  for (auto &c : s) {
    c = (wchar_t)towlower(c);
  }

  return s;
}

std::wstring Utils::ComposeEvent(const krabs::schema &s) {
  std::wstring ev;
  try {
    ev = s.event_name();
  } catch (...) {
  }
  ev = TrimWs(ev);
  if (!ev.empty())
    return ev;

  std::wstring task;
  std::wstring op;
  try {
    task = s.task_name();
  } catch (...) {
  }
  try {
    op = s.opcode_name();
  } catch (...) {
  }
  task = TrimWs(task);
  op = TrimWs(op);

  if (!task.empty() || !op.empty()) {
    std::wstring out = task;
    if (!op.empty()) {
      if (!out.empty()) {
        out += L"/";
      }

      out += op;
    }
    return out.empty() ? L"#" + std::to_wstring(s.event_opcode()) : out;
  }
  return L"#" + std::to_wstring(s.event_opcode());
}

std::string Utils::InferCategory(const std::wstring &providerW, const std::wstring &taskW) {
  auto p = ToLower(providerW);
  auto t = ToLower(taskW);
  if (p.contains(L"dotnetruntime")) {
    return ".net";
  }

  if (p.contains(L"dns-client")) {
    return "dns";
  }

  if (p.contains(L"winhttp") ||
      p.contains(L"http")) {
    return "http";
  }

  if (p.contains(L"wmi-activity")) {
    return "wmi";
  }

  if (p.contains(L"powershell")) {
    return "ps";
  }

  if (p.contains(L"tcpip")) {
    return "net";
  }

  if (p.contains(L"kernel")) {
    if (t.contains(L"thread")) {
      return "thread";
    }

    if (t.contains(L"process")) {
      return "process";
    }

    if (t.contains(L"file")) {
      return "file";
    }

    if (t.contains(L"registry")) {
      return "reg";
    }

    return "kernel";
  }
  if (t.contains(L"registry")) {
    return "reg";
  }

  if (t.contains(L"file")) {
    return "file";
  }

  if (t.contains(L"network") ||
      t.contains(L"tcp")) {
    return "net";
  }

  return "other";
}

void Utils::SetIfFound(nlohmann::json &dst, const char *key, const nlohmann::json &src, std::initializer_list<const char *> names) {
  for (auto n : names) {
    auto it = src.find(n);
    if (it != src.end() && !it->is_null()) {
      dst[key] = *it;

      return;
    }
  }
}

nlohmann::json Utils::NormalizeProto(const nlohmann::json &props) {
  auto it = props.find("Protocol");
  if (it != props.end()) {
    if (it->is_number_integer()) {
      int v = *it;
      if (v == 6) {
        return "TCP";
      }

      if (v == 17) {
        return "UDP";
      }

      return v;
    }

    return *it;
  }
  it = props.find("protocol");
  if (it != props.end()) {
    return *it;
  }

  return nlohmann::json();
}

nlohmann::json Utils::ExtractNet(const nlohmann::json &props) {
  nlohmann::json net;
  SetIfFound(net, "dst", props, {"daddr", "DestAddress", "DestIp", "RemoteIP", "DestinationIp", "dstIp"});
  SetIfFound(net, "dport", props, {"dport", "DestPort", "RemotePort", "DestinationPort", "dstPort"});
  if (auto proto = NormalizeProto(props); !proto.is_null()) {
    net["proto"] = proto;
  }

  return net;
}

std::string Utils::NtstatusToText(const nlohmann::json &v) {
  if (v.is_number_integer()) {
    auto code = (unsigned long)v.get<long long>();
    if (code == 0) {
      return "SUCCESS";
    }

    std::ostringstream oss;
    oss << "0x" << std::hex << code;
    return oss.str();
  }
  if (v.is_string()) {
    return v.get<std::string>();
  }

  return "UNKNOWN";
}

nlohmann::json Utils::ExtractDns(const nlohmann::json &props) {
  nlohmann::json dns;
  SetIfFound(dns, "qname", props, {"QueryName", "Name", "Query", "DomainName"});
  SetIfFound(dns, "qtype", props, {"QueryType", "Type"});
  SetIfFound(dns, "rcode", props, {"QueryStatus", "Status", "ResponseCode", "RCode"});
  return dns;
}

nlohmann::json Utils::ExtractFile(const nlohmann::json &props, const std::wstring &task, const std::wstring &opname) {
  nlohmann::json f;
  SetIfFound(f, "path", props, {"FileName", "FilePath", "ObjectName", "ImagePath", "Path"});
  SetIfFound(f, "op", props, {"Operation", "IrpOp"});

  if (!f.contains("op")) {
    std::wstring op = TrimWs(opname);
    std::wstring tk = TrimWs(task);
    std::wstring combo = tk;
    if (!op.empty()) {
      if (!combo.empty())
        combo += L"/";
      combo += op;
    }
    if (!combo.empty()) {
      f["op"] = narrow_utf8(combo);
    }
  }

  if (auto it = props.find("Status"); it != props.end()) {
    f["status"] = NtstatusToText(*it);
  } else if (auto it2 = props.find("NtStatus"); it2 != props.end()) {
    f["status"] = NtstatusToText(*it2);
  } else if (auto it3 = props.find("ReturnValue"); it3 != props.end()) {
    f["status"] = NtstatusToText(*it3);
  }
  return f;
}

int Utils::ResolveBitness(HANDLE h) {
  HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
  if (auto pIsWow64Process2 = reinterpret_cast<IsWow64Process2_t>(
          GetProcAddress(k32, "IsWow64Process2"));
      pIsWow64Process2) {
    USHORT processMachine = 0;
    USHORT nativeMachine = 0;
    if (pIsWow64Process2(h, &processMachine, &nativeMachine)) {
      bool isNative64 = (nativeMachine == IMAGE_FILE_MACHINE_AMD64 ||
                         nativeMachine == IMAGE_FILE_MACHINE_ARM64);
      bool isWow = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN);
      if (isNative64 && !isWow) {
        return 64;
      }

      if (isNative64 && isWow) {
        return 32;
      }
    }
  } else {
    BOOL wow = FALSE;
    if (IsWow64Process(h, &wow)) {
      SYSTEM_INFO si{};
      GetNativeSystemInfo(&si);
      bool os64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                   si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
      if (os64) {
        return wow ? 32 : 64;
      }
    }
  }
  return 64; // assumption
}

std::string Utils::narrow_utf8(const std::wstring &w) {
  if (w.empty()) {
    return {};
  }

  int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
  return s;
}

nlohmann::json Utils::BestEffortProcFromPid(DWORD pid) {
  nlohmann::json p;
  if (pid == 0 || pid == 0xFFFFFFFFu) {
    return p;
  }

  if (HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); h) {
    wchar_t buf[MAX_PATH];
    if (DWORD sz = MAX_PATH; QueryFullProcessImageNameW(h, 0, buf, &sz)) {
      std::wstring wpath(buf, sz);
      p["path"] = narrow_utf8(wpath);
      auto pos = wpath.find_last_of(L"\\/");
      p["name"] = narrow_utf8(pos == std::wstring::npos ? wpath : wpath.substr(pos + 1));
    }
    p["bitness"] = ResolveBitness(h);
    ::CloseHandle(h);
  }
  return p;
}

nlohmann::json Utils::NormUintOrNull(ULONG v) {
  return (v == 0xFFFFFFFFuL) ? nlohmann::json(nullptr) : nlohmann::json(v);
}

unsigned long long Utils::ts100nsFromLargeInteger(const LARGE_INTEGER &ts) {
  ULARGE_INTEGER u;
  u.LowPart = ts.LowPart;
  u.HighPart = ts.HighPart;
  return u.QuadPart;
}

std::string Utils::getHostName() {
  wchar_t buf[256]{};
  DWORD len = (DWORD)std::size(buf);
  if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf, &len)) {
    return Utils::narrow_utf8(std::wstring(buf, len));
  }

  len = (DWORD)std::size(buf);
  if (GetComputerNameW(buf, &len)) {
    return Utils::narrow_utf8(std::wstring(buf, len));
  }

  return {};
}

std::string Utils::iso8601FromLargeIntegerTimestamp(const LARGE_INTEGER &ts) {
  ULARGE_INTEGER uli{};
  uli.QuadPart = static_cast<ULONGLONG>(ts.QuadPart);
  FILETIME ft{.dwLowDateTime = ts.LowPart, .dwHighDateTime = uli.HighPart};
  SYSTEMTIME st_utc{};

  if (!FileTimeToSystemTime(&ft, &st_utc)) {
    return {};
  }
  std::ostringstream oss;
  oss << std::setfill('0')
      << std::setw(4) << st_utc.wYear << "-"
      << std::setw(2) << st_utc.wMonth << "-"
      << std::setw(2) << st_utc.wDay << "T"
      << std::setw(2) << st_utc.wHour << ":"
      << std::setw(2) << st_utc.wMinute << ":"
      << std::setw(2) << st_utc.wSecond << "."
      << std::setw(3) << st_utc.wMilliseconds << "Z";

  return oss.str();
}

std::string Utils::guidToString(const GUID &g) {
  wchar_t buf[64];
  if (int n = ::StringFromGUID2(g, buf, 64); n <= 0) {
    return {};
  }

  return Utils::narrow_utf8(buf);
}
