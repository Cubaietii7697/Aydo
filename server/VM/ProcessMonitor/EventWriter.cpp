#include "EventWriter.hpp"
#include <tdh.h>
#include <iomanip>
#include <objbase.h>
#include <sstream>
#include "Utils.hpp"

using nlohmann::json;

EventWriter::EventWriter(std::wstring path,
                         WireFormat fmt,
                         bool pretty,
                         bool length_prefixed)
    : path_(std::move(path))
    , pretty_(pretty)
    , fmt_(fmt)
    , length_prefixed_(length_prefixed) {
  out_.open(path_, std::ios::out | std::ios::app | std::ios::binary);
}

void EventWriter::flush() {
  std::scoped_lock<std::mutex> lk(mtx_);
  out_.flush();
}

static inline const wchar_t *info_wstr(const TRACE_EVENT_INFO *info, ULONG offset) {
  return reinterpret_cast<const wchar_t *>(
      reinterpret_cast<const BYTE *>(info) + offset);
}

void EventWriter::fill_props_via_tdh(nlohmann::json &props,
                                     const EVENT_RECORD &rec,
                                     const krabs::trace_context &ctx) const {
  ULONG size = 0;
  auto status = ::TdhGetEventInformation(const_cast<EVENT_RECORD *>(&rec),
                                         0, nullptr, nullptr, &size);
  if (status != ERROR_INSUFFICIENT_BUFFER || size == 0)
    return;

  std::vector<BYTE> buf(size);
  auto info = reinterpret_cast<TRACE_EVENT_INFO *>(buf.data());
  status = ::TdhGetEventInformation(const_cast<EVENT_RECORD *>(&rec),
                                    0, nullptr, info, &size);
  if (status != ERROR_SUCCESS)
    return;

  krabs::schema schema(rec, ctx.schema_locator);
  krabs::parser parser(schema);

  for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
    auto const &epi = info->EventPropertyInfoArray[i];
    const wchar_t *wname = info_wstr(info, epi.NameOffset);
    const std::string name = Utils::narrow_utf8(wname);

    auto inType = epi.nonStructType.InType;

    try {
      switch (inType) {
      case TDH_INTYPE_UNICODESTRING: {
        auto w = parser.parse<std::wstring>(wname);
        props[name] = Utils::narrow_utf8(w);
        break;
      }
      case TDH_INTYPE_ANSISTRING: {
        props[name] = parser.parse<std::string>(wname);
        break;
      }
      case TDH_INTYPE_INT8: {
        props[name] = parser.parse<int8_t>(wname);
        break;
      }
      case TDH_INTYPE_UINT8: {
        props[name] = parser.parse<uint8_t>(wname);
        break;
      }
      case TDH_INTYPE_INT16: {
        props[name] = parser.parse<int16_t>(wname);
        break;
      }
      case TDH_INTYPE_UINT16: {
        props[name] = parser.parse<uint16_t>(wname);
        break;
      }
      case TDH_INTYPE_INT32: {
        props[name] = parser.parse<int32_t>(wname);
        break;
      }
      case TDH_INTYPE_UINT32: {
        props[name] = parser.parse<uint32_t>(wname);
        break;
      }
      case TDH_INTYPE_INT64: {
        props[name] = parser.parse<int64_t>(wname);
        break;
      }
      case TDH_INTYPE_UINT64: {
        props[name] = parser.parse<uint64_t>(wname);
        break;
      }
      case TDH_INTYPE_BOOLEAN: {
        props[name] = parser.parse<bool>(wname);
        break;
      }
      case TDH_INTYPE_GUID: {
        GUID g = parser.parse<GUID>(wname);
        wchar_t buf[64];
        ::StringFromGUID2(g, buf, 64);
        props[name] = Utils::narrow_utf8(buf);
        break;
      }
      case TDH_INTYPE_POINTER:
      case TDH_INTYPE_HEXINT32:
      case TDH_INTYPE_HEXINT64: {
        try {
          auto v = parser.parse<uint64_t>(wname);
          std::ostringstream oss;
          oss << "0x" << std::hex << std::nouppercase << v;
          props[name] = oss.str();
        } catch (...) {
          auto v = parser.parse<uint32_t>(wname);
          std::ostringstream oss;
          oss << "0x" << std::hex << std::nouppercase << v;
          props[name] = oss.str();
        }
        break;
      }
      default:
        try {
          auto w = parser.parse<std::wstring>(wname);
          props[name] = Utils::narrow_utf8(w);
        } catch (...) {
          props[name] = "<unsupported>";
        }
        break;
      }
    } catch (...) {
      props[name] = "<parse_error>";
    }
  }
}

std::string EventWriter::guid_to_string(const GUID &g) {
  wchar_t buf[64];
  if (int n = ::StringFromGUID2(g, buf, 64); n <= 0)
    return {};
  return Utils::narrow_utf8(buf);
}

std::string EventWriter::iso8601_from_large_integer_timestamp(const LARGE_INTEGER &ts) {
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

unsigned long long EventWriter::ts100ns_from_large_integer(const LARGE_INTEGER &ts) {
  ULARGE_INTEGER u;
  u.LowPart = ts.LowPart;
  u.HighPart = ts.HighPart;
  return u.QuadPart;
}

std::string EventWriter::host_name() {
  wchar_t buf[256]{};
  DWORD len = (DWORD)std::size(buf);
  if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf, &len))
    return Utils::narrow_utf8(std::wstring(buf, len));
  len = (DWORD)std::size(buf);
  if (GetComputerNameW(buf, &len))
    return Utils::narrow_utf8(std::wstring(buf, len));
  return {};
}

/* void EventWriter::add_property(json &props,
                               [[maybe_unused]] const krabs::schema &schema,
                               krabs::parser &parser,
                               const krabs::property &prop) const {
  const std::wstring wname = prop.name();
  const std::string name = Utils::narrow_utf8(wname);

  try {
    switch (prop.type()) {
    case TDH_INTYPE_UNICODESTRING: {
      auto w = parser.parse<std::wstring>(wname);
      props[name] = Utils::narrow_utf8(w);
      break;
    }
    case TDH_INTYPE_ANSISTRING: {
      props[name] = parser.parse<std::string>(wname);
      break;
    }
    case TDH_INTYPE_INT8:
      props[name] = parser.parse<int8_t>(wname);
      break;
    case TDH_INTYPE_UINT8:
      props[name] = parser.parse<uint8_t>(wname);
      break;
    case TDH_INTYPE_INT16:
      props[name] = parser.parse<int16_t>(wname);
      break;
    case TDH_INTYPE_UINT16:
      props[name] = parser.parse<uint16_t>(wname);
      break;
    case TDH_INTYPE_INT32:
      props[name] = parser.parse<int32_t>(wname);
      break;
    case TDH_INTYPE_UINT32:
      props[name] = parser.parse<uint32_t>(wname);
      break;
    case TDH_INTYPE_INT64:
      props[name] = parser.parse<int64_t>(wname);
      break;
    case TDH_INTYPE_UINT64:
      props[name] = parser.parse<uint64_t>(wname);
      break;
    case TDH_INTYPE_BOOLEAN: {
      props[name] = parser.parse<bool>(wname);
      break;
    }
    case TDH_INTYPE_GUID: {
      GUID g = parser.parse<GUID>(wname);
      props[name] = guid_to_string(g);
      break;
    }
    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_HEXINT32:
    case TDH_INTYPE_HEXINT64: {
      try {
        auto v = parser.parse<uint64_t>(wname);
        std::ostringstream oss;
        oss << "0x" << std::hex << std::nouppercase << v;
        props[name] = oss.str();
      } catch (...) {
        auto v = parser.parse<uint32_t>(wname);
        std::ostringstream oss;
        oss << "0x" << std::hex << std::nouppercase << v;
        props[name] = oss.str();
      }
      break;
    }
    case TDH_INTYPE_BINARY: {
      auto bin = parser.parse<std::vector<uint8_t>>(wname);
      static const char *kHex = "0123456789abcdef"; // all hex options
      std::string hex;
      hex.reserve(2 * bin.size());
      for (auto b : bin) {
        hex.push_back(kHex[(b >> 4) & 0xF]);
        hex.push_back(kHex[b & 0xF]);
      }
      props[name] = json{{"_type", "bytes"}, {"hex", hex}};
      break;
    }
    default: {
      try {
        auto w = parser.parse<std::wstring>(wname);
        props[name] = Utils::narrow_utf8(w);
      } catch (...) {
        props[name] = "<unsupported>";
      }
      break;
    }
    }
  } catch (...) {
    props[name] = "<parse_error>";
  }
}
*/

void EventWriter::write_event_json(const EVENT_RECORD &rec,
                                   const krabs::trace_context &ctx) {
  krabs::schema schema(rec, ctx.schema_locator);

  json j;
  // time & host
  j["ts"] = iso8601_from_large_integer_timestamp(rec.EventHeader.TimeStamp);
  j["raw_ts_100ns"] = static_cast<unsigned long long>(rec.EventHeader.TimeStamp.QuadPart);
  j["host"] = host_name();

  // provider & event naming
  std::wstring providerW;
  try {
    providerW = schema.provider_name();
  } catch (...) {
  }
  j["provider"] = Utils::narrow_utf8(providerW);

  const std::wstring taskW = [&] { std::wstring t; try { t = schema.task_name(); }  catch(...) {} return t; }();
  const std::wstring opcodeW = [&] { std::wstring o; try { o = schema.opcode_name(); } catch(...) {} return o; }();
  const std::wstring eventW = Utils::ComposeEvent(schema);

  j["event"] = Utils::narrow_utf8(eventW);
  j["event_id"] = schema.event_id();
  j["category"] = Utils::InferCategory(providerW, taskW);

  // ids
  j["pid"] = Utils::NormUintOrNull(rec.EventHeader.ProcessId);
  j["tid"] = Utils::NormUintOrNull(rec.EventHeader.ThreadId);

  if (!IsEqualGUID(rec.EventHeader.ActivityId, GUID{})) {
    j["activity"] = guid_to_string(rec.EventHeader.ActivityId);
  }

  j["task_name"] = Utils::narrow_utf8(taskW);

  // raw props
  json props = json::object();
  fill_props_via_tdh(props, rec, ctx);
  j["props"] = props;

  // proc
  {
    json proc;
    Utils::SetIfFound(proc, "name", props, {"ProcessName", "ImageName", "ImageFileName"});
    Utils::SetIfFound(proc, "path", props, {"ImagePath", "ProcessPath", "FilePath", "ObjectName"});
    Utils::SetIfFound(proc, "ppid", props, {"ParentProcessId", "ParentPid", "PPID"});
    Utils::SetIfFound(proc, "bitness", props, {"Bitness"});
    Utils::SetIfFound(proc, "user_sid", props, {"UserSid", "SID"});
    Utils::SetIfFound(proc, "integrity", props, {"IntegrityLevel", "IL"});
    Utils::SetIfFound(proc, "elevated", props, {"Elevated"});
    Utils::SetIfFound(proc, "signer", props, {"Signer", "SignatureSigner", "Company"});
    Utils::SetIfFound(proc, "sig_status", props, {"SignatureStatus", "SigStatus"});
    Utils::SetIfFound(proc, "sha256", props, {"SHA256", "Sha256", "ImageHash"});

    if (!proc.contains("name") || !proc.contains("path")) {
      json fallback = Utils::BestEffortProcFromPid(rec.EventHeader.ProcessId);
      for (auto &kv : fallback.items())
        proc[kv.key()] = kv.value();
    }
    if (!proc.empty())
      j["proc"] = std::move(proc);
  }

  // projections
  if (json net = Utils::ExtractNet(props); !net.empty())
    j["net"] = std::move(net);
  if (json dns = Utils::ExtractDns(props); !dns.empty())
    j["dns"] = std::move(dns);
  if (json fil = Utils::ExtractFile(props, taskW, opcodeW); !fil.empty())
    j["file"] = std::move(fil);

  write_out(j);
}

void EventWriter::write_out(const nlohmann::json &j) {
  std::scoped_lock<std::mutex> lk(mtx_);
  if (!out_)
    return;

  if (fmt_ == WireFormat::Msgpack) {
    std::vector<std::uint8_t> buf = nlohmann::json::to_msgpack(j);
    if (length_prefixed_) {
      const std::uint32_t n = static_cast<std::uint32_t>(buf.size());
      out_.write(reinterpret_cast<const char *>(&n), sizeof(n));
    }
    out_.write(reinterpret_cast<const char *>(buf.data()),
               static_cast<std::streamsize>(buf.size()));
  } else {
    const std::string line = pretty_ ? (j.dump(2) + "\n") : (j.dump() + "\n");
    out_.write(line.data(), static_cast<std::streamsize>(line.size()));
  }
}

void EventWriter::operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
  write_event_json(rec, ctx);
}
