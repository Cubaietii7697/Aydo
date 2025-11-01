#include "EventWriter.hpp"
#include <tdh.h>
#include <iomanip>
#include <objbase.h>
#include <sstream>

using nlohmann::json;

EventWriter::EventWriter(std::wstring path)
    : path_(std::move(path)) {
  out_.open(path_, std::ios::out | std::ios::app | std::ios::binary);
}

void EventWriter::flush() {
  std::scoped_lock<std::mutex> lk(mtx_);
  out_.flush();
}

std::string EventWriter::narrow_utf8(const std::wstring &w) {
  if (w.empty())
    return {};
  int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
  return s;
}

static inline const wchar_t *info_wstr(const TRACE_EVENT_INFO *info, ULONG offset) {
  return reinterpret_cast<const wchar_t *>(
      reinterpret_cast<const BYTE *>(info) + offset);
}

void EventWriter::fill_props_via_tdh(nlohmann::json &props,
                                     const EVENT_RECORD &rec,
                                     const krabs::trace_context &ctx) {
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
    const std::string name = narrow_utf8(wname);

    auto inType = epi.nonStructType.InType;

    try {
      switch (inType) {
      case TDH_INTYPE_UNICODESTRING: {
        auto w = parser.parse<std::wstring>(wname);
        props[name] = narrow_utf8(w);
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
        props[name] = narrow_utf8(buf);
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
          props[name] = narrow_utf8(w);
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
  return narrow_utf8(buf);
}

std::string EventWriter::iso8601_from_large_integer_timestamp(const LARGE_INTEGER &ts) {
  FILETIME ft;
  ft.dwLowDateTime = ts.LowPart;
  ft.dwHighDateTime = ts.HighPart;

  SYSTEMTIME st_utc{};
  if (!::FileTimeToSystemTime(&ft, &st_utc)) {
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

void EventWriter::add_property(json &props,
                               [[maybe_unused]] const krabs::schema &schema,
                               krabs::parser &parser,
                               const krabs::property &prop) const {
  const std::wstring wname = prop.name();
  const std::string name = narrow_utf8(wname);

  try {
    switch (prop.type()) {
    case TDH_INTYPE_UNICODESTRING: {
      auto w = parser.parse<std::wstring>(wname);
      props[name] = narrow_utf8(w);
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
        props[name] = narrow_utf8(w);
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

void EventWriter::write_event_json(const EVENT_RECORD &rec,
                                   const krabs::trace_context &ctx) {
  krabs::schema schema(rec, ctx.schema_locator);
  krabs::parser parser(schema);

  json j;
  j["ts"] = iso8601_from_large_integer_timestamp(rec.EventHeader.TimeStamp);
  j["provider"] = narrow_utf8(schema.provider_name());
  j["provider_guid"] = guid_to_string(rec.EventHeader.ProviderId);

  std::wstring ev;

  ev = schema.event_name();

  if (ev.empty()) {
    std::wstring task;
    std::wstring op;
    try {
      task = schema.task_name();
    } catch (...) {
    }
    try {
      op = schema.opcode_name();
    } catch (...) {
    }
    if (!task.empty() || !op.empty()) {
      if (!task.empty())
        ev += task;
      if (!op.empty()) {
        if (!ev.empty())
          ev += L"/";
        ev += op;
      }
    } else {
      ev = L"#";
      ev += std::to_wstring(schema.event_opcode());
    }
  }
  j["event"] = narrow_utf8(ev);

  try {
    j["task_name"] = narrow_utf8(schema.task_name());
  } catch (...) {
  }
  try {
    j["opcode_name"] = narrow_utf8(schema.opcode_name());
  } catch (...) {
  }

  j["id"] = schema.event_id();
  j["version"] = static_cast<int>(schema.event_version());
  j["level"] = static_cast<int>(rec.EventHeader.EventDescriptor.Level);
  j["opcode"] = schema.event_opcode();

  auto norm = [](ULONG v) -> json {
    return v == 0xFFFFFFFFu ? json(nullptr) : json(v);
  };
  j["pid"] = norm(rec.EventHeader.ProcessId);
  j["tid"] = norm(rec.EventHeader.ThreadId);

  if (!IsEqualGUID(rec.EventHeader.ActivityId, GUID{})) {
    j["activity"] = guid_to_string(rec.EventHeader.ActivityId);
  }

  {
    ULONGLONG kw = rec.EventHeader.EventDescriptor.Keyword;
    j["keywords"] = std::format("0x{:016X}", kw);
  }

  json props = json::object();
  fill_props_via_tdh(props, rec, ctx);
  j["props"] = std::move(props);

  const std::string line = pretty_ ? (j.dump(2) + "\n") : (j.dump() + "\n");
  std::scoped_lock<std::mutex> lk(mtx_);
  out_.write(line.data(), static_cast<std::streamsize>(line.size()));
}

void EventWriter::operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
  write_event_json(rec, ctx);
}
