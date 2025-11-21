#include "EventWriter.hpp"
#include <tdh.h>
#include <botan/hex.h>
#include <iomanip>
#include <objbase.h>
#include <sstream>
#include "Constants.hpp"
#include "SqlRequests.hpp"
#include "Utils.hpp"

EventWriter::EventWriter(std::wstring path,
                         WireFormat fmt,
                         bool pretty,
                         bool length_prefixed)
    : m_path(std::move(path))
    , m_pretty(pretty)
    , m_wireFornat(fmt)
    , m_db(nullptr)
    , m_lengthPrefixed(length_prefixed) {

  std::scoped_lock<std::mutex> lk(m_mtx);

  if (m_wireFornat == WireFormat::Sqlite) {
    if (sqlite3_open16(m_path.c_str(), &m_db) != SQLITE_OK) {
      sqlite3_close(m_db);
      m_db = nullptr;
    }
    initSqliteSchema();
  } else {
    m_out.open(m_path, std::ios::out | std::ios::app | std::ios::binary);
  }
}

void EventWriter::writeToSqlite(const nlohmann::json &j) {
  if (!m_db || !j.is_object()) {
    return; // We expect a JSON object with key/value pairs.
  }

  std::vector<std::string> columns;
  std::vector<nlohmann::json> values;

  collectColumnsAndValues(j, columns, values);

  if (columns.empty()) {
    // Nothing meaningful to insert.
    return;
  }

  const std::string sql = buildInsertSql(columns);

  sqlite3_stmt *stmt = nullptr;
  if (!prepareInsertStatement(sql, &stmt)) {
    return;
  }

  if (!bindJsonValues(stmt, values)) {
    sqlite3_finalize(stmt);
    return;
  }

  const int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

void EventWriter::initSqliteSchema() {
  if (!m_db) {
    return;
  }

  char *errMsg = nullptr;
  int rc = sqlite3_exec(m_db, SqlRequstes::TABLES_CREATE, nullptr, nullptr, &errMsg);
  if (rc != SQLITE_OK) {
    if (errMsg) {
      sqlite3_free(errMsg);
    }
  }
}

bool EventWriter::bindJsonValues(sqlite3_stmt *stmt,
                                 const std::vector<nlohmann::json> &values) {
  if (!stmt) {
    return false;
  }

  for (size_t i = 0; i < values.size(); ++i) {
    const auto &val = values[i];
    const int idx = static_cast<int>(i + 1);

    int rc = SQLITE_OK;

    if (val.is_number_integer()) {
      rc = sqlite3_bind_int64(stmt, idx, val.get<long long>());
    } else if (val.is_number_unsigned()) {
      rc = sqlite3_bind_int64(
          stmt, idx,
          static_cast<sqlite3_int64>(val.get<unsigned long long>()));
    } else if (val.is_number_float()) {
      rc = sqlite3_bind_double(stmt, idx, val.get<double>());
    } else if (val.is_boolean()) {
      rc = sqlite3_bind_int(stmt, idx, val.get<bool>() ? 1 : 0);
    } else if (val.is_string()) {
      const std::string &s = val.get_ref<const std::string &>();
      rc = sqlite3_bind_text(stmt, idx, s.c_str(), -1, SQLITE_TRANSIENT);
    } else {
      // Fallback: store as JSON text.
      const std::string s = val.dump();
      rc = sqlite3_bind_text(stmt, idx, s.c_str(), -1, SQLITE_TRANSIENT);
    }

    if (rc != SQLITE_OK) {
      // Optional: log sqlite3_errmsg(m_db).
      return false;
    }
  }

  return true;
}

bool EventWriter::prepareInsertStatement(const std::string &sql, sqlite3_stmt **stmtOut) {
  if (!m_db || !stmtOut) {
    return false;
  }

  *stmtOut = nullptr;

  const int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, stmtOut, nullptr);
  if (rc != SQLITE_OK || !*stmtOut) {
    if (*stmtOut) {
      sqlite3_finalize(*stmtOut);
      *stmtOut = nullptr;
    }
    // Optional: log the error with sqlite3_errmsg(m_db).
    return false;
  }

  return true;
}

std::string EventWriter::buildInsertSql(const std::vector<std::string> &columns) {
  std::ostringstream sql;

  sql << "INSERT INTO Events(";
  for (size_t i = 0; i < columns.size(); ++i) {
    if (i > 0) {
      sql << ",";
    }
    // Quote identifiers in case some are reserved words (e.g. State).
    sql << "\"" << columns[i] << "\"";
  }

  sql << ") VALUES(";
  for (size_t i = 0; i < columns.size(); ++i) {
    if (i > 0) {
      sql << ",";
    }
    sql << "?";
  }
  sql << ");";

  return sql.str();
}

void EventWriter::collectColumnsAndValues(const nlohmann::json &j,
                                          std::vector<std::string> &columns,
                                          std::vector<nlohmann::json> &values) {
  columns.clear();
  values.clear();

  auto addIfMatch = [&](const std::string &colName, const nlohmann::json &val) {
    if (!SqlRequstes::TABLES.contains(colName) || val.is_null()) {
      return;
    }
    // avoid duplicate column names
    if (std::find(columns.begin(), columns.end(), colName) != columns.end()) {
      return;
    }
    columns.push_back(colName);
    values.push_back(val);
  };

  // 1. map top-level metadata fields to schema column names
  if (j.contains("event_id")) {
    addIfMatch("EventId", j["event_id"]);
  }
  if (j.contains("ts")) {
    addIfMatch("EventTime", j["ts"]);
  }
  if (j.contains("host")) {
    addIfMatch("Computer", j["host"]);
  }
  if (j.contains("provider")) {
    addIfMatch("Provider", j["provider"]);
  }

  // helper to walk nested json objects
  auto addFromObject = [&](const nlohmann::json &obj) {
    if (!obj.is_object()) {
      return;
    }
    for (auto it = obj.begin(); it != obj.end(); ++it) {
      addIfMatch(it.key(), it.value());
    }
  };

  // 2. walk root in case you ever put schema fields there directly
  addFromObject(j);

  // 3. walk projections where the real ETW fields live
  if (j.contains("props")) {
    addFromObject(j["props"]);
  }
  if (j.contains("proc")) {
    addFromObject(j["proc"]);
  }
  if (j.contains("net")) {
    addFromObject(j["net"]);
  }
  if (j.contains("dns")) {
    addFromObject(j["dns"]);
  }
  if (j.contains("file")) {
    addFromObject(j["file"]);
  }
}

EventWriter::~EventWriter() {
  std::scoped_lock<std::mutex> lk(m_mtx);

  if (m_db) {
    sqlite3_close(m_db);
    m_db = nullptr;
  }

  if (m_out.is_open()) {
    try {
      m_out.flush();
      m_out.close();
    } catch (...) {
    }
  }
}

void EventWriter::flush() {
  std::scoped_lock<std::mutex> lk(m_mtx);

  if (m_wireFornat != WireFormat::Sqlite && m_out.is_open()) {
    m_out.flush();
  }
}

static inline const wchar_t *info_wstr(const TRACE_EVENT_INFO *info, ULONG offset) {
  return reinterpret_cast<const wchar_t *>(
      reinterpret_cast<const BYTE *>(info) + offset);
}

void EventWriter::fillPropsViaTdh(nlohmann::json &props,
                                  const EVENT_RECORD &rec,
                                  const krabs::trace_context &ctx) const {
  ULONG size = 0;
  auto status = ::TdhGetEventInformation(const_cast<EVENT_RECORD *>(&rec),
                                         0, nullptr, nullptr, &size);
  if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
    return;
  }

  std::vector<BYTE> buf(size);
  auto info = reinterpret_cast<TRACE_EVENT_INFO *>(buf.data());
  status = TdhGetEventInformation(const_cast<EVENT_RECORD *>(&rec),
                                  0, nullptr, info, &size);
  if (status != ERROR_SUCCESS) {
    return;
  }

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
        wchar_t buf[Constants::GUID_SIZE];
        ::StringFromGUID2(g, buf, Constants::GUID_SIZE);
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

void EventWriter::writeEventJson(const EVENT_RECORD &rec,
                                 const krabs::trace_context &ctx) {
  krabs::schema schema(rec, ctx.schema_locator);

  nlohmann::json j;
  // time & host
  j["ts"] = Utils::iso8601FromLargeIntegerTimestamp(rec.EventHeader.TimeStamp);
  j["raw_ts_100ns"] = static_cast<unsigned long long>(rec.EventHeader.TimeStamp.QuadPart);
  j["host"] = Utils::getHostName();

  // provider & event naming
  std::wstring providerW;
  try {
    providerW = schema.provider_name();
  } catch (...) {
  }

  j["provider"] = Utils::narrow_utf8(providerW);

  const std::wstring taskW = [&] { std::wstring t; try { t = schema.task_name(); }  catch(...) {} return t; }();
  const std::wstring opcodeW = [&] { std::wstring o; try { o = schema.opcode_name(); } catch(...) {} return o; }();
  const std::wstring eventW = Utils::composeEvent(schema);

  j["event"] = Utils::narrow_utf8(eventW);
  j["event_id"] = schema.event_id();
  j["category"] = Utils::inferCategory(providerW, taskW);

#if defined(EVENT_HEADER_EXTENDED_DATA_COUNT) // defined in newer SDKs
  j["EventRecordId"] =
      static_cast<unsigned long long>(rec.EventHeader.EventRecordId);
#else
  // Older Windows SDK: no EventRecordId in EVENT_HEADER
  j["EventRecordId"] = 0;
#endif
  j["Channel"] =
      static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Channel);
  j["Level"] =
      static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Level);
  j["Task"] =
      static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Task);
  j["Opcode"] =
      static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Opcode);
  j["Keywords"] =
      rec.EventHeader.EventDescriptor.Keyword;

  // ids
  j["pid"] = Utils::normUintOrNull(rec.EventHeader.ProcessId);
  j["tid"] = Utils::normUintOrNull(rec.EventHeader.ThreadId);

  if (!IsEqualGUID(rec.EventHeader.ActivityId, GUID{})) {
    j["activity"] = Utils::guidToString(rec.EventHeader.ActivityId);
  }

  j["task_name"] = Utils::narrow_utf8(taskW);

  // raw props
  nlohmann::json props = nlohmann::json::object();
  fillPropsViaTdh(props, rec, ctx);
  j["props"] = props;

  // proc
  nlohmann::json proc;
  Utils::setIfFound(proc, "name", props, {"ProcessName", "ImageName", "ImageFileName"});
  Utils::setIfFound(proc, "path", props, {"ImagePath", "ProcessPath", "FilePath", "ObjectName"});
  Utils::setIfFound(proc, "ppid", props, {"ParentProcessId", "ParentPid", "PPID"});
  Utils::setIfFound(proc, "bitness", props, {"Bitness"});
  Utils::setIfFound(proc, "user_sid", props, {"UserSid", "SID"});
  Utils::setIfFound(proc, "integrity", props, {"IntegrityLevel", "IL"});
  Utils::setIfFound(proc, "elevated", props, {"Elevated"});
  Utils::setIfFound(proc, "signer", props, {"Signer", "SignatureSigner", "Company"});
  Utils::setIfFound(proc, "sig_status", props, {"SignatureStatus", "SigStatus"});
  Utils::setIfFound(proc, "sha256", props, {"SHA256", "Sha256", "ImageHash"});

  if (!proc.contains("name") || !proc.contains("path")) {
    nlohmann::json fallback = Utils::bestEffortProcFromPid(rec.EventHeader.ProcessId);
    for (auto &kv : fallback.items()) {
      proc[kv.key()] = kv.value();
    }
  }
  if (!proc.empty()) {
    j["proc"] = std::move(proc);
  }

  // projections
  if (nlohmann::json net = Utils::extractNet(props); !net.empty()) {
    j["net"] = std::move(net);
  }

  if (nlohmann::json dns = Utils::extractDns(props); !dns.empty()) {
    j["dns"] = std::move(dns);
  }

  if (nlohmann::json fil = Utils::extractFile(props, taskW, opcodeW); !fil.empty()) {
    j["file"] = std::move(fil);
  }
  enrichSigmaFields(j);

  writeOut(j);
}

void EventWriter::writeOut(const nlohmann::json &j) {
  std::scoped_lock<std::mutex> lk(m_mtx);

  if (m_wireFornat == WireFormat::Sqlite) {
    if (!m_db) {
      return; // DB failed to open
    }
    writeToSqlite(j);
    return;
  }
  if (!m_out) {
    return;
  }
  if (m_wireFornat == WireFormat::Msgpack) {
    std::vector<std::uint8_t> buf = nlohmann::json::to_msgpack(j);
    if (m_lengthPrefixed) {
      const auto n = static_cast<std::uint32_t>(buf.size());
      m_out.write(reinterpret_cast<const char *>(&n), sizeof(n));
    }
    m_out.write(reinterpret_cast<const char *>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
  } else {

    const std::string line = m_pretty ? (j.dump(Constants::JSON_INDENT_WIDTH) + "\n") : (j.dump() + "\n");
    m_out.write(line.data(), static_cast<std::streamsize>(line.size()));
  }
}

void EventWriter::enrichSigmaFields(nlohmann::json &j) {
  const nlohmann::json emptyObj = nlohmann::json::object();

  const nlohmann::json &props =
      (j.contains("props") && j["props"].is_object()) ? j["props"] : emptyObj;
  const nlohmann::json &proc =
      (j.contains("proc") && j["proc"].is_object()) ? j["proc"] : emptyObj;
  const nlohmann::json &net =
      (j.contains("net") && j["net"].is_object()) ? j["net"] : emptyObj;
  const nlohmann::json &dns =
      (j.contains("dns") && j["dns"].is_object()) ? j["dns"] : emptyObj;
  const nlohmann::json &file =
      (j.contains("file") && j["file"].is_object()) ? j["file"] : emptyObj;

  // return the first non-null value we find.
  auto lookup = [&](const std::vector<std::string> &keys) -> const nlohmann::json * {
    for (const auto &k : keys) {
      if (const auto *v = Utils::getIfPresent(j, k))
        return v;
      if (const auto *v = Utils::getIfPresent(props, k))
        return v;
      if (const auto *v = Utils::getIfPresent(proc, k))
        return v;
      if (const auto *v = Utils::getIfPresent(net, k))
        return v;
      if (const auto *v = Utils::getIfPresent(dns, k))
        return v;
      if (const auto *v = Utils::getIfPresent(file, k))
        return v;
    }
    return nullptr;
  };

  // Copy a value from any of the given source keys into 'dst',
  // but only if 'dst' is not already set in 'j'.
  auto ensureCopy = [&](const std::string &dst,
                        const std::vector<std::string> &sources) {
    if (j.contains(dst) && !j[dst].is_null()) {
      return;
    }
    if (const nlohmann::json *v = lookup(sources)) {
      j[dst] = *v;
    }
  };

  // Same as ensureCopy, but lower-case the string value.
  // If the source is not a string, do nothing.
  auto ensureLowered = [&](const std::string &dst,
                           const std::vector<std::string> &sources) {
    if (j.contains(dst) && !j[dst].is_null()) {
      return; // destination already has a value
    }
    if (const nlohmann::json *v = lookup(sources)) {
      if (v->is_string()) {
        std::string s = v->get<std::string>();
        j[dst] = Utils::toLower(s);
      }
    }
  };

  // if either side has a value, copy it to the other side.
  auto ensureSyncedPair = [&](const std::string &a, const std::string &b) {
    ensureCopy(a, {a, b});
    ensureCopy(b, {a, b});
  };

  ensureCopy("Computer", {"Computer", "host"});
  ensureSyncedPair("CommandLine", "Commandline");
  ensureSyncedPair("LocalPort", "localport");
  ensureSyncedPair("ObjectName", "object_name");
  ensureSyncedPair("State", "STATE");
  ensureSyncedPair("ObjectClass", "ObjectClas");

  ensureLowered(
      "domain_in_lowercase_xxx",
      {"domain_in_lowercase_xxx",
       "TargetDomainName",
       "TargetServerName",
       "DomainName"});
  ensureLowered(
      "param1_lower",
      {"param1_lower",
       "Param1",
       "param1"});
}

void EventWriter::operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
  writeEventJson(rec, ctx);
}
