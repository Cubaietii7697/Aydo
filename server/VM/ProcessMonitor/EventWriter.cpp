#include "EventWriter.hpp"
#include <tdh.h>
#include <botan/hex.h>
#include <iomanip>
#include <objbase.h>
#include <sstream>
#include "Constants.hpp"
#include "SqlRequests.hpp"
#include "Utils.hpp"

struct Mapping;

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
    OutputDebugStringA("writeToSqlite: no DB handle or JSON is not an object\n");
    return;
  }

  std::vector<std::string> columns;
  std::vector<nlohmann::json> values;

  collectColumnsAndValues(j, columns, values);

  if (columns.empty()) {
    OutputDebugStringA("writeToSqlite: no columns collected for INSERT\n");
    return;
  }

  const std::string sql = buildInsertSql(columns);

  sqlite3_stmt *stmt = nullptr;
  if (!prepareInsertStatement(sql, &stmt)) {
    OutputDebugStringA("writeToSqlite: prepareInsertStatement failed\n");
    return;
  }

  if (!bindJsonValues(stmt, values)) {
    OutputDebugStringA("writeToSqlite: bindJsonValues failed\n");
    sqlite3_finalize(stmt);
    return;
  }

  if (const int rc = sqlite3_step(stmt); rc != SQLITE_DONE) {

    std::string msg = std::format("writeToSqlite: sqlite3_step failed, rc={}",
                                  std::to_string(rc));
    if (m_db) {
      msg += ", err=";
      msg += sqlite3_errmsg(m_db);
    }
    msg += "\n";
    OutputDebugStringA(msg.c_str());
  } else {
    OutputDebugStringA("writeToSqlite: inserted one event\n");
  }

  sqlite3_finalize(stmt);
}

void EventWriter::initSqliteSchema() {
  if (!m_db) {
    return;
  }

  char *errMsg = nullptr;
  const int rc = sqlite3_exec(m_db, SqlRequstes::TABLES_CREATE, nullptr, nullptr, &errMsg);
  if (rc != SQLITE_OK) {

    std::string msg = std::format("sqlite3_exec(TABLES_CREATE) failed, rc={}",
                                  std::to_string(rc));

    if (errMsg) {
      msg += ", err=";
      msg += errMsg;
      sqlite3_free(errMsg);
    }
    msg += "\n";
    OutputDebugStringA(msg.c_str());
  }
}

bool EventWriter::bindJsonValues(sqlite3_stmt *stmt,
                                 const std::vector<nlohmann::json> &values) const {
  if (!stmt) {
    return false;
  }

  for (size_t i = 0; i < values.size(); ++i) {
    const auto &val = values[i];
    const auto idx = static_cast<int>(i + 1);

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

  if (const int rc = sqlite3_prepare_v2(m_db, sql.c_str(), -1, stmtOut, nullptr); rc != SQLITE_OK || !*stmtOut) {
    if (*stmtOut) {
      sqlite3_finalize(*stmtOut);
      *stmtOut = nullptr;
    }
    // Optional: log the error with sqlite3_errmsg(m_db).
    return false;
  }

  return true;
}

std::string EventWriter::buildInsertSql(const std::vector<std::string> &columns) const {
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
                                          std::vector<nlohmann::json> &values) const {
  columns.clear();
  values.clear();

  // Define special mappings where DB column name != JSON key
  static const std::unordered_map<std::string_view, std::string_view> specialMappings = {
      {"EventId", "event_id"},
      {"EventTime", "ts"},
      {"Computer", "host"},
      {"Provider", "provider"},
      {"Category", "category"},
      {"TaskName", "task_name"}};

  auto findInHierarchy = [&](const std::string_view key) -> const nlohmann::json * {
    // Check root
    if (auto it = j.find(key); it != j.end() && !it->is_null())
      return &it.value();

    static const std::array categories = {"props", "proc", "net", "dns", "file"};
    for (const auto &cat : categories) {
      if (auto catIt = j.find(cat); catIt != j.end() && catIt->is_object()) {
        if (auto it = catIt->find(key); it != catIt->end() && !it->is_null())
          return &it.value();
      }
    }
    return nullptr;
  };

  for (const auto &colName : SqlRequstes::TABLES) {
    // Use mapped key if it exists, otherwise use the column name itself
    auto mapIt = specialMappings.find(colName);
    std::string_view searchKey = (mapIt != specialMappings.end()) ? mapIt->second : colName;

    if (const nlohmann::json *src = findInHierarchy(searchKey)) {
      columns.push_back(colName);
      values.push_back(*src);
    }
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
    } catch (const std::exception &e) {
    }
  }
}

void EventWriter::flush() {
  std::scoped_lock<std::mutex> lk(m_mtx);

  if (m_wireFornat != WireFormat::Sqlite && m_out.is_open()) {
    m_out.flush();
  }
}

static inline const wchar_t *info_wstr(const BYTE *base,
                                       size_t baseSizeBytes,
                                       ULONG offsetBytes) {
  if (!base || offsetBytes >= baseSizeBytes) {
    return L"";
  }

  const void *p = base + offsetBytes;
  return static_cast<const wchar_t *>(p);
}

void EventWriter::fillPropsViaTdh(nlohmann::json &props,
                                  const EVENT_RECORD &rec,
                                  const krabs::trace_context &ctx) const {
  try {
    // 1. Get Event Information
    ULONG size = 0;
    ::TdhGetEventInformation(const_cast<EVENT_RECORD *>(&rec), 0, nullptr, nullptr, &size);
    if (size == 0)
      return;

    std::vector<BYTE> buf(size);
    auto *info = reinterpret_cast<TRACE_EVENT_INFO *>(buf.data());
    if (TdhGetEventInformation(const_cast<EVENT_RECORD *>(&rec), 0, nullptr, info, &size) != ERROR_SUCCESS)
      return;

    krabs::schema schema(rec, ctx.schema_locator);
    krabs::parser parser(schema);

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
      auto const &epi = info->EventPropertyInfoArray[i];
      const auto *wname = reinterpret_cast<const wchar_t *>(buf.data() + epi.NameOffset);
      const std::string name = Utils::narrow_utf8(wname);

      if (SqlRequstes::SKIP_FIELDS.contains(name)) {
        props[name] = "<skipped>";
        continue;
      }

      try {
        switch (epi.nonStructType.InType) {
        // Strings
        case TDH_INTYPE_UNICODESTRING:
          props[name] = Utils::narrow_utf8(parser.parse<std::wstring>(wname));
          break;
        case TDH_INTYPE_ANSISTRING:
          props[name] = parser.parse<std::string>(wname);
          break;
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
        case TDH_INTYPE_BOOLEAN:
          props[name] = parser.parse<bool>(wname);
          break;

        // Hex / Pointers
        case TDH_INTYPE_POINTER:
        case TDH_INTYPE_HEXINT32:
        case TDH_INTYPE_HEXINT64: {
          uint64_t val = (epi.length == 4) ? parser.parse<uint32_t>(wname) : parser.parse<uint64_t>(wname);
          props[name] = (std::ostringstream() << "0x" << std::hex << std::nouppercase << val).str();
          break;
        }

        // GUIDs
        case TDH_INTYPE_GUID: {
          GUID g = parser.parse<GUID>(wname);
          wchar_t bufGuid[Constants::GUID_SIZE];
          props[name] = StringFromGUID2(g, bufGuid, Constants::GUID_SIZE) ? Utils::narrow_utf8(bufGuid) : "<unsupported>";
          break;
        }

        default: // Fallback
          props[name] = Utils::narrow_utf8(parser.parse<std::wstring>(wname));
          break;
        }
      } catch (...) {
        props[name] = "<parse_error>";
      }
    }
  } catch (const std::exception &e) {
    OutputDebugStringA((std::string("krabs error: ") + e.what() + "\n").c_str());
  }
}

void EventWriter::writeEventJson(const EVENT_RECORD &rec,
                                 const krabs::trace_context &ctx) {
  nlohmann::json j;

  try {
    //
    // 1. Basic header fields (no krabs involved)
    //
    j["ts"] = Utils::iso8601FromLargeIntegerTimestamp(rec.EventHeader.TimeStamp);
    j["raw_ts_100ns"] =
        static_cast<unsigned long long>(rec.EventHeader.TimeStamp.QuadPart);
    j["host"] = Utils::getHostName();

#if defined(EVENT_HEADER_EXTENDED_DATA_COUNT)
    j["EventRecordId"] =
        static_cast<unsigned long long>(rec.EventHeader.EventRecordId);
#else
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
    j["Keywords"] = rec.EventHeader.EventDescriptor.Keyword;

    // Fallback EventId straight from the header (works even without krabs schema)
    j["event_id"] =
        static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Id);

    j["pid"] = Utils::normUintOrNull(rec.EventHeader.ProcessId);
    j["tid"] = Utils::normUintOrNull(rec.EventHeader.ThreadId);

    if (!IsEqualGUID(rec.EventHeader.ActivityId, GUID{})) {
      j["activity"] = Utils::guidToString(rec.EventHeader.ActivityId);
    }

    //
    // 2. Provider / task / opcode names via krabs::schema (best-effort)
    //
    std::wstring providerW;
    std::wstring taskW;
    std::wstring opcodeW;
    std::wstring eventW;

    try {
      krabs::schema schema(rec, ctx.schema_locator);

      providerW = [&] {
        std::wstring p;
        try {
          p = schema.provider_name();
        } catch (const std::exception &e) {
        }
        return p;
      }();

      taskW = [&] {
        std::wstring t;
        try {
          t = schema.task_name();
        } catch (const std::exception &e) {
        }
        return t;
      }();

      opcodeW = [&] {
        std::wstring o;
        try {
          o = schema.opcode_name();
        } catch (const std::exception &e) {
        }
        return o;
      }();

      eventW = Utils::composeEvent(schema);
      j["event"] = Utils::narrow_utf8(eventW);
      // Prefer schema’s event_id if available
      j["event_id"] = schema.event_id();

      j["category"] = Utils::inferCategory(providerW, taskW);
    } catch (const krabs::could_not_find_schema &) {
      OutputDebugStringA("krabs: could_not_find_schema in writeEventJson (names only)\n");
      // keep header-based event_id/category defaults
    } catch (const krabs::type_mismatch_assert &) {
      OutputDebugStringA("krabs: type_mismatch_assert in writeEventJson (names only)\n");
    } catch (const std::exception &e) {
      OutputDebugStringA("krabs: unknown exception in writeEventJson (names only)\n");
    }

    j["provider"] = Utils::narrow_utf8(providerW);
    j["task_name"] = Utils::narrow_utf8(taskW);

    //
    // 3. Properties via TDH + krabs parser (already has its own try/catch)
    //
    nlohmann::json props = nlohmann::json::object();
    fillPropsViaTdh(props, rec, ctx);
    j["props"] = props;

    //
    // 4. Projections: proc / net / dns / file
    //
    nlohmann::json proc;
    Utils::setIfFound(proc, "name", props,
                      {"ProcessName", "ImageName", "ImageFileName"});
    Utils::setIfFound(proc, "path", props,
                      {"ImagePath", "ProcessPath", "FilePath", "ObjectName"});
    Utils::setIfFound(proc, "ppid", props,
                      {"ParentProcessId", "ParentPid", "PPID"});
    Utils::setIfFound(proc, "bitness", props, {"Bitness"});
    Utils::setIfFound(proc, "user_sid", props, {"UserSid", "SID"});
    Utils::setIfFound(proc, "integrity", props, {"IntegrityLevel", "IL"});
    Utils::setIfFound(proc, "elevated", props, {"Elevated"});
    Utils::setIfFound(proc, "signer", props,
                      {"Signer", "SignatureSigner", "Company"});
    Utils::setIfFound(proc, "sig_status", props,
                      {"SignatureStatus", "SigStatus"});
    Utils::setIfFound(proc, "sha256", props,
                      {"SHA256", "Sha256", "ImageHash"});

    if (!proc.contains("name") || !proc.contains("path")) {
      nlohmann::json fallback =
          Utils::bestEffortProcFromPid(rec.EventHeader.ProcessId);
      for (auto &kv : fallback.items()) {
        proc[kv.key()] = kv.value();
      }
    }

    if (!proc.empty()) {
      j["proc"] = std::move(proc);
    }

    if (nlohmann::json net = Utils::extractNet(props); !net.empty()) {
      j["net"] = std::move(net);
    }

    if (nlohmann::json dns = Utils::extractDns(props); !dns.empty()) {
      j["dns"] = std::move(dns);
    }

    if (nlohmann::json fil = Utils::extractFile(props, taskW, opcodeW);
        !fil.empty()) {
      j["file"] = std::move(fil);
    }
    enrichSigmaFields(j);
  } catch (const std::exception &e) {
    OutputDebugStringA("krabs: fatal exception in writeEventJson envelope\n");
  }

  try {
    writeOut(j);
  } catch (const std::exception &e) {
    OutputDebugStringA("writeEventJson: exception in writeOut\n");
  }
}

void EventWriter::writeOut(const nlohmann::json &j) {
  std::scoped_lock<std::mutex> lk(m_mtx);

  if (m_wireFornat == WireFormat::Sqlite) {
    if (!m_db) {
      if (sqlite3_open16(m_path.c_str(), &m_db) != SQLITE_OK) {
        OutputDebugStringA("writeOut: sqlite3_open16 failed in Sqlite mode\n");
        sqlite3_close(m_db);
        m_db = nullptr;
        return;
      }
      initSqliteSchema();
    }

    writeToSqlite(j);
    return;
  }

  // File-based formats (JsonLines / Msgpack).
  if (!m_out.is_open()) {
    m_out.open(m_path, std::ios::out | std::ios::app | std::ios::binary);
  }

  if (!m_out) {
    OutputDebugStringA("writeOut: failed to open output file stream\n");
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
  } else { // JsonLines
    const std::string line =
        m_pretty ? (j.dump(Constants::JSON_INDENT_WIDTH) + "\n")
                 : (j.dump() + "\n");
    m_out.write(line.data(), static_cast<std::streamsize>(line.size()));
  }
}

void EventWriter::enrichSigmaFields(nlohmann::json &j) const {
  // Use a fixed-size array to avoid heap allocation for every event
  const nlohmann::json *searchScope[6];
  size_t scopeSize = 0;
  searchScope[scopeSize++] = &j;

  static const std::array categories = {"props", "proc", "net", "dns", "file"};
  for (const auto &cat : categories) {
    if (auto it = j.find(cat); it != j.end() && it->is_object())
      searchScope[scopeSize++] = &(*it);
  }

  auto lookup = [&](const std::vector<std::string> &sources) -> const nlohmann::json * {
    for (const auto &key : sources) {
      for (size_t i = 0; i < scopeSize; ++i) {
        if (auto it = searchScope[i]->find(key); it != searchScope[i]->end() && !it->is_null())
          return &it.value();
      }
    }
    return nullptr;
  };

  // Transformation Helpers
  auto process = [&](const std::string &dst, const std::vector<std::string> &sources, bool lower = false) {
    if (j.contains(dst) && !j[dst].is_null())
      return;

    if (const auto *v = lookup(sources)) {
      if (lower && v->is_string()) {
        j[dst] = Utils::toLower(v->get_ref<const std::string &>());
      } else {
        j[dst] = *v;
      }
    }
  };

  for (const auto &rule : Constants::RULES) {
    process(rule.dst, rule.src, rule.lower);
  }

  for (auto [a, b] : {std::pair{"CommandLine", "Commandline"}, {"LocalPort", "localport"}, {"ObjectName", "object_name"}, {"State", "STATE"}, {"ObjectClass", "ObjectClas"}}) {
    process(a, {a, b});
    process(b, {a, b});
  }

  if (!j.contains("Payload") || j["Payload"].is_null()) {
    j["Payload"] = j.dump();
  }
}

void EventWriter::operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
  writeEventJson(rec, ctx);
}
