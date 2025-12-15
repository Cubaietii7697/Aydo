#pragma once
#include "pch.h"
#include <krabs.hpp>
#include <nlohmann/json.hpp>

#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include <sqlite3.h>

class EventWriter {
public:
  enum class WireFormat { JsonLines,
                          Msgpack,
                          Sqlite };

  explicit EventWriter(std::wstring path,
                       WireFormat fmt = WireFormat::Sqlite,
                       bool pretty = false,
                       bool lengthPrefixed = true);
  ~EventWriter();

  void flush();
  void operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx);

  void setFormat(WireFormat f, bool lengthPrefixed = true) {
    std::scoped_lock<std::mutex> lk(m_mtx);
    m_wireFornat = f;
    m_lengthPrefixed = lengthPrefixed;
  }

private:
  void writeEventJson(const EVENT_RECORD &rec, const krabs::trace_context &ctx);
  void collectColumnsAndValues(const nlohmann::json &j,
                               std::vector<std::string> &columns,
                               std::vector<nlohmann::json> &values);
  void writeToSqlite(const nlohmann::json &j);
  void initSqliteSchema();
  void writeOut(const nlohmann::json &j);

  void fillPropsViaTdh(nlohmann::json &props,
                       const EVENT_RECORD &rec,
                       const krabs::trace_context &ctx) const;
  std::string buildInsertSql(const std::vector<std::string> &columns);

  bool prepareInsertStatement(const std::string &sql, sqlite3_stmt **stmtOut);

  bool bindJsonValues(sqlite3_stmt *stmt,
                      const std::vector<nlohmann::json> &values);
  void enrichSigmaFields(nlohmann::json &j);

private:
  std::mutex m_mtx;
  std::ofstream m_out;
  std::wstring m_path;
  bool m_pretty = false;

  WireFormat m_wireFornat = WireFormat::Sqlite;
  sqlite3 *m_db = nullptr;

  bool m_lengthPrefixed = true;
};
