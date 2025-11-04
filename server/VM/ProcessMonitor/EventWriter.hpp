#pragma once
#include "pch.h"
#include <krabs.hpp>
#include <nlohmann/json.hpp>

#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

class EventWriter {
public:
  enum class WireFormat { JsonLines,
                          Msgpack };

  explicit EventWriter(std::wstring path,
                       WireFormat fmt = WireFormat::JsonLines,
                       bool pretty = false,
                       bool lengthPrefixed = true);

  void flush();
  void operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx);

  void setFormat(WireFormat f, bool lengthPrefixed = true) {
    std::scoped_lock<std::mutex> lk(m_mtx);
    m_wireFornat = f;
    m_lengthPrefixed = lengthPrefixed;
  }

private:
  void addProperty(nlohmann::json &props,
                   [[maybe_unused]] const krabs::schema &schema,
                   krabs::parser &parser,
                   const krabs::property &prop) const;
  void writeEventJson(const EVENT_RECORD &rec, const krabs::trace_context &ctx);

  void writeOut(const nlohmann::json &j);

  void fillPropsViaTdh(nlohmann::json &props,
                       const EVENT_RECORD &rec,
                       const krabs::trace_context &ctx) const;

private:
  std::mutex m_mtx;
  std::ofstream m_out;
  std::wstring m_path;
  bool m_pretty = false;

  WireFormat m_wireFornat = WireFormat::JsonLines;
  bool m_lengthPrefixed = true;
};
