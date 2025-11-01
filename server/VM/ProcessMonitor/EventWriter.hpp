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
                       bool length_prefixed = true);

  void flush();
  void operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx);

  void set_format(WireFormat f, bool length_prefixed = true) {
    std::scoped_lock<std::mutex> lk(mtx_);
    fmt_ = f;
    length_prefixed_ = length_prefixed;
  }

  static std::string guid_to_string(const GUID &g);

private:
  void write_event_json(const EVENT_RECORD &rec, const krabs::trace_context &ctx);

  void write_out(const nlohmann::json &j);

  void fill_props_via_tdh(nlohmann::json &props,
                          const EVENT_RECORD &rec,
                          const krabs::trace_context &ctx) const;

  static std::string iso8601_from_large_integer_timestamp(const LARGE_INTEGER &ts);
  static unsigned long long ts100ns_from_large_integer(const LARGE_INTEGER &ts);
  static std::string host_name();

private:
  std::mutex mtx_;
  std::ofstream out_;
  std::wstring path_;
  bool pretty_ = false;

  WireFormat fmt_ = WireFormat::JsonLines;
  bool length_prefixed_ = true;
};
