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
  explicit EventWriter(std::wstring path);

  void operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx);

  void flush();

  void set_pretty(bool enable) { pretty_ = enable; }

private:
  void write_event_json(const EVENT_RECORD &rec, const krabs::trace_context &ctx);
  static void fill_props_via_tdh(nlohmann::json &props,
                                 const EVENT_RECORD &rec,
                                 const krabs::trace_context &ctx);
  static std::string narrow_utf8(const std::wstring &w);
  static std::string guid_to_string(const GUID &g);
  static std::string iso8601_from_large_integer_timestamp(const LARGE_INTEGER &ts);

  void add_property(nlohmann::json &props,
                    const krabs::schema &schema,
                    krabs::parser &parser,
                    const krabs::property &prop) const;

private:
  std::wstring path_;
  std::ofstream out_;
  std::mutex mtx_;
  bool pretty_ = false;
};
