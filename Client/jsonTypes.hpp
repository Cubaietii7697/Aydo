#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace jsonTypes {

struct SignatureEntry {
  std::string name;
  std::string signature;
};

struct SignatureDatabaseFormat {
  std::vector<SignatureEntry> simple;
  std::vector<SignatureEntry> complex;
};

inline void from_json(const nlohmann::json &j, SignatureEntry &entry) {
  j.at("signature").get_to(entry.signature);
  j.at("name").get_to(entry.name);
}

inline void to_json(nlohmann::json &j, const SignatureEntry &entry) {
  j = nlohmann::json{{"signature", entry.signature}, {"name", entry.name}};
}

inline void from_json(const nlohmann::json &j, SignatureDatabaseFormat &format) {
  format.simple.clear();
  format.complex.clear();

  // Handle "simple" section which can be either an array of objects or a map of signature->name
  if (j.contains("simple")) {
    const auto &simple = j.at("simple");
    if (simple.is_array()) {
      simple.get_to(format.simple);
    } else if (simple.is_object()) {
      for (auto it = simple.begin(); it != simple.end(); ++it) {
        SignatureEntry e;
        e.signature = it.key();
        // tolerate non-string values by converting to string if needed
        if (it.value().is_string()) {
          e.name = it.value().get<std::string>();
        } else {
          e.name = it.value().dump();
        }
        format.simple.push_back(std::move(e));
      }
    }
  }

  // Handle "complex" section similarly
  if (j.contains("complex")) {
    const auto &complex = j.at("complex");
    if (complex.is_array()) {
      complex.get_to(format.complex);
    } else if (complex.is_object()) {
      for (auto it = complex.begin(); it != complex.end(); ++it) {
        SignatureEntry e;
        e.signature = it.key();
        if (it.value().is_string()) {
          e.name = it.value().get<std::string>();
        } else {
          e.name = it.value().dump();
        }
        format.complex.push_back(std::move(e));
      }
    }
  }
}

inline void to_json(nlohmann::json &j, const SignatureDatabaseFormat &format) {
  j = nlohmann::json{{"simple", format.simple}, {"complex", format.complex}};
}

} // namespace jsonTypes
