#pragma once

#include <string>
#include <unordered_map>

#include "jsonTypes.hpp"

enum class SignatureType {
  Simple,
  Complex,
};

class SignaturesDatabase {
private:
  std::string m_filePath;
  std::unordered_map<std::string, std::vector<jsonTypes::SignatureEntry>> m_database;

public:
  explicit SignaturesDatabase(std::string filePath);
  ~SignaturesDatabase() = default;

  [[nodiscard]] std::vector<std::string> getSignatures(SignatureType type) const;

  [[nodiscard]] std::string getSignatureName(const std::string &signature) const;

  void load();
};
