#include "SignaturesDatabase.hpp"

#include <fstream>

#include "Errors.hpp"
#include "jsonTypes.hpp"

SignaturesDatabase::SignaturesDatabase(std::string filePath)
    : m_filePath(std::move(filePath)) {
}

std::vector<std::string> SignaturesDatabase::getSignatures(SignatureType type) const {
  std::vector<std::string> signatures;

  if (type == SignatureType::Simple) {
    for (const auto &entry : m_database.at("simple")) {
      signatures.push_back(entry.signature);
    }
  } else {
    for (const auto &entry : m_database.at("complex")) {
      signatures.push_back(entry.signature);
    }
  }

  return signatures;
}

std::string SignaturesDatabase::getSignatureName(const std::string &signature) const {
  for (const auto &entry : m_database.at("simple")) {
    if (entry.signature == signature) {
      return entry.name;
    }
  }

  for (const auto &entry : m_database.at("complex")) {
    if (entry.signature == signature) {
      return entry.name;
    }
  }

  throw Errors::SignatureNotFoundException();
}

void SignaturesDatabase::load() {
  std::ifstream file(m_filePath);
  if (!file.is_open()) {
    throw Errors::FailedToOpenFileException();
  }

  m_database.clear();

  std::string content((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
  nlohmann::json json = nlohmann::json::parse(content);

  jsonTypes::SignatureDatabaseFormat format = json.get<jsonTypes::SignatureDatabaseFormat>();

  m_database["simple"] = format.simple;
  m_database["complex"] = format.complex;
}
