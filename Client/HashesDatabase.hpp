#pragma once

#include <optional>
#include <string>

class HashesDatabase {
private:
  std::string m_filePath;
  
public:
  explicit HashesDatabase(std::string filePath);
  ~HashesDatabase() = default;

  [[nodiscard]] std::optional<std::string> getHashName(const std::string &hash) const;
};
