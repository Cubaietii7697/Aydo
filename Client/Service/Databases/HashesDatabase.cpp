// Suppress C++17 deprecation warnings for codecvt/wstring_convert used by sqlite_orm
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "HashesDatabase.hpp"

#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <sqlite_orm/sqlite_orm.h>
#include <string>
#include <utility>

#include "../Errors.hpp"

namespace {
struct FileHash {
  std::string hash;
  std::string name;
};

inline auto makeStorage(const std::string &dbPath) {
  using namespace sqlite_orm;
  return make_storage(
      dbPath,
      make_table("file_hashes",
                 make_column("hash", &FileHash::hash, primary_key()),
                 make_column("name", &FileHash::name)));
}

using Storage = decltype(makeStorage(std::string{}));

Storage &storageFor(const std::string &dbPath) {
  static std::mutex mtx;
  static std::unique_ptr<Storage> storage;
  std::lock_guard<std::mutex> lock(mtx);

  if (!storage) {
    storage = std::make_unique<Storage>(makeStorage(dbPath));
  }

  return *storage;
}

} // namespace

HashesDatabase::HashesDatabase(std::string filePath)
    : m_filePath(std::move(filePath)) {
  storageFor(m_filePath); // create the storage
}

std::optional<std::string> HashesDatabase::getHashName(const std::string &hash) const {
  if (hash.empty()) {
    return std::nullopt;
  }
  if (!std::filesystem::exists(m_filePath)) {
    return std::nullopt;
  }

  try {
    auto &storage = storageFor(m_filePath);

    if (auto rec = storage.get_pointer<FileHash>(hash)) {
      return rec->name;
    }
  } catch (const std::exception &) {
    throw Errors::FailedToGetHashNameException();
  }

  return std::nullopt;
}
