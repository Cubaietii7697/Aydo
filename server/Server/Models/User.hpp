#pragma once

#include <optional>
#include <trantor/utils/Date.h>
#include <drogon/orm/Result.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/CoroMapper.h>
#include <drogon/orm/Mapper.h>

namespace Models {
class User {
private:
  std::string m_id;
  std::string m_email;
  std::string m_nickname;
  std::string m_passwordHash;
  trantor::Date m_createdAt;
  trantor::Date m_updatedAt;

public:
  User() = default;
  explicit User(const drogon::orm::Row &row);

  static std::optional<User> getByEmail(
      const drogon::orm::DbClientPtr &dbClient, const std::string &email);

  static std::optional<User> getById(
      const drogon::orm::DbClientPtr &dbClient, const std::string &id);

  static void create(const drogon::orm::DbClientPtr &dbClient,
                     User &user);

  [[nodiscard]] const std::string &getId() const {
    return m_id;
  }

  [[nodiscard]] const std::string &getEmail() const {
    return m_email;
  }

  [[nodiscard]] const std::string &getNickname() const {
    return m_nickname;
  }

  [[nodiscard]] const std::string &getPasswordHash() const {
    return m_passwordHash;
  }

  [[nodiscard]] const trantor::Date &getCreatedAt() const {
    return m_createdAt;
  }

  [[nodiscard]] const trantor::Date &getUpdatedAt() const {
    return m_updatedAt;
  }

  void setId(const std::string &id) {
    m_id = id;
  }

  void setEmail(const std::string &email) {
    m_email = email;
  }

  void setNickname(const std::string &nickname) {
    m_nickname = nickname;
  }

  void setPasswordHash(const std::string &passwordHash) {
    m_passwordHash = passwordHash;
  }

  void setCreatedAt(const trantor::Date &createdAt) {
    m_createdAt = createdAt;
  }

  void setUpdatedAt(const trantor::Date &updatedAt) {
    m_updatedAt = updatedAt;
  }
};
} // namespace Models
