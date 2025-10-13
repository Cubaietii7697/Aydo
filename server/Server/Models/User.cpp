#include "User.hpp"

#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <optional>

using drogon::orm::DbClientPtr;

namespace Models {

std::optional<User> User::getByEmail(const DbClientPtr &dbClient,
                                     const std::string &email) {
  auto result = dbClient->execSqlSync(
      "SELECT id, email, nickname, passwordHash, createdAt, updatedAt FROM users WHERE email = $1 LIMIT 1",
      email);

  if (result.empty()) {
    return std::nullopt;
  }

  const auto &row = result[0];

  User user;
  user.setId(std::to_string(row["id"].as<int>()));
  user.setEmail(row["email"].as<std::string>());
  user.setNickname(row["nickname"].as<std::string>());
  user.setPasswordHash(row["passwordHash"].as<std::string>());

  return user;
}

std::optional<User> User::getById(const DbClientPtr &dbClient,
                                  const std::string &id) {
  // Validate and convert string ID to integer for database query
  if (id.empty()) {
    return std::nullopt;
  }

  int userId;
  try {
    userId = std::stoi(id);
  } catch (const std::invalid_argument &) {
    return std::nullopt;
  } catch (const std::out_of_range &) {
    return std::nullopt;
  }

  auto result = dbClient->execSqlSync(
      "SELECT id, email, nickname, passwordHash, createdAt, updatedAt FROM users WHERE id = $1 LIMIT 1",
      userId);

  if (result.empty()) {
    return std::nullopt;
  }

  const auto &row = result[0];

  User user;
  user.setId(std::to_string(row["id"].as<int>()));
  user.setEmail(row["email"].as<std::string>());
  user.setNickname(row["nickname"].as<std::string>());
  user.setPasswordHash(row["passwordHash"].as<std::string>());

  return user;
}

void User::create(const DbClientPtr &dbClient, User &user) {
  auto result = dbClient->execSqlSync(
      "INSERT INTO users (email, nickname, passwordHash) VALUES ($1, $2, $3) RETURNING id",
      user.getEmail(), user.getNickname(), user.getPasswordHash());
  
  if (!result.empty()) {
    user.setId(std::to_string(result[0]["id"].as<int>()));
  }
}

} // namespace Models
