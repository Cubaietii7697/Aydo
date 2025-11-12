#include "DatabaseSetup.hpp"

#include <string>

namespace DatabaseSetup {

using drogon::orm::DbClientPtr;

bool makeSureUserTableExists(const DbClientPtr &dbClient) {
  try {
    dbClient->execSqlSync(R"(CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,

            email VARCHAR(255) NOT NULL UNIQUE,
            nickname VARCHAR(255) NOT NULL,
            passwordHash VARCHAR(255) NOT NULL,

            createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updatedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );)");
    LOG_INFO << "Ensured users table exists";

    return true;
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to create or verify users table: " << e.what();

    return false;
  }
}

bool setupDatabase() {
  auto dbClient = drogon::app().getDbClient();

  if (!makeSureUserTableExists(dbClient)) {
    return false;
  }

  LOG_INFO << "Database setup completed";

  return true;
}

} // namespace DatabaseSetup
