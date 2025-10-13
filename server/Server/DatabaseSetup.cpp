#include "DatabaseSetup.hpp"

#include <cstdlib>
#include <string>

using drogon::orm::DbClientPtr;

void makeSureUserTableExists(const DbClientPtr &dbClient) {
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
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to create or verify users table: " << e.what();
    exit(EXIT_FAILURE);
  }
}

void setupDatabase() {
  try {
    auto dbClient = drogon::app().getDbClient();

    makeSureUserTableExists(dbClient);

    LOG_INFO << "Database setup completed";
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to setup database: " << e.what();
    exit(EXIT_FAILURE);
  }
}

