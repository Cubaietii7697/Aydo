#pragma once
#include <drogon/HttpAppFramework.h>
#include <string>
#include <trantor/utils/Logger.h>

void makeSureUserTableExists(const drogon::orm::DbClientPtr &dbClient);

void setupDatabase();
