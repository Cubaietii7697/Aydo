#include "ServerCommunications.hpp"
#include "../UserConfig.hpp"

#include <cpr/cpr.h>
#include <iostream>
#include <nlohmann/json.hpp>

std::unique_ptr<ServerCommunications> ServerCommunications::m_instance = nullptr;
std::mutex ServerCommunications::m_mutex;

void ServerCommunications::initialize(const std::string &serverAddress, const std::string &authenticationToken, const std::string &refreshToken) {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_instance) {
    m_instance.reset(new ServerCommunications(serverAddress, authenticationToken, refreshToken));
  }
}

ServerCommunications &ServerCommunications::getInstance() {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_instance) {
    throw std::runtime_error("ServerCommunications not initialized. Call initialize() first.");
  }
  return *m_instance;
}

ServerCommunications::ServerCommunications(const std::string &serverAddress,
                                           const std::string &authenticationToken,
                                           const std::string &refreshToken)
    : m_serverAddress(serverAddress)
    , m_authenticationToken(authenticationToken)
    , m_refreshToken(refreshToken) {}

ServerCommunications::~ServerCommunications() {}

long ServerCommunications::postRequest(const std::string &endpoint, const std::string &body, std::string &responseBody) {
  try {
    cpr::Header headers = {{"Content-Type", "application/json"}};
    if (!m_authenticationToken.empty()) {
      headers.insert({"Authorization", "Bearer " + m_authenticationToken});
    }

    auto response = cpr::Post(
        cpr::Url{m_serverAddress + endpoint},
        cpr::Body{body},
        headers);

    responseBody = response.text;
    return response.status_code;
  } catch (const std::exception &e) {
    std::cerr << "Request error on " << endpoint << ": " << e.what() << std::endl;
    return 0;
  }
}

bool ServerCommunications::login(const std::string &email, const std::string &password) {
  nlohmann::json payload = {
      {"email", email},
      {"password", password}};

  std::string responseBody;
  if (postRequest("/api/auth/login", payload.dump(), responseBody) == static_cast<long>(HttpStatus::Ok)) {
    try {
      auto jsonResponse = nlohmann::json::parse(responseBody);
      if (jsonResponse.contains("accessToken")) {
        m_authenticationToken = jsonResponse["accessToken"];
        UserConfig::getInstance().accessToken = m_authenticationToken;
        if (jsonResponse.contains("refreshToken")) {
          m_refreshToken = jsonResponse["refreshToken"];
          UserConfig::getInstance().refreshToken = m_refreshToken;
        }
        UserConfig::getInstance().save();
        return true;
      }
    } catch (const std::exception &e) {
      std::cerr << "Login JSON parse error: " << e.what() << std::endl;
    }
  }
  return false;
}

bool ServerCommunications::registerUser(const std::string &email, const std::string &nickname, const std::string &password) {
  nlohmann::json payload = {
      {"email", email},
      {"nickname", nickname},
      {"password", password}};

  std::string responseBody;
  if (postRequest("/api/auth/register", payload.dump(), responseBody) == static_cast<long>(HttpStatus::Ok)) {
    try {
      auto jsonResponse = nlohmann::json::parse(responseBody);
      if (jsonResponse.contains("accessToken")) {
        m_authenticationToken = jsonResponse["accessToken"];
        UserConfig::getInstance().accessToken = m_authenticationToken;
        if (jsonResponse.contains("refreshToken")) {
          m_refreshToken = jsonResponse["refreshToken"];
          UserConfig::getInstance().refreshToken = m_refreshToken;
        }
        UserConfig::getInstance().save();
        return true;
      }
    } catch (const std::exception &e) {
      std::cerr << "Register JSON parse error: " << e.what() << std::endl;
    }
  }
  return false;
}

bool ServerCommunications::requestFileScan(const std::string &fileHash, const int runtime, nlohmann::json &responseJson) {
  nlohmann::json payload = {
      {"fileHash", fileHash},
      {"runtime", std::to_string(runtime)}};

  std::string responseBody;
  long status = postRequest("/api/sandbox/request-file-scan", payload.dump(), responseBody);
  if (status == static_cast<long>(HttpStatus::Ok) || status == static_cast<long>(HttpStatus::Created)) {
    try {
      responseJson = nlohmann::json::parse(responseBody);
      return true;
    } catch (const std::exception &e) {
      std::cerr << "RequestFileScan JSON parse error: " << e.what() << std::endl;
    }
  }
  return false;
}

bool ServerCommunications::uploadFile(const std::string &fileHash, const std::string &filePath) {
  try {
    cpr::Header headers;
    if (!m_authenticationToken.empty()) {
      headers.insert({"Authorization", "Bearer " + m_authenticationToken});
    }

    auto response = cpr::Post(
        cpr::Url{m_serverAddress + "/api/sandbox/upload-file"},
        cpr::Multipart{{"fileHash", fileHash},
                       {"file", cpr::File{filePath}}},
        headers);

    return response.status_code == static_cast<long>(HttpStatus::Ok);
  } catch (const std::exception &e) {
    std::cerr << "UploadFile error: " << e.what() << std::endl;
    return false;
  }
}
