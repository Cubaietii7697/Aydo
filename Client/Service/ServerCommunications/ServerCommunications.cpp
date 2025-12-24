#include "ServerCommunications.hpp"

#include <cpr/cpr.h>
#include <iostream>
#include <nlohmann/json.hpp>

std::unique_ptr<ServerCommunications> ServerCommunications::m_instance = nullptr;
std::mutex ServerCommunications::m_mutex;

void ServerCommunications::initialize(const std::string &serverAddress, const std::string &authenticationToken) {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_instance) {
    m_instance.reset(new ServerCommunications(serverAddress, authenticationToken));
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
                                           const std::string &authenticationToken)
    : m_serverAddress(serverAddress)
    , m_authenticationToken(authenticationToken) {}

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
        return true;
      }
    } catch (const std::exception &e) {
      std::cerr << "Register JSON parse error: " << e.what() << std::endl;
    }
  }
  return false;
}

bool ServerCommunications::requestFileScan(const std::string &fileHash, int runtime, nlohmann::json &responseJson) {
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
