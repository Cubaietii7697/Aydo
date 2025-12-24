#pragma once

#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

class ServerCommunications {
private:
  std::string m_serverAddress;
  std::string m_authenticationToken;

  static std::unique_ptr<ServerCommunications> m_instance;
  static std::mutex m_mutex;

  ServerCommunications(const std::string &serverAddress,
                       const std::string &authenticationToken);

  enum class HttpStatus {
    Ok = 200,
    Created = 201,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    Conflict = 409,
    InternalServerError = 500
  };

  long postRequest(const std::string &endpoint, const std::string &body, std::string &responseBody);

public:
  ~ServerCommunications();

  ServerCommunications(const ServerCommunications &) = delete;
  ServerCommunications &operator=(const ServerCommunications &) = delete;
  ServerCommunications(ServerCommunications &&) = delete;
  ServerCommunications &operator=(ServerCommunications &&) = delete;

  static void initialize(const std::string &serverAddress, const std::string &authenticationToken = "");
  static ServerCommunications &getInstance();

  bool login(const std::string &email, const std::string &password);
  bool registerUser(const std::string &email, const std::string &nickname, const std::string &password);

  bool requestFileScan(const std::string &fileHash, const int runtime, nlohmann::json &responseJson);
  bool uploadFile(const std::string &fileHash, const std::string &filePath);
};