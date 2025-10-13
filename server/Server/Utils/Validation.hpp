#pragma once

#include <json/json.h>
#include <optional>
#include <regex>
#include <string>

namespace Utils::Validation {

enum class FieldType {
  Email,
  Nickname,
  Password,
  RefreshToken
};

inline constexpr unsigned int MIN_PASSWORD_LENGTH = 8;
inline const std::regex EMAIL_PATTERN(
    R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
inline const std::regex NICKNAME_PATTERN(R"(^[a-zA-Z]+$)");
inline const std::regex PASSWORD_HAS_ATLEAST_ONE_LOWER(R"([a-z])");
inline const std::regex PASSWORD_HAS_ATLEAST_ONE_UPPER(R"([A-Z])");
inline const std::regex PASSWORD_HAS_ATLEAST_ONE_DIGIT(R"([0-9])");

[[nodiscard]] std::optional<std::string> validateField(
    const Json::Value *jsonBody,
    const std::string &fieldName,
    FieldType fieldType);

[[nodiscard]] bool isValidEmail(const std::string &email);

[[nodiscard]] bool isValidNickname(const std::string &nickname);

[[nodiscard]] bool isValidPassword(const std::string &password);

[[nodiscard]] bool isValidRefreshToken(const std::string &refreshToken);

} // namespace Utils::Validation
