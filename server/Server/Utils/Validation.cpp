#include "Validation.hpp"

#include <regex>

namespace Utils::Validation {

// Checks for a valid email (AAA@BBB.CCC)
bool isValidEmail(const std::string &email) {
  if (email.empty()) {
    return false;
  }

  return std::regex_match(email, EMAIL_PATTERN);
}

// Checks for a valid nickname (only letters [upper and lower case])
bool isValidNickname(const std::string &nickname) {
  if (nickname.empty()) {
    return false;
  }

  return std::regex_match(nickname, NICKNAME_PATTERN);
}

// Checks for a valid password (8+ chars with 1 lower, 1 upper, 1 digit)
bool isValidPassword(const std::string &password) {
  if (password.length() < MIN_PASSWORD_LENGTH) {
    return false;
  }

  if (!std::regex_search(password, PASSWORD_HAS_ATLEAST_ONE_LOWER)) {
    return false;
  }

  if (!std::regex_search(password, PASSWORD_HAS_ATLEAST_ONE_UPPER)) {
    return false;
  }

  if (!std::regex_search(password, PASSWORD_HAS_ATLEAST_ONE_DIGIT)) {
    return false;
  }

  return true;
}

// Checks for a valid refresh token (we don't validate the token itself, just check if it's not empty)
bool isValidRefreshToken(std::string_view refreshToken) {
  if (refreshToken.empty()) {
    return false;
  }

  return true;
}

// Checks for a valid file hash (64 hex characters for SHA256)
bool isValidFileHash(const std::string &fileHash) {
  if (fileHash.length() != 64) {
    return false;
  }

  // Check for null bytes
  if (fileHash.find('\0') != std::string::npos) {
    return false;
  }

  // Check all characters are valid hex digits
  for (char c : fileHash) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      return false;
    }
  }

  return true;
}

// Checks for a valid runtime (positive integer)
// TODO: Discuss min and max times w/mentor
bool isValidRuntime(const std::string &runtime) {
  if (runtime.empty()) {
    return false;
  }

  try {
    int value = std::stoi(runtime);
    return value > 0;
  } catch (...) {
    return false;
  }
}

std::optional<std::string> validateField(
    const Json::Value *jsonBody,
    const std::string &fieldName,
    FieldType fieldType) {
  if (!jsonBody) {
    return std::nullopt;
  }

  const std::string value = jsonBody->get(fieldName, "").asString();

  if (value.empty()) {
    return std::nullopt;
  }

  bool isValid = false;

  switch (fieldType) {
  case FieldType::Email:
    isValid = isValidEmail(value);
    break;
  case FieldType::Nickname:
    isValid = isValidNickname(value);
    break;
  case FieldType::Password:
    isValid = isValidPassword(value);
    break;
  case FieldType::RefreshToken:
    isValid = isValidRefreshToken(value);
    break;
  case FieldType::FileHash:
    isValid = isValidFileHash(value);
    break;
  case FieldType::Runtime:
    isValid = isValidRuntime(value);
    break;
  }

  return isValid ? std::make_optional(value) : std::nullopt;
}

} // namespace Utils::Validation
