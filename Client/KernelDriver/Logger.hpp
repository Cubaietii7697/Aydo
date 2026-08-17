#pragma once

enum class LogLevel {
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARNING,
  LOG_ERROR,
};

namespace Logger {
void log(LogLevel level, const char *format, ...);

const char *_getLogLevelString(LogLevel level);
} // namespace Logger

#define LOG_DEBUG(format, ...) Logger::log(LogLevel::LOG_DEBUG, format, __VA_ARGS__)
#define LOG_INFO(format, ...) Logger::log(LogLevel::LOG_INFO, format, __VA_ARGS__)
#define LOG_WARNING(format, ...) Logger::log(LogLevel::LOG_WARNING, format, __VA_ARGS__)
#define LOG_ERROR(format, ...) Logger::log(LogLevel::LOG_ERROR, format, __VA_ARGS__)