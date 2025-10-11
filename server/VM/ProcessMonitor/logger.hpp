#pragma once
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>

class Logger {
public:
  enum class LogLevel { LOG_INFO,
                        LOG_ERROR,
                        LOG_DEBUG };

  [[nodiscard]] static bool Init(const std::wstring &logPath, bool alsoConsole = true);

  static void Shutdown();

  static void Info(const std::wstring &msg) { log(LogLevel::LOG_INFO, msg); }
  static void Error(const std::wstring &msg) { log(LogLevel::LOG_ERROR, msg); }
  static void Debug(const std::wstring &msg) { log(LogLevel::LOG_DEBUG, msg); }

private:
  std::wofstream m_ofs;
  bool m_console = true;
  std::mutex m_mtx;

  static Logger &instance() {
    static Logger inst;
    return inst;
  }

  static void log(LogLevel lvl, const std::wstring &msg);
};
