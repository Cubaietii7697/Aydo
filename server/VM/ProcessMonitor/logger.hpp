#pragma once
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>

class Logger {
public:
  enum class Level { LOG_INFO,
                     LOG_ERROR,
                     LOG_DEBUG };

  static void Init(const std::wstring &logPath, bool alsoConsole = true);

  static void Shutdown();

  static void Info(const std::wstring &msg) { log(Level::LOG_INFO, msg); }
  static void Error(const std::wstring &msg) { log(Level::LOG_ERROR, msg); }
  static void Debug(const std::wstring &msg) { log(Level::LOG_DEBUG, msg); }

private:
  std::wofstream ofs;
  bool console = true;
  std::mutex mtx;

  static Logger &instance() {
    static Logger inst;
    return inst;
  }

  static void log(Level lvl, const std::wstring &msg);
};
