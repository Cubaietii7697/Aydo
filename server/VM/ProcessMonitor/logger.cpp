#include "logger.hpp"

void Logger::Init(const std::wstring &logPath, bool alsoConsole) {
  instance().ofs.open(logPath, std::ios::out | std::ios::app);
  instance().console = alsoConsole;
  if (!instance().ofs.is_open()) {
    throw std::runtime_error("Failed to open log file");
  }
}

void Logger::Shutdown() {
  if (instance().ofs.is_open()) {
    instance().ofs.flush();
    instance().ofs.close();
  }
}

void Logger::log(Level lvl, const std::wstring &msg) {

  auto &inst = instance();
  std::lock_guard<std::mutex> lock(inst.mtx);

  const wchar_t *prefix = L"";
  switch (lvl) {
  case Level::LOG_INFO:
    prefix = L"[INFO] ";
    break;
  case Level::LOG_ERROR:
    prefix = L"[ERROR] ";
    break;
  case Level::LOG_DEBUG:
    prefix = L"[DBG] ";
    break;
  }

  if (inst.console) {
    if (lvl == Level::LOG_ERROR)
      std::wcerr << prefix << msg << std::endl;
    else
      std::wcout << prefix << msg << std::endl;
  }

  if (inst.ofs.is_open()) {
    inst.ofs << prefix << msg << std::endl;
    inst.ofs.flush();
  }
}
