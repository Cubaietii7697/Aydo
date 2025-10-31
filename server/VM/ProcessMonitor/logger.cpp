#include "Logger.hpp"

bool Logger::Init(const std::wstring &logPath, bool alsoConsole) {
  instance().m_console = alsoConsole;
  instance().m_ofs.exceptions(std::ios::failbit | std::ios::badbit);
  const std::filesystem::path p{logPath};
  try {
    instance().m_ofs.open(p, std::ios::out | std::ios::app);
  } catch (const std::ios_base::failure &) {
    return false;
  }

  return true;
}

void Logger::Shutdown() {
  if (instance().m_ofs.is_open()) {
    instance().m_ofs.flush();
    instance().m_ofs.close();
  }
}

void Logger::log(LogLevel lvl, const std::wstring &msg) {

  auto &inst = instance();
  std::scoped_lock<std::mutex> lock(inst.m_mtx);

  const wchar_t *prefix{};
  switch (lvl) {
    using enum Logger::LogLevel;
  case LOG_INFO:
    prefix = L"[INFO] ";
    break;
  case LOG_ERROR:
    prefix = L"[ERROR] ";
    break;
  case LOG_DEBUG:
    prefix = L"[DBG] ";
    break;
  }

  if (inst.m_console) {
    if (lvl == LogLevel::LOG_ERROR)
      std::wcerr << prefix << msg << std::endl;
    else
      std::wcout << prefix << msg << std::endl;
  }

  if (inst.m_ofs.is_open()) {
    inst.m_ofs << prefix << msg << std::endl;
    inst.m_ofs.flush();
  }
}
