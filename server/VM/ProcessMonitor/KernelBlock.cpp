#include "kernelBlock.hpp"
#include <stdexcept>
KernelBlock::KernelBlock(const std::wstring &userSessionName)
    : m_sessionName(userSessionName) {
}

void KernelBlock::addDefaultKernelProviders() {
  addProvider<krabs::kernel::process_provider>();
  addProvider<krabs::kernel::thread_provider>();
  addProvider<krabs::kernel::image_load_provider>();
  addProvider<krabs::kernel::registry_provider>();
  addProvider<krabs::kernel::file_io_provider>();
  addProvider<krabs::kernel::network_tcpip_provider>();
  addProvider<krabs::kernel::file_init_io_provider>();
  addProvider<krabs::kernel::disk_io_provider>();
  addProvider<krabs::kernel::disk_file_io_provider>();
  addProvider<krabs::kernel::context_switch_provider>();
}

void KernelBlock::start(const Callback &cb) {
  if (m_thread.joinable()) {
    throw std::runtime_error("KernelBlock::start called while already running");
  }

  m_cb = cb;
  m_trace = std::make_unique<krabs::kernel_trace>(m_sessionName);

  for (auto const &up : m_provs) {
    up->attach(*m_trace, m_cb);
  }

  m_thread = std::thread([this] {
    try {
      m_trace->start();
    } catch (...) {

      throw;
    }
  });
}

void KernelBlock::stop() {
  if (!m_trace) {
    return;
  }

  m_trace->stop();
  if (m_thread.joinable()) {
    m_thread.join();
  }

  m_provs.clear();
  m_trace.reset();
  m_cb = Callback{};
}
