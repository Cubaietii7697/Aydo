#pragma once
#include <krabs.hpp>

struct KernelBlock {
  krabs::kernel_trace trace{L"AydoKernelTrace"};
  krabs::kernel::process_provider proc;
  krabs::kernel::thread_provider thrd;
  krabs::kernel::image_load_provider img;
  krabs::kernel::registry_provider reg;
  krabs::kernel::file_io_provider file;
  krabs::kernel::network_tcpip_provider net;
  krabs::kernel::file_init_io_provider fileInit;
  krabs::kernel::disk_io_provider disk;
  krabs::kernel::disk_file_io_provider diskFile;
  krabs::kernel::context_switch_provider ctx;
};
