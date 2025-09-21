#include "readFromVm.hpp"
#include <evntrace.h>
#include <iostream>
#include <windows.h>

int wmain(int argc, wchar_t *argv[]) {
  std::wcout << L"Starting ETW Monitor..." << std::endl;

  readFromVm monitor;
  // auto to chrome procces
  const std::wstring targetExe =
      (argc > 1) ? std::wstring(argv[1]) : L"chrome.exe";

  std::wcout << L"Looking for process: " << targetExe << std::endl;
  std::set<DWORD> pids = monitor.FindPidByName(targetExe);
  if (pids.empty()) {
    std::wcerr << L"Could not find process: " << targetExe << L"\n";
    std::wcout << L"Available processes with 'chrome' in name:" << std::endl;

    // Show available Chrome processes for debugging
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
      PROCESSENTRY32W pe;
      pe.dwSize = sizeof(pe);
      if (Process32FirstW(snap, &pe)) {
        do {
          std::wstring processName = pe.szExeFile;
          if (processName.find(L"chrome") != std::wstring::npos) {
            std::wcout << L"  " << pe.szExeFile << L" (PID: "
                       << pe.th32ProcessID << L")" << std::endl;
          }
        } while (Process32NextW(snap, &pe));
      }
      CloseHandle(snap);
    }

    std::wcout << L"Press Enter to exit...\n";
    std::wstring dummy;
    std::getline(std::wcin, dummy);
    return 1;
  }

  g_targetPids = pids;
  std::wcout << L"Found " << pids.size() << L" chrome.exe processes:\n";
  for (DWORD pid : pids) {
    std::wcout << L"  PID: " << pid << std::endl;
    g_targetPids.insert(pid);
  }
  // Use the standard kernel logger session name
  const std::wstring sessionName = L"NT Kernel Logger";
  std::wcout << L"Using session name: " << sessionName << std::endl;

  ULONG status = 0;
  if (!monitor.StartKernelSession(sessionName, status)) {
    std::wcerr << L"[ERROR] StartKernelSession failed: " << status << L"\n";
    std::wcout << L"Press Enter to exit...\n";
    std::wstring dummy;
    std::getline(std::wcin, dummy);
    return 1;
  }

  std::wcout << L"Kernel session started successfully!" << std::endl;

  // Start worker thread
  std::atomic<bool> workerStarted{false};
  std::atomic<int> workerResult{-1};

  std::wcout << L"Starting worker thread..." << std::endl;
  std::thread worker([&monitor, &sessionName, &workerStarted, &workerResult]() {
    std::wcout << L"[WORKER] Thread started" << std::endl;
    workerStarted = true;
    bool ok = monitor.OpenAndProcessRealTime(sessionName);
    workerResult = ok ? 0 : 1;
    std::wcout << L"[WORKER] Thread finished with result: "
               << (ok ? L"SUCCESS" : L"FAILURE") << std::endl;
  });

  Sleep(500);

  if (!workerStarted) {
    std::wcerr << L"Worker thread did not start properly.\n";
  } else {
    std::wcout << L"Worker thread started successfully!" << std::endl;
  }

  std::wcout << L"\n=== ETW Monitor Active ===" << std::endl;
  std::wcout << L"Monitoring PIDs: [ ";
  for (DWORD pid : pids) {
    std::wcout << L"  PID: " << pid << std::endl;
    g_targetPids.insert(pid);
  }
  std::wcout << L"] (" << targetExe << L")" << std::endl;
  std::wcout << L"You should see events within 15 seconds..." << std::endl;
  std::wcout << L"If you don't see any events, try:" << std::endl;
  std::wcout << L"1. Run as Administrator" << std::endl;
  std::wcout << L"2. Try with notepad.exe instead" << std::endl;
  std::wcout << L"3. Create some activity in the target process" << std::endl;
  std::wcout << L"\nPress Enter to stop monitoring...\n" << std::endl;

  std::wstring dummy;
  std::getline(std::wcin, dummy);

  std::wcout << L"Stopping trace..." << std::endl;

  // Stop tracing
  if (g_hTrace != 0 && g_hTrace != INVALID_PROCESSTRACE_HANDLE) {
    std::wcout << L"Closing trace handle..." << std::endl;
    ULONG closeStatus = CloseTrace(g_hTrace);
    if (closeStatus != ERROR_SUCCESS &&
        closeStatus != ERROR_CTX_CLOSE_PENDING) {
      std::wcerr << L"CloseTrace failed: " << closeStatus << L"\n";
    } else {
      std::wcout << L"Trace handle closed successfully" << std::endl;
    }
    g_hTrace = 0;
  }

  monitor.StopKernelSession(sessionName);

  std::wcout << L"Waiting for worker thread to finish..." << std::endl;
  if (worker.joinable())
    worker.join();

  if (workerResult != 0) {
    std::wcerr << L"Worker reported failure (code=" << (int)workerResult.load()
               << L")\n";
  } else {
    std::wcout << L"Worker completed successfully" << std::endl;
  }

  std::wcout << L"Shutdown complete.\nPress Enter to exit...\n";
  std::wstring vvv;
  std::getline(std::wcin, vvv);
  return 0;
}
