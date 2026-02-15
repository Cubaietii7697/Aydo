#include "pch.h"
#include "SelfTest.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "EventWriter.hpp"
#include "ThreadAnalysisEngine.hpp"
#include "ThreadCaches.hpp"

using ScenarioFeeder = std::function<void(
    ThreadAnalysisEngine &,
    std::chrono::time_point<std::chrono::system_clock>)>;

struct Scenario {
  std::string name;
  ScenarioFeeder feeder;
  std::map<std::string, int> expectedCounts;
};

static NormalizedEvent s_makeEvent(
    std::chrono::time_point<std::chrono::system_clock> ts,
    DWORD pid,
    DWORD tid,
    std::string provider,
    int eventId,
    std::string eventName,
    std::string taskName = {}) {
  NormalizedEvent ne{};
  ne.ts = ts;
  ne.pid = pid;
  ne.tid = tid;
  ne.provider = std::move(provider);
  ne.eventId = eventId;
  ne.fields["event"] = std::move(eventName);
  if (!taskName.empty()) {
    ne.fields["task_name"] = std::move(taskName);
  }
  ne.fields["SourcePid"] = static_cast<uint32_t>(pid);
  return ne;
}

static bool s_loadFindingCounts(
    const std::filesystem::path &dbPath,
    std::map<std::string, int> &counts,
    std::string &error) {
  sqlite3 *db = nullptr;
  if (sqlite3_open16(dbPath.c_str(), &db) != SQLITE_OK || !db) {
    error = "failed opening sqlite db";
    if (db) {
      sqlite3_close_v2(db);
    }
    return false;
  }

  sqlite3_stmt *stmt = nullptr;
  const char *sql = "SELECT Type, COUNT(*) FROM Findings GROUP BY Type";
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK || !stmt) {
    error = sqlite3_errmsg(db);
    if (error.find("no such table: Findings") != std::string::npos) {
      sqlite3_close_v2(db);
      return true;
    }
    if (stmt) {
      sqlite3_finalize(stmt);
    }
    sqlite3_close_v2(db);
    return false;
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *typeTxt = sqlite3_column_text(stmt, 0);
    if (!typeTxt) {
      continue;
    }
    const int count = sqlite3_column_int(stmt, 1);
    counts[reinterpret_cast<const char *>(typeTxt)] = count;
  }

  sqlite3_finalize(stmt);
  sqlite3_close_v2(db);
  return true;
}

static bool s_runScenario(const Scenario &scenario) {
  const auto dbPath =
      std::filesystem::temp_directory_path() /
      std::filesystem::path("pm_selftest_" + scenario.name + ".sqlite");

  std::error_code ec;
  std::filesystem::remove(dbPath, ec);

  {
    ThreadCaches caches;
    EventWriter writer(dbPath.wstring(), EventWriter::WireFormat::Sqlite, false, true);
    ThreadAnalysisEngine engine(&caches, &writer);

    const auto base = std::chrono::system_clock::time_point(std::chrono::seconds(10));
    scenario.feeder(engine, base);
    writer.flush();
  }

  std::map<std::string, int> actual;
  std::string error;
  const bool loaded = s_loadFindingCounts(dbPath, actual, error);
  std::filesystem::remove(dbPath, ec);
  if (!loaded) {
    std::wcerr << L"[self-test] " << std::wstring(scenario.name.begin(), scenario.name.end())
               << L" failed to read findings: "
               << std::wstring(error.begin(), error.end())
               << std::endl;
    return false;
  }

  bool ok = true;
  for (const auto &[type, expected] : scenario.expectedCounts) {
    const int got = actual.contains(type) ? actual[type] : 0;
    if (got != expected) {
      ok = false;
    }
  }
  for (const auto &[type, got] : actual) {
    const int expected = scenario.expectedCounts.contains(type) ? scenario.expectedCounts.at(type) : 0;
    if (got != expected) {
      ok = false;
    }
  }

  if (!ok) {
    std::wcerr << L"[self-test] "
               << std::wstring(scenario.name.begin(), scenario.name.end())
               << L" expected vs actual mismatch." << std::endl;
    std::wcerr << L"  expected:";
    for (const auto &[type, count] : scenario.expectedCounts) {
      std::wcerr << L" [" << std::wstring(type.begin(), type.end()) << L"=" << count << L"]";
    }
    std::wcerr << std::endl;

    std::wcerr << L"  actual:";
    for (const auto &[type, count] : actual) {
      std::wcerr << L" [" << std::wstring(type.begin(), type.end()) << L"=" << count << L"]";
    }
    std::wcerr << std::endl;
  }

  return ok;
}

static std::vector<Scenario> s_buildScenarios() {
  return {
      {
          "remote_thread_positive",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1001,
                5001,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                5,
                "Info");
            access.fields["SourcePid"] = uint32_t(1001);
            access.fields["TargetPid"] = uint32_t(2001);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto start = s_makeEvent(
                base + std::chrono::seconds(1),
                2001,
                5002,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            start.fields["SourcePid"] = uint32_t(2001);
            start.fields["TargetPid"] = uint32_t(2001);
            start.fields["TargetTid"] = uint32_t(3001);
            start.fields["ProcessId"] = uint32_t(2001);
            start.fields["TThreadId"] = uint32_t(3001);
            engine.onEvent(start);
          },
          {{"RemoteThreadCreation", 1}},
      },
      {
          "apc_positive",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1101,
                5101,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                6,
                "Info");
            access.fields["SourcePid"] = uint32_t(1101);
            access.fields["TargetPid"] = uint32_t(2101);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto apc = s_makeEvent(
                base + std::chrono::seconds(1),
                1101,
                5102,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                99,
                "QueueUserAPC");
            apc.fields["SourcePid"] = uint32_t(1101);
            apc.fields["TargetPid"] = uint32_t(2101);
            apc.fields["TargetTid"] = uint32_t(3101);
            engine.onEvent(apc);
          },
          {{"AsynchronousProcedureCallQueueing", 1}},
      },
      {
          "hijack_positive",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto start = s_makeEvent(
                base + std::chrono::seconds(0),
                2201,
                5201,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            start.fields["SourcePid"] = uint32_t(2201);
            start.fields["TargetPid"] = uint32_t(2201);
            start.fields["TargetTid"] = uint32_t(3201);
            start.fields["ProcessId"] = uint32_t(2201);
            start.fields["TThreadId"] = uint32_t(3201);
            engine.onEvent(start);

            auto suspend = s_makeEvent(
                base + std::chrono::seconds(1),
                1201,
                5202,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                200,
                "SuspendThread");
            suspend.fields["SourcePid"] = uint32_t(1201);
            suspend.fields["TargetPid"] = uint32_t(2201);
            suspend.fields["TargetTid"] = uint32_t(3201);
            engine.onEvent(suspend);

            auto context = s_makeEvent(
                base + std::chrono::seconds(2),
                1201,
                5203,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                201,
                "SetThreadContext");
            context.fields["SourcePid"] = uint32_t(1201);
            context.fields["TargetPid"] = uint32_t(2201);
            context.fields["TargetTid"] = uint32_t(3201);
            engine.onEvent(context);

            auto resume = s_makeEvent(
                base + std::chrono::seconds(3),
                1201,
                5204,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                202,
                "ResumeThread");
            resume.fields["SourcePid"] = uint32_t(1201);
            resume.fields["TargetPid"] = uint32_t(2201);
            resume.fields["TargetTid"] = uint32_t(3201);
            engine.onEvent(resume);
          },
          {{"ThreadHijackHeuristic", 1}},
      },
      {
          "negative_local_actions",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1301,
                5301,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                6,
                "Info");
            access.fields["SourcePid"] = uint32_t(1301);
            access.fields["TargetPid"] = uint32_t(1301);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto apc = s_makeEvent(
                base + std::chrono::seconds(1),
                1301,
                5302,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                99,
                "QueueUserAPC");
            apc.fields["SourcePid"] = uint32_t(1301);
            apc.fields["TargetPid"] = uint32_t(1301);
            apc.fields["TargetTid"] = uint32_t(3301);
            engine.onEvent(apc);

            auto start = s_makeEvent(
                base + std::chrono::seconds(2),
                1301,
                5303,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            start.fields["SourcePid"] = uint32_t(1301);
            start.fields["TargetPid"] = uint32_t(1301);
            start.fields["TargetTid"] = uint32_t(3301);
            start.fields["ProcessId"] = uint32_t(1301);
            start.fields["TThreadId"] = uint32_t(3301);
            engine.onEvent(start);

            auto suspend = s_makeEvent(
                base + std::chrono::seconds(3),
                1301,
                5304,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                200,
                "SuspendThread");
            suspend.fields["SourcePid"] = uint32_t(1301);
            suspend.fields["TargetPid"] = uint32_t(1301);
            suspend.fields["TargetTid"] = uint32_t(3301);
            engine.onEvent(suspend);

            auto context = s_makeEvent(
                base + std::chrono::seconds(4),
                1301,
                5305,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                201,
                "SetThreadContext");
            context.fields["SourcePid"] = uint32_t(1301);
            context.fields["TargetPid"] = uint32_t(1301);
            context.fields["TargetTid"] = uint32_t(3301);
            engine.onEvent(context);

            auto resume = s_makeEvent(
                base + std::chrono::seconds(5),
                1301,
                5306,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                202,
                "ResumeThread");
            resume.fields["SourcePid"] = uint32_t(1301);
            resume.fields["TargetPid"] = uint32_t(1301);
            resume.fields["TargetTid"] = uint32_t(3301);
            engine.onEvent(resume);
          },
          {},
      },
      {
          "negative_incomplete_sequence",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto start = s_makeEvent(
                base + std::chrono::seconds(0),
                2401,
                5401,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            start.fields["SourcePid"] = uint32_t(2401);
            start.fields["TargetPid"] = uint32_t(2401);
            start.fields["TargetTid"] = uint32_t(3401);
            start.fields["ProcessId"] = uint32_t(2401);
            start.fields["TThreadId"] = uint32_t(3401);
            engine.onEvent(start);

            auto suspend = s_makeEvent(
                base + std::chrono::seconds(1),
                1401,
                5402,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                200,
                "SuspendThread");
            suspend.fields["SourcePid"] = uint32_t(1401);
            suspend.fields["TargetPid"] = uint32_t(2401);
            suspend.fields["TargetTid"] = uint32_t(3401);
            engine.onEvent(suspend);

            auto resume = s_makeEvent(
                base + std::chrono::seconds(2),
                1401,
                5403,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                202,
                "ResumeThread");
            resume.fields["SourcePid"] = uint32_t(1401);
            resume.fields["TargetPid"] = uint32_t(2401);
            resume.fields["TargetTid"] = uint32_t(3401);
            engine.onEvent(resume);
          },
          {},
      },
      {
          "negative_stale",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1501,
                5501,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                5,
                "Info");
            access.fields["SourcePid"] = uint32_t(1501);
            access.fields["TargetPid"] = uint32_t(2501);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto staleStart = s_makeEvent(
                base + std::chrono::seconds(12),
                2501,
                5502,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            staleStart.fields["SourcePid"] = uint32_t(2501);
            staleStart.fields["TargetPid"] = uint32_t(2501);
            staleStart.fields["TargetTid"] = uint32_t(3501);
            staleStart.fields["ProcessId"] = uint32_t(2501);
            staleStart.fields["TThreadId"] = uint32_t(3501);
            engine.onEvent(staleStart);

            auto owner = s_makeEvent(
                base + std::chrono::seconds(0),
                2601,
                5503,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            owner.fields["SourcePid"] = uint32_t(2601);
            owner.fields["TargetPid"] = uint32_t(2601);
            owner.fields["TargetTid"] = uint32_t(3601);
            owner.fields["ProcessId"] = uint32_t(2601);
            owner.fields["TThreadId"] = uint32_t(3601);
            engine.onEvent(owner);

            auto suspend = s_makeEvent(
                base + std::chrono::seconds(1),
                1601,
                5504,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                200,
                "SuspendThread");
            suspend.fields["SourcePid"] = uint32_t(1601);
            suspend.fields["TargetPid"] = uint32_t(2601);
            suspend.fields["TargetTid"] = uint32_t(3601);
            engine.onEvent(suspend);

            auto context = s_makeEvent(
                base + std::chrono::seconds(14),
                1601,
                5505,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                201,
                "SetThreadContext");
            context.fields["SourcePid"] = uint32_t(1601);
            context.fields["TargetPid"] = uint32_t(2601);
            context.fields["TargetTid"] = uint32_t(3601);
            engine.onEvent(context);

            auto resume = s_makeEvent(
                base + std::chrono::seconds(15),
                1601,
                5506,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                202,
                "ResumeThread");
            resume.fields["SourcePid"] = uint32_t(1601);
            resume.fields["TargetPid"] = uint32_t(2601);
            resume.fields["TargetTid"] = uint32_t(3601);
            engine.onEvent(resume);
          },
          {},
      },
      {
          "duplicate_suppression",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1701,
                5701,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                6,
                "Info");
            access.fields["SourcePid"] = uint32_t(1701);
            access.fields["TargetPid"] = uint32_t(2701);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto apc1 = s_makeEvent(
                base + std::chrono::seconds(1),
                1701,
                5702,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                99,
                "NtQueueApcThread");
            apc1.fields["SourcePid"] = uint32_t(1701);
            apc1.fields["TargetPid"] = uint32_t(2701);
            apc1.fields["TargetTid"] = uint32_t(3701);
            engine.onEvent(apc1);

            auto apc2 = s_makeEvent(
                base + std::chrono::seconds(2),
                1701,
                5703,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                99,
                "NtQueueApcThread");
            apc2.fields["SourcePid"] = uint32_t(1701);
            apc2.fields["TargetPid"] = uint32_t(2701);
            apc2.fields["TargetTid"] = uint32_t(3701);
            engine.onEvent(apc2);
          },
          {{"AsynchronousProcedureCallQueueing", 1}},
      },
  };
}

int RunProcessMonitorSelfTest() {
  const auto scenarios = s_buildScenarios();
  int failed = 0;

  for (const auto &scenario : scenarios) {
    if (s_runScenario(scenario)) {
      std::wcout << L"[self-test] PASS "
                 << std::wstring(scenario.name.begin(), scenario.name.end())
                 << std::endl;
    } else {
      std::wcout << L"[self-test] FAIL "
                 << std::wstring(scenario.name.begin(), scenario.name.end())
                 << std::endl;
      ++failed;
    }
  }

  if (failed == 0) {
    std::wcout << L"[self-test] all scenarios passed" << std::endl;
    return EXIT_SUCCESS;
  }

  std::wcerr << L"[self-test] failures: " << failed << std::endl;
  return EXIT_FAILURE;
}



