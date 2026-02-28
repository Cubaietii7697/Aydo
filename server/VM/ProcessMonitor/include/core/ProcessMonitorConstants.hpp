#pragma once

#include <cstdint>
#include <string_view>

namespace ProcessMonitorConstants {
inline constexpr std::uint32_t INVALID_PID = 0;
inline constexpr std::uint32_t ALL_PROCESSES_SNAPSHOT = 0;
inline constexpr std::uint64_t DEFAULT_ANY_MASK = 0;
inline constexpr std::uint64_t DEFAULT_ALL_MASK = 0;
inline constexpr long long MIN_WAIT_MS = 0;
inline constexpr long long MAX_WAIT_MS = 0x7fffffff;
inline constexpr std::wstring_view PID_SEPARATOR = L", ";
} // namespace ProcessMonitorConstants
