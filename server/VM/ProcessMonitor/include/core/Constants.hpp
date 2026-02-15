#pragma once

#include <cstddef>
#include <cstdint>

namespace Constants {
inline constexpr int g_defaultTraceDurationSeconds = 60;
inline constexpr int g_bitness32 = 32;
inline constexpr int g_bitness64 = 64;
inline constexpr int g_guidStringBufferChars = 64;
inline constexpr int g_jsonIndentWidth = 2;
inline constexpr int g_ipProtocolTcp = 6;
inline constexpr int g_ipProtocolUdp = 17;
inline constexpr int g_hostNameBufferChars = 256;
inline constexpr int g_sqliteBusyTimeoutMs = 5000;
inline constexpr int g_millisecondsPerSecond = 1000;
inline constexpr std::uint32_t g_invalidPid = 0xFFFFFFFFu;
inline constexpr std::size_t g_snakeCaseExtraCapacity = 8;
} // namespace Constants
