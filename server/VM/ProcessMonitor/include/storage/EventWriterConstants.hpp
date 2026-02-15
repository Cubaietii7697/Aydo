#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace EventWriterConstants {

inline constexpr int g_sqliteAutoLength = -1;
inline constexpr int g_sqliteIndexBase = 1;
inline constexpr int g_pragmaTableInfoNameColumnIndex = 1;

inline constexpr std::size_t g_flattenedFieldReserveSize = 256;
inline constexpr std::size_t g_searchScopeCapacity = 6;
inline constexpr std::uint16_t g_uint32ByteWidth = 4;
inline constexpr size_t g_bucketNames = 5;
inline constexpr std::array<const char *, g_bucketNames> g_eventBucketNames = {"props", "proc", "net", "dns", "file"};

inline constexpr int g_payloadBindEventRecordId = 1;
inline constexpr int g_payloadBindJsonText = 2;

inline constexpr int g_fieldBindEventRecordId = 1;
inline constexpr int g_fieldBindKey = 2;
inline constexpr int g_fieldBindValue = 3;
inline constexpr int g_fieldBindValueType = 4;

inline constexpr int g_findingBindEventTime = 1;
inline constexpr int g_findingBindType = 2;
inline constexpr int g_findingBindSeverity = 3;
inline constexpr int g_findingBindConfidence = 4;
inline constexpr int g_findingBindSourcePid = 5;
inline constexpr int g_findingBindTargetPid = 6;
inline constexpr int g_findingBindTid = 7;
inline constexpr int g_findingBindEvidenceJson = 8;

} // namespace EventWriterConstants
