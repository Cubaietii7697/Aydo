// pch.h
#pragma once

// clang-format off
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Winsock2 must be before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>

// Now Windows
#include <windows.h>

// ETW / WMI / Trace
#include <evntrace.h>
#include <tdh.h>
#include <wmistr.h>
#include <evntprov.h>

// C/C++ basics last
#include <cstdint>
#include <string>
#include <vector>
// clang-format on
