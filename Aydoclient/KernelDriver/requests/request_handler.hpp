#pragma once
#include "../pch.hpp"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

EXTERN_C_START
NTSTATUS Requests_HandleKill(ULONG pid);
EXTERN_C_END
