#pragma once

#include <ntdef.h>

// getting these shitty constants to work was a pain in the ass
namespace Constants {
static const WCHAR DEVICE_NAME[] = L"\\Device\\AydoDriver";
static const WCHAR SYMLINK_NAME[] = L"\\??\\AydoDriver";
} // namespace Constants