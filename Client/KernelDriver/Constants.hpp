#pragma once

#include <ntdef.h>

// getting these shitty constants to work was a pain in the ass
namespace Constants {
static const WCHAR DEVICE_NAME[] = L"\\Device\\AydoDriver";
static const WCHAR SYMLINK_NAME[] = L"\\??\\AydoDriver";

static const char *EXPECTED_SERVICE_IMAGE = "Service.exe";

// Minifilter driver service name
static const WCHAR MINIFILTER_DRIVER_NAME[] = L"DK";

// Altitude is basically priority for object callbacks
static const WCHAR ALTITUDE[] = L"320000";

static const WCHAR *PROTECTED_REGISTRY_PATHS[] = {
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\KD2",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AYDS",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DK",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\KD2",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\AYDS",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\DK"};

static const WCHAR *PROTECTED_SERVICE_NAMES[] = {L"KD2", L"AYDS",
                                                 L"DK"};
static const WCHAR PROTECTED_PATH[] = L"C:\\Users\\KAN12\\Desktop\\Aydo";
} // namespace Constants