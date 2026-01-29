#pragma once

#include <ntifs.h>

namespace Constants {
static WCHAR FILE_PROTECTION_PORT_NAME[] = L"\\AydoFPPort";
static WCHAR FILE_PROTECTION_ALTITUDE[] = L"320000";

static const WCHAR *PROTECTED_DIRECTORIES[] = {L"\\Users\\KAN12\\Desktop\\Aydo"};

static const WCHAR CORE_DEVICE_NAME[] = L"\\Device\\AydoDriver";

// Protected directory constants (when creating the install should prolly change this too)
static const WCHAR PROTECTED_DIR_1[] = L"\\Users\\KAN12\\Desktop\\Aydo";
static const WCHAR PROTECTED_DIR_2[] = L"\\Users\\KAN12\\Documents\\Aydo";

static const WCHAR AYDO_PORT_NAME[] = L"\\AydoFilterPort";
static const ULONG AYDO_MAX_QUEUE_DEPTH = 128;
static const ULONG AYDO_SCAN_TIMEOUT = 30000;

static const ULONG AYDO_POOL_TAG_CONTEXT = 'CdyA';
static const ULONG AYDO_POOL_TAG_STRING = 'SdyA';
static const ULONG AYDO_POOL_TAG_BUFFER = 'BdyA';
static const ULONG AYDO_POOL_TAG_GENERIC = 'GdyA';

static const ULONG AYDO_CONTEXT_MAGIC = 0x67676767;

} // namespace Constants