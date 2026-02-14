#pragma once

#include <ntifs.h>

namespace Constants {
static WCHAR MINIFILTER_PORT_NAME[] = L"\\AydoFilterPort";
static WCHAR FILE_PROTECTION_ALTITUDE[] = L"320000";

static const WCHAR *PROTECTED_DIRECTORIES[] = {L"\\Users\\KAN12\\Desktop\\Aydo"};

static const WCHAR CORE_DEVICE_NAME[] = L"\\Device\\AydoDriver";

// Protected directory constants
static const WCHAR PROTECTED_DIR_1[] = L"\\Users\\KAN12\\Desktop\\Aydo";
static const WCHAR PROTECTED_DIR_2[] = L"\\Users\\KAN12\\Documents\\Aydo";
static const WCHAR PROTECTED_PATH[] = L"\\Device\\HarddiskVolume3\\Users\\KAN12\\Desktop\\Aydo\\";

static const WCHAR AYDO_PORT_NAME[] = L"\\AydoFilterPort";
static const ULONG AYDO_MAX_QUEUE_DEPTH = 128;
static const ULONG AYDO_SCAN_TIMEOUT = 30000;
static const ULONG AYDO_MESSAGE_TIMEOUT = 1000;

// Security configuration
static const BOOLEAN AYDO_FAIL_SECURE = FALSE;    // Set to TRUE for fail-secure mode (block on scan failures)
static const BOOLEAN AYDO_PAUSE_PROCESSES = TRUE; // Set to TRUE to pause processes during scanning

static const ULONG AYDO_POOL_TAG_CONTEXT = 'CdyA';
static const ULONG AYDO_POOL_TAG_STRING = 'SdyA';
static const ULONG AYDO_POOL_TAG_BUFFER = 'BdyA';
static const ULONG AYDO_POOL_TAG_GENERIC = 'GdyA';

static const unsigned int PROTECTED_PATH_BUFFER_CHARS = 1024;
static const ULONG PROTECTED_POOL_TAG = 'tPrF';

static const ULONG AYDO_CONTEXT_MAGIC = 0x67676767; // six sevennnn

static const unsigned int MAX_PATH = 512;
static const unsigned int MAX_LOG_SIZE_DEFAULT = 512;

} // namespace Constants