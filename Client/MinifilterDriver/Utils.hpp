#include <ntifs.h>
#include <fltKernel.h>

namespace FileProtection {
// Forward declarations or include header
struct FileContext;
struct ScanRequest;
struct ScanResponse;
typedef struct FileContext *PFileContext;
typedef struct ScanRequest *PScanRequest;
typedef struct ScanResponse *PScanResponse;

} // namespace FileProtection

#include "FileProtection.hpp"

namespace FileProtection {

BOOLEAN isProtectedPath(PUNICODE_STRING filePath);
BOOLEAN isProtectedProcess();
NTSTATUS connectToCoreDriver();
NTSTATUS getProtectedPID();
BOOLEAN isExecutable(PUNICODE_STRING extension);

} // namespace FileProtection
