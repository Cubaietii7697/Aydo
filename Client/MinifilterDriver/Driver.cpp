#include "FileProtection.hpp"

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT driverObject,
    PUNICODE_STRING registryPath) {
    
    return FileProtection::initialize(driverObject, registryPath);
}