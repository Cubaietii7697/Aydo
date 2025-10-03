// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <libloaderapi.h>
#include <ostream>
#include <winternl.h>

#include "pch.h"

struct FunctionToPatch {
  const char *dllName;
  const char *functionName;
  void *newFunction;
  void **oldFunction;
};

static bool patchIAT(HMODULE hModule, const char *importDllName, const char *importFunctionName, void *newFunction, void **oldFunction) {
  // Get the base address of the module
  BYTE *base = reinterpret_cast<BYTE *>(hModule);

  // Get the DOS header and NT headers
  auto *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
  auto *ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(base + dosHeader->e_lfanew);

  // Get the import table
  auto importsDirectories = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!importsDirectories.Size) {
    return false;
  }

  // Get the import descriptor
  auto *imageImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(base + importsDirectories.VirtualAddress);

  for (; imageImportDescriptor->Name; ++imageImportDescriptor) {
    // If the CURRENT DLL name is not the one we're looking for, skip it
    auto *currentDllName = reinterpret_cast<LPSTR>(base + imageImportDescriptor->Name);
    if (_stricmp(currentDllName, importDllName) != 0) {
      continue;
    }

    // If it is, get the IAT and ILT
    auto *iat = reinterpret_cast<IMAGE_THUNK_DATA *>(base + imageImportDescriptor->FirstThunk);
    auto *ilt = reinterpret_cast<IMAGE_THUNK_DATA *>(base + imageImportDescriptor->OriginalFirstThunk);

    // If the ILT is null, use the IAT
    if (!ilt) {
      ilt = iat;
    }

    // For every function in the DLL
    for (; iat->u1.Function; ++iat, ++ilt) {
      if (!IMAGE_SNAP_BY_ORDINAL(ilt->u1.AddressOfData)) {
        // If the function is not an ordinal (nameless), get the import by name
        auto *importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(base + ilt->u1.AddressOfData);
        if (_stricmp(importByName->Name, importFunctionName) != 0) {
          continue;
        }

        // Get the old function
        void **iatSlot = reinterpret_cast<void **>(&iat->u1.Function);

        // Get the ability to change the IAT
        DWORD oldProtect;
        if (!VirtualProtect(iatSlot, sizeof(void *), PAGE_READWRITE, &oldProtect)) {
          return false;
        }

        // Save the old function
        if (oldFunction) {
          *oldFunction = *iatSlot;
        }

        // Replace the IAT with our new function
        *iatSlot = newFunction;

        // Remove our ability to change the IAT
        if (!VirtualProtect(iatSlot, sizeof(void *), oldProtect, &oldProtect)) {
          return false;
        }

        FlushInstructionCache(GetCurrentProcess(), iatSlot, sizeof(void *));

        return true;
      }
    }
  }

  return false;
}

typedef VOID(WINAPI *Sleep_t)(DWORD);
static Sleep_t oldSleepFunction = nullptr;

static VOID WINAPI newSleepFunction(DWORD dwMilliseconds) {
  // Do nothing
}

typedef NTSTATUS(NTAPI *NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
static NtDelayExecution_t oldNtDelayExecution = nullptr;

static NTSTATUS NTAPI newNtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER delayInterval) {
  UNREFERENCED_PARAMETER(alertable);

  // Do nothing

  return static_cast<NTSTATUS>(EXIT_SUCCESS);
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  static const FunctionToPatch functionsToPatch[] = {
      {
          "KERNEL32.dll",
          "Sleep",
          reinterpret_cast<void *>(newSleepFunction),
          reinterpret_cast<void **>(&oldSleepFunction),
      },
      {
          "ntdll.dll",
          "NtDelayExecution",
          reinterpret_cast<void *>(newNtDelayExecution),
          reinterpret_cast<void **>(&oldNtDelayExecution),
      },
  };

  if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    for (const auto &functionToPatch : functionsToPatch) {
      if (!patchIAT(GetModuleHandle(nullptr), functionToPatch.dllName, functionToPatch.functionName, functionToPatch.newFunction, functionToPatch.oldFunction)) {
        std::cout << "Failed to patch " << functionToPatch.dllName << ":" << functionToPatch.functionName << std::endl;
      }
    }
  }

  return TRUE;
}
