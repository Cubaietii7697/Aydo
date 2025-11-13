#pragma once

#include <ntifs.h>

namespace Validation {

template <typename T>
NTSTATUS validateInputBuffer(PIRP Irp, T **outBuffer) {
  PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
  ULONG inputSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;

  if (inputSize < sizeof(T)) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  T *buffer = (T *)Irp->AssociatedIrp.SystemBuffer;
  if (buffer == nullptr) {
    return STATUS_INVALID_PARAMETER;
  }

  *outBuffer = buffer;

  return STATUS_SUCCESS;
}

template <typename T>
NTSTATUS validateOutputBuffer(PIRP Irp, T **outBuffer) {
  PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
  ULONG outputSize = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

  if (outputSize < sizeof(T)) {
    return STATUS_BUFFER_TOO_SMALL;
  }

  T *buffer = (T *)Irp->AssociatedIrp.SystemBuffer;
  if (buffer == nullptr) {
    return STATUS_INVALID_PARAMETER;
  }

  *outBuffer = buffer;

  return STATUS_SUCCESS;
}
} // namespace Validation
