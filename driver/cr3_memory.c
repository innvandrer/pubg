#include "cr3_memory.h"
#include "driver.h"

/*
 * Never __writecr3 here. A CR3 switch at DISPATCH (or in VirtualBox even at
 * PASSIVE) can freeze the guest with no bugcheck. Ping never took that path,
 * which is why ping succeeded while test_read hung the whole VM.
 *
 * Copy rules:
 *  - PASSIVE_LEVEL only (ProbeForRead / MmCopyVirtualMemory may fault).
 *  - Same-process: ProbeForRead + RtlCopyMemory in the calling context.
 *  - Other process: MmCopyVirtualMemory with a live EPROCESS. No page-walk
 *    retry loop, no physical map of guest RAM (MMIO hang).
 */
NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS FromProcess,
    PVOID FromAddress,
    PEPROCESS ToProcess,
    PVOID ToAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T NumberOfBytesCopied);

NTKERNELAPI NTSTATUS PsGetProcessExitStatus(PEPROCESS Process);

ULONG Cr3GetDirectoryTableBaseOffset(void)
{
    return EPROCESS_DIRECTORY_TABLE_BASE_OFFSET;
}

static BOOLEAN Cr3IsValidUserRange(PVOID address, SIZE_T size)
{
    const ULONG_PTR start = (ULONG_PTR)address;
    ULONG_PTR end;

    if (!address || size == 0 || size > MM_MAX_READ)
        return FALSE;

    if (start < 0x10000 || start > 0x00007FFFFFFFFFFFULL)
        return FALSE;

    end = start + size - 1;
    if (end < start || end > 0x00007FFFFFFFFFFFULL)
        return FALSE;

    return TRUE;
}

static BOOLEAN Cr3HasValidDirectoryTableBase(PEPROCESS process)
{
    ULONG_PTR dtb;

    if (!process)
        return FALSE;

    dtb = *(PULONG_PTR)((PUCHAR)process + Cr3GetDirectoryTableBaseOffset());
    /* Bits 12+ are the PML4 physical page; 0 means no valid user page tables. */
    return (dtb & ~0xFFFULL) != 0;
}

static NTSTATUS Cr3PrepareCopy(PEPROCESS process, PVOID address, SIZE_T size)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    if (!process || !address || size == 0 || size > MM_MAX_READ)
        return STATUS_INVALID_PARAMETER;

    if (!Cr3IsValidUserRange(address, size))
        return STATUS_INVALID_PARAMETER;

    if (PsGetProcessExitStatus(process) != STATUS_PENDING)
        return STATUS_PROCESS_IS_TERMINATING;

    if (!Cr3HasValidDirectoryTableBase(process))
        return STATUS_INVALID_PARAMETER;

    return STATUS_SUCCESS;
}

NTSTATUS ReadMemoryByCR3(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size)
{
    SIZE_T copied = 0;
    NTSTATUS status = Cr3PrepareCopy(process, address, size);

    if (!NT_SUCCESS(status))
        return status;

    /* Calling process: no attach, no CR3 switch. */
    if (process == PsGetCurrentProcess()) {
        __try {
            ProbeForRead(address, size, 1);
            RtlCopyMemory(buffer, address, size);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
        return STATUS_SUCCESS;
    }

    DbgPrint("[MyMemoryDriver] MmCopyVirtualMemory read proc=%p addr=%p size=%Iu\n",
             process, address, size);

    __try {
        status = MmCopyVirtualMemory(
            process,
            address,
            PsGetCurrentProcess(),
            buffer,
            size,
            KernelMode,
            &copied);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (!NT_SUCCESS(status))
        return status;
    if (copied != size)
        return STATUS_PARTIAL_COPY;
    return STATUS_SUCCESS;
}

NTSTATUS WriteMemoryByCR3(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size)
{
    SIZE_T copied = 0;
    NTSTATUS status = Cr3PrepareCopy(process, address, size);

    if (!NT_SUCCESS(status))
        return status;

    if (process == PsGetCurrentProcess()) {
        __try {
            ProbeForWrite(address, size, 1);
            RtlCopyMemory(address, buffer, size);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
        return STATUS_SUCCESS;
    }

    DbgPrint("[MyMemoryDriver] MmCopyVirtualMemory write proc=%p addr=%p size=%Iu\n",
             process, address, size);

    __try {
        status = MmCopyVirtualMemory(
            PsGetCurrentProcess(),
            buffer,
            process,
            address,
            size,
            KernelMode,
            &copied);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (!NT_SUCCESS(status))
        return status;
    if (copied != size)
        return STATUS_PARTIAL_COPY;
    return STATUS_SUCCESS;
}
