#include "driver.h"
#include "cr3_memory.h"

#include <intrin.h>

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);

static PDEVICE_OBJECT g_device = NULL;
static uint32_t g_session_key = 0;
static uint32_t g_message_count = 0;

static void SessionRotateKeyIfNeeded(void)
{
    if (++g_message_count < MM_KEY_ROTATE_INTERVAL)
        return;

    g_message_count = 0;
    g_session_key = MmRotateKey(g_session_key);
}

static void SessionReset(void)
{
    g_session_key = 0;
    g_message_count = 0;
}

static BOOLEAN SessionIsReady(void)
{
    return g_session_key != 0;
}

static void SessionDecrypt(void* buffer, size_t size)
{
    if (size > MM_MAX_READ)
        return;
    MmXorCrypt(buffer, size, g_session_key);
    SessionRotateKeyIfNeeded();
}

static void SessionEncrypt(void* buffer, size_t size)
{
    /* Never XOR a garbage length: METHOD_BUFFERED SystemBuffer is small, and
     * walking gigabytes of kernel VA (or MMIO) freezes a VirtualBox guest
     * with no bugcheck. Callers must pass the saved request size. */
    if (size == 0 || size > MM_MAX_READ)
        return;
    MmXorCrypt(buffer, size, g_session_key);
    SessionRotateKeyIfNeeded();
}

static NTSTATUS CompleteIrp(PIRP irp, NTSTATUS status, ULONG_PTR info)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS LookupLiveProcess(HANDLE pid, PEPROCESS* out_process)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    *out_process = NULL;

    if (!pid)
        return STATUS_INVALID_PARAMETER;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status) || !process)
        return STATUS_INVALID_PARAMETER;

    *out_process = process;
    return STATUS_SUCCESS;
}

static NTSTATUS ReadProcessMemorySafe(
    HANDLE pid,
    uint64_t address,
    PVOID buffer,
    uint32_t size)
{
    PEPROCESS process = NULL;
    NTSTATUS status = LookupLiveProcess(pid, &process);
    if (!NT_SUCCESS(status))
        return status;

    status = ReadMemoryByCR3(
        process,
        (PVOID)(ULONG_PTR)address,
        buffer,
        (SIZE_T)size);

    ObDereferenceObject(process);
    return status;
}

static NTSTATUS WriteProcessMemorySafe(
    HANDLE pid,
    uint64_t address,
    PVOID buffer,
    uint32_t size)
{
    PEPROCESS process = NULL;
    NTSTATUS status = LookupLiveProcess(pid, &process);
    if (!NT_SUCCESS(status))
        return status;

    status = WriteMemoryByCR3(
        process,
        (PVOID)(ULONG_PTR)address,
        buffer,
        (SIZE_T)size);

    ObDereferenceObject(process);
    return status;
}

NTSTATUS MmDispatchCreateClose(PDEVICE_OBJECT device_object, PIRP irp)
{
    UNREFERENCED_PARAMETER(device_object);
    return CompleteIrp(irp, STATUS_SUCCESS, 0);
}

NTSTATUS MmDispatchDeviceControl(PDEVICE_OBJECT device_object, PIRP irp)
{
    UNREFERENCED_PARAMETER(device_object);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buffer = irp->AssociatedIrp.SystemBuffer;

    switch (code) {
    case IOCTL_HANDSHAKE: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(uint32_t) ||
            stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(uint32_t) ||
            !buffer) {
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        g_session_key = *(uint32_t*)buffer;
        g_message_count = 0;
        *(uint32_t*)buffer = g_session_key ^ MM_XOR_MASK;
        return CompleteIrp(irp, STATUS_SUCCESS, sizeof(uint32_t));
    }

    case IOCTL_READ_MEMORY: {
        MEMORY_READ_REQUEST req;
        ULONG out_len;
        NTSTATUS status;

        if (!SessionIsReady())
            return CompleteIrp(irp, STATUS_ACCESS_DENIED, 0);

        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MEMORY_READ_REQUEST))
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);

        out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
        if (out_len == 0 || !buffer)
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);

        /*
         * METHOD_BUFFERED: SystemBuffer is input AND output. Decrypt a stack
         * copy, then copy user bytes into SystemBuffer. Using req->size after
         * the copy (old code) treated the first 16 payload bytes as the
         * request: test_read's 0xA0..0xAF pattern made size=0xAFAEADAC, and
         * SessionEncrypt XOR-walked ~2.9GB of kernel VA — guest clock freeze,
         * no bugcheck, IRP never completed.
         */
        RtlCopyMemory(&req, buffer, sizeof(req));
        SessionDecrypt(&req, sizeof(req));

        if (req.size == 0 || req.size > MM_MAX_READ)
            return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);

        if (req.size > out_len)
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);

        status = ReadProcessMemorySafe(
            (HANDLE)(ULONG_PTR)req.process_id,
            req.address,
            buffer,
            req.size);

        if (!NT_SUCCESS(status))
            return CompleteIrp(irp, status, 0);

        SessionEncrypt(buffer, req.size);
        return CompleteIrp(irp, STATUS_SUCCESS, req.size);
    }

    case IOCTL_WRITE_MEMORY: {
        MEMORY_WRITE_REQUEST req;
        NTSTATUS status;
        uint8_t* payload;
        SIZE_T expected;

        if (!SessionIsReady())
            return CompleteIrp(irp, STATUS_ACCESS_DENIED, 0);

        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MEMORY_WRITE_REQUEST) ||
            !buffer) {
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        RtlCopyMemory(&req, buffer, sizeof(req));
        SessionDecrypt(&req, sizeof(req));

        if (req.size == 0 || req.size > MM_MAX_WRITE)
            return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);

        expected = sizeof(MEMORY_WRITE_REQUEST) + req.size;
        if (stack->Parameters.DeviceIoControl.InputBufferLength < expected)
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);

        payload = (uint8_t*)buffer + sizeof(MEMORY_WRITE_REQUEST);
        SessionDecrypt(payload, req.size);

        status = WriteProcessMemorySafe(
            (HANDLE)(ULONG_PTR)req.process_id,
            req.address,
            payload,
            req.size);

        return CompleteIrp(irp, status, 0);
    }

    case IOCTL_PING: {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MEMORY_PING_RESPONSE) ||
            !buffer) {
            return CompleteIrp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }

        MEMORY_PING_RESPONSE* resp = (MEMORY_PING_RESPONSE*)buffer;
        resp->magic = MM_PING_MAGIC;
        resp->version = 2;
        return CompleteIrp(irp, STATUS_SUCCESS, sizeof(MEMORY_PING_RESPONSE));
    }

    default:
        return CompleteIrp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
}

VOID DriverUnload(PDRIVER_OBJECT driver_object)
{
    DbgPrint("[MyMemoryDriver] DriverUnload\n");

    UNICODE_STRING sym = RTL_CONSTANT_STRING(SYM_LINK_NAME);
    IoDeleteSymbolicLink(&sym);

    if (g_device)
        IoDeleteDevice(g_device);

    SessionReset();
    UNREFERENCED_PARAMETER(driver_object);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);

    UNICODE_STRING dev = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING sym = RTL_CONSTANT_STRING(SYM_LINK_NAME);

    NTSTATUS status = IoCreateDevice(
        driver_object,
        0,
        &dev,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_device);

    if (!NT_SUCCESS(status))
        return status;

    status = IoCreateSymbolicLink(&sym, &dev);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device);
        g_device = NULL;
        return status;
    }

    driver_object->MajorFunction[IRP_MJ_CREATE] = MmDispatchCreateClose;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = MmDispatchCreateClose;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MmDispatchDeviceControl;
    driver_object->DriverUnload = DriverUnload;

    g_device->Flags |= DO_BUFFERED_IO;
    g_device->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[MyMemoryDriver] DriverEntry ok device=%wZ symlink=%wZ\n", &dev, &sym);
    return STATUS_SUCCESS;
}
