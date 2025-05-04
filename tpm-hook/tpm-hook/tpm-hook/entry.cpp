// Made By OF
#include "global.h"
#include <ntddk.h>

void GenerateRandomData(char* buffer, size_t length)
{
    ULONG seed = (ULONG)KeQueryTimeIncrement();
    for (size_t i = 0; i < length; i++) {
        buffer[i] = (char)(RtlRandomEx(&seed) % 256);
    }
}

void SpoofTPMResponse(PIRP irp) {
    PVOID systemBuffer = irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer) {
        size_t length = irp->IoStatus.Information;
        if (length > 0) {
            GenerateRandomData((char*)systemBuffer, length);
        }
    }

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}

void MaintainHook(PDRIVER_OBJECT driverObject) {
    static PDRIVER_DISPATCH* functionBase = driverObject->MajorFunction;

    if (functionBase != driverObject->MajorFunction) {
        for (DWORD i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
            driverObject->MajorFunction[i] = &Hook::Dispatch;
        }
        Log("Dispatch re-hooked");
    }
}

EXTERN_C NTSTATUS Entry()
{
    Log("Entry at 0x%p", &Entry);

    NTSTATUS status = Utils::GenerateRandomKey(&Hook::generatedKey);
    if (!NT_SUCCESS(status))
    {
        Log("Failed to generate random key");
        return status;
    }

    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, L"\\Driver\\TPM");

    PDRIVER_OBJECT driverObject;
    status = Utils::ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, nullptr, 0,
        *Utils::IoDriverObjectType, KernelMode, nullptr,
        reinterpret_cast<PVOID*>(&driverObject));
    if (!NT_SUCCESS(status))
        return status;

    Log("Found tpm.sys DRIVER_OBJECT at 0x%p", driverObject);

    Hook::originalDispatch = driverObject->MajorFunction[0];

    for (DWORD i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        driverObject->MajorFunction[i] = &Hook::Dispatch;
    }

    Log("Dispatch hooked");
    Log("Made By OF");

    while (TRUE) {
        MaintainHook(driverObject);
    }

    return STATUS_SUCCESS;
}
