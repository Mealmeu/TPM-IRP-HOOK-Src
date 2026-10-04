// Made By OF
#include "global.h"
#include <ntddk.h>

// 100ms in 100-nanosecond intervals (negative = relative time)
#define MAINTAIN_HOOK_INTERVAL_MS 100
#define MAINTAIN_HOOK_INTERVAL (-(LONGLONG)(MAINTAIN_HOOK_INTERVAL_MS) * 10000LL)

void MaintainHook(PDRIVER_OBJECT driverObject) {
    static PDRIVER_DISPATCH savedDispatch = driverObject->MajorFunction[0];

    if (driverObject->MajorFunction[0] != &Hook::Dispatch) {
        for (DWORD i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
            driverObject->MajorFunction[i] = &Hook::Dispatch;
        }
        Log("Dispatch re-hooked");
    }
}

EXTERN_C NTSTATUS Entry()
{
    Log("Entry at 0x%p", &Entry);

    NTSTATUS status = Utils::LoadOrGenerateKey(&Hook::generatedKey);
    if (!NT_SUCCESS(status))
    {
        Log("Failed to load/generate EK");
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

    LARGE_INTEGER interval;
    interval.QuadPart = MAINTAIN_HOOK_INTERVAL;

    while (TRUE) {
        MaintainHook(driverObject);
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    return STATUS_SUCCESS;
}
