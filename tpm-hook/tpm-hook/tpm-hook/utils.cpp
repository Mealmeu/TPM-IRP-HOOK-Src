#include "global.h"

char* Utils::Compare(const char* haystack, const char* needle)
{
	do
	{
		const char* h = haystack;
		const char* n = needle;
		while (tolower(static_cast<unsigned char>(*h)) == tolower(static_cast<unsigned char>(*n)) && *n)
		{
			h++;
			n++;
		}

		if (*n == 0)
			return const_cast<char*>(haystack);
	} while (*haystack++);
	return nullptr;
}

PVOID Utils::GetModuleBase(const char* moduleName)
{
	PVOID address = nullptr;
	ULONG size = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return nullptr;

#pragma warning(disable : 4996)
	PSYSTEM_MODULE_INFORMATION moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, size));
	if (!moduleList)
		return nullptr;

	status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
	if (!NT_SUCCESS(status))
		goto end;

	for (ULONG_PTR i = 0; i < moduleList->ulModuleCount; i++)
	{
		ULONG64 pointer = reinterpret_cast<ULONG64>(&moduleList->Modules[i]);
		pointer += sizeof(SYSTEM_MODULE);
		if (pointer > (reinterpret_cast<ULONG64>(moduleList) + size))
			break;

		SYSTEM_MODULE module = moduleList->Modules[i];
		module.ImageName[255] = '\0';
		if (Compare(module.ImageName, moduleName))
		{
			address = module.Base;
			break;
		}
	}

end:
	ExFreePool(moduleList);
	return address;
}

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))
ULONG64 Utils::FindPattern(void* baseAddress, ULONG64 size, const char* pattern)
{
	BYTE* firstMatch = nullptr;
	const char* currentPattern = pattern;

	BYTE* start = static_cast<BYTE*>(baseAddress);
	BYTE* end = start + size;

	for (BYTE* current = start; current < end; current++)
	{
		BYTE byte = currentPattern[0]; if (!byte) return reinterpret_cast<ULONG64>(firstMatch);
		if (byte == '\?' || *static_cast<BYTE*>(current) == GET_BYTE(byte, currentPattern[1]))
		{
			if (!firstMatch) firstMatch = current;
			if (!currentPattern[2]) return reinterpret_cast<ULONG64>(firstMatch);
			((byte == '\?') ? (currentPattern += 2) : (currentPattern += 3));
		}
		else
		{
			currentPattern = pattern;
			firstMatch = nullptr;
		}
	}

	return 0;
}

ULONG64 Utils::FindPatternImage(void* base, const char* pattern)
{
	ULONG64 match = 0;

	PIMAGE_NT_HEADERS64 headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (USHORT i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, ".text", 5) == 0 || *reinterpret_cast<DWORD32*>(section->Name) == 'EGAP')
		{
			match = FindPattern(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(base) + section->VirtualAddress), section->Misc.VirtualSize, pattern);
			if (match)
				break;
		}
	}

	return match;
}

SIZE_T Utils::MemoryCopySafe(void* destination, void* source, SIZE_T size)
{
	MM_COPY_ADDRESS address;
	address.VirtualAddress = source;
	SIZE_T copied;
	MmCopyMemory(destination, address, size, MM_COPY_MEMORY_VIRTUAL, &copied);
	return copied;
}

SIZE_T Utils::GetFunctionSize(ULONG64 function)
{
	constexpr SIZE_T sizeToCheck = 2000;
	PBYTE buffer = static_cast<PBYTE>(ExAllocatePool(NonPagedPool, sizeToCheck));
	if (!buffer)
		return 0;

	MemoryCopySafe(buffer, reinterpret_cast<void*>(function), sizeToCheck);

	for (SIZE_T i = 0; i < sizeToCheck; i++)
	{
		BYTE current = buffer[i];
		if (current == 0xC3)
		{
			ExFreePool(buffer);
			return i;
		}
	}

	ExFreePool(buffer);
	return 0;
}

bool Utils::IsInRange(ULONG64 start, SIZE_T size, ULONG64 input)
{
	return (input > start && input < start + size);
}

void Utils::ChangeIoc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine)
{
	PIOC_REQUEST request = static_cast<PIOC_REQUEST>(ExAllocatePool(NonPagedPool, sizeof(IOC_REQUEST)));

	request->Buffer = irp->AssociatedIrp.SystemBuffer;
	request->Size = ioc->Parameters.DeviceIoControl.OutputBufferLength;
	request->OriginalContext = ioc->Context;
	request->Original = ioc->CompletionRoutine;

	ioc->Control = SL_INVOKE_ON_SUCCESS;
	ioc->Context = request;
	ioc->CompletionRoutine = routine;
}

UINT32 Utils::BigEndianToLittleEndian32(UINT32 bigEndianValue)
{
	return ((bigEndianValue >> 24) & 0x000000FF) |
		((bigEndianValue >> 8) & 0x0000FF00) |
		((bigEndianValue << 8) & 0x00FF0000) |
		((bigEndianValue << 24) & 0xFF000000);
}

USHORT Utils::BigEndianToLittleEndian16(USHORT bigEndianValue)
{
	return ((bigEndianValue >> 8) & 0x00FF) |
		((bigEndianValue << 8) & 0xFF00);
}

void Utils::Randomize(void* buffer, SIZE_T size)
{
    BCryptGenRandom(nullptr, static_cast<PUCHAR>(buffer), static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

BCRYPT_KEY_HANDLE g_ekPrivKey = nullptr;

NTSTATUS Utils::GenerateRandomKey(TPM2B_PUBLIC_KEY_RSA* inputKey)
{
	BCRYPT_ALG_HANDLE algorithm = nullptr;
	BCRYPT_KEY_HANDLE keyHandle = nullptr;
	PUCHAR keyBlob = nullptr;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = BCryptGenerateKeyPair(algorithm, &keyHandle, 2048, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = BCryptFinalizeKeyPair(keyHandle, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	DWORD keyBlobLength = 0;
	status = BCryptExportKey(keyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &keyBlobLength, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	keyBlob = static_cast<PUCHAR>(ExAllocatePool(NonPagedPool, keyBlobLength));
	if (!keyBlob)
	{
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	status = BCryptExportKey(keyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB, keyBlob, keyBlobLength, &keyBlobLength, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	memcpy(inputKey->buffer, keyBlob, keyBlobLength);
	inputKey->size = static_cast<UINT16>(keyBlobLength);

Cleanup:
	if (keyBlob)
		ExFreePool(keyBlob);

	if (keyHandle)
		BCryptDestroyKey(keyHandle);

	if (algorithm)
		BCryptCloseAlgorithmProvider(algorithm, 0);

	return status;
}

static const WCHAR EK_REG_PATH[] =
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TPM\\Parameters";
static const WCHAR EK_VALUE[]    = L"EKBlob";

NTSTATUS Utils::LoadOrGenerateKey(TPM2B_PUBLIC_KEY_RSA* pubKey)
{
    BCRYPT_ALG_HANDLE hAlg  = nullptr;
    BCRYPT_KEY_HANDLE hKey  = nullptr;
    PUCHAR            blob  = nullptr;
    ULONG             blobLen = 0;
    HANDLE            hReg  = nullptr;
    NTSTATUS          status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    {
        UNICODE_STRING regPath;
        RtlInitUnicodeString(&regPath, EK_REG_PATH);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &regPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

        if (NT_SUCCESS(ZwOpenKey(&hReg, KEY_READ | KEY_WRITE, &oa))) {
            UNICODE_STRING valName;
            RtlInitUnicodeString(&valName, EK_VALUE);

            ULONG infoLen = 0;
            ZwQueryValueKey(hReg, &valName, KeyValuePartialInformation,
                nullptr, 0, &infoLen);

            if (infoLen > sizeof(KEY_VALUE_PARTIAL_INFORMATION)) {
                PKEY_VALUE_PARTIAL_INFORMATION info =
                    static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(
                        ExAllocatePoolWithTag(NonPagedPool, infoLen, 'pmTE'));
                if (info) {
                    if (NT_SUCCESS(ZwQueryValueKey(hReg, &valName,
                            KeyValuePartialInformation, info, infoLen, &infoLen))
                        && info->Type == REG_BINARY
                        && info->DataLength >= sizeof(BCRYPT_RSAKEY_BLOB)) {
                        if (NT_SUCCESS(BCryptImportKeyPair(hAlg, nullptr,
                                BCRYPT_RSAFULLPRIVATE_BLOB,
                                &hKey, info->Data, info->DataLength, 0))) {
                            Log("EK: loaded from registry");
                        }
                    }
                    ExFreePoolWithTag(info, 'pmTE');
                }
            }
        }
    }

    if (!hKey) {
        status = BCryptGenerateKeyPair(hAlg, &hKey, 2048, 0);
        if (!NT_SUCCESS(status)) goto Cleanup;
        status = BCryptFinalizeKeyPair(hKey, 0);
        if (!NT_SUCCESS(status)) goto Cleanup;

        status = BCryptExportKey(hKey, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB,
            nullptr, 0, &blobLen, 0);
        if (NT_SUCCESS(status) && blobLen > 0) {
            blob = static_cast<PUCHAR>(
                ExAllocatePoolWithTag(NonPagedPool, blobLen, 'pmTE'));
            if (blob && NT_SUCCESS(BCryptExportKey(hKey, nullptr,
                    BCRYPT_RSAFULLPRIVATE_BLOB, blob, blobLen, &blobLen, 0))) {
                if (!hReg) {
                    UNICODE_STRING regPath;
                    RtlInitUnicodeString(&regPath, EK_REG_PATH);
                    OBJECT_ATTRIBUTES oa2;
                    InitializeObjectAttributes(&oa2, &regPath,
                        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
                    ULONG disp = 0;
                    ZwCreateKey(&hReg, KEY_WRITE, &oa2, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, &disp);
                }
                if (hReg) {
                    UNICODE_STRING valName;
                    RtlInitUnicodeString(&valName, EK_VALUE);
                    ZwSetValueKey(hReg, &valName, 0, REG_BINARY, blob, blobLen);
                }
                Log("EK: generated and persisted to registry");
            }
            if (blob) { ExFreePoolWithTag(blob, 'pmTE'); blob = nullptr; }
        }
        blobLen = 0;
    }

    status = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB,
        nullptr, 0, &blobLen, 0);
    if (!NT_SUCCESS(status) || blobLen == 0 || blobLen > sizeof(pubKey->buffer))
        goto Cleanup;

    blob = static_cast<PUCHAR>(
        ExAllocatePoolWithTag(NonPagedPool, blobLen, 'pmTE'));
    if (!blob) { status = STATUS_NO_MEMORY; goto Cleanup; }

    status = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB,
        blob, blobLen, &blobLen, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    RtlCopyMemory(pubKey->buffer, blob, blobLen);
    pubKey->size = static_cast<UINT16>(blobLen);
    ExFreePoolWithTag(blob, 'pmTE'); blob = nullptr;

    if (g_ekPrivKey) BCryptDestroyKey(g_ekPrivKey);
    g_ekPrivKey = hKey;
    hKey = nullptr;

Cleanup:
    if (blob)  ExFreePoolWithTag(blob, 'pmTE');
    if (hKey)  BCryptDestroyKey(hKey);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hReg)  ZwClose(hReg);
    return status;
}
