#include "global.h"

#define FILE_DEVICE_TPM         0x00000101
#define IOCTL_TPM_QUERY_CAPS    CTL_CODE(FILE_DEVICE_TPM, 0x0001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TPM_SEND_CMD      CTL_CODE(FILE_DEVICE_TPM, 0x0002, METHOD_BUFFERED, FILE_ANY_ACCESS)

// TPM2 command/response wire layout (all big-endian on wire)
#pragma pack(push, 1)
typedef struct { UINT16 tag; UINT32 size; UINT32 code; } TPM2_CMD_HDR;
typedef struct { UINT16 tag; UINT32 size; UINT32 rc; }   TPM2_RSP_HDR;
#pragma pack(pop)

static UINT32 SwapU32(UINT32 v) {
    return ((v >> 24) & 0xFF) | ((v >> 8) & 0xFF00) |
           ((v << 8) & 0xFF0000) | ((v << 24) & 0xFF000000);
}
static UINT16 SwapU16(UINT16 v) { return (v >> 8) | (v << 8); }

static ULONG BuildSuccessRsp(PBYTE buf, ULONG bufMax, ULONG payloadSz)
{
    ULONG total = sizeof(TPM2_RSP_HDR) + payloadSz;
    if (total > bufMax) return 0;
    TPM2_RSP_HDR* h = reinterpret_cast<TPM2_RSP_HDR*>(buf);
    h->tag  = SwapU16(TPM_ST_NO_SESSIONS);
    h->size = SwapU32(total);
    h->rc   = 0;
    return total;
}

static NTSTATUS HandleGetRandom(PIRP irp, PIO_STACK_LOCATION ioc)
{
    ULONG outLen = ioc->Parameters.DeviceIoControl.OutputBufferLength;
    PBYTE buf = static_cast<PBYTE>(irp->AssociatedIrp.SystemBuffer);
    if (!buf || outLen < sizeof(TPM2_RSP_HDR) + 2) goto fail;

    UINT16 requested = 32;
    ULONG inLen = ioc->Parameters.DeviceIoControl.InputBufferLength;
    if (inLen >= sizeof(TPM2_CMD_HDR) + 2) {
        PBYTE cmd = static_cast<PBYTE>(irp->AssociatedIrp.SystemBuffer);
        UINT16 raw; RtlCopyMemory(&raw, cmd + sizeof(TPM2_CMD_HDR), 2);
        requested = SwapU16(raw);
    }
    if (requested > 64) requested = 64;

    {
        ULONG payloadSz = 2 + requested;
        if (outLen < sizeof(TPM2_RSP_HDR) + payloadSz) goto fail;

        PBYTE payload = buf + sizeof(TPM2_RSP_HDR);
        UINT16 sizeField = SwapU16(requested);
        RtlCopyMemory(payload, &sizeField, 2);
        Utils::Randomize(payload + 2, requested);

        ULONG written = BuildSuccessRsp(buf, outLen, payloadSz);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = written;
        IofCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
fail:
    irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
    irp->IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_BUFFER_TOO_SMALL;
}

static NTSTATUS HandleGetCapability(PIRP irp, PIO_STACK_LOCATION ioc)
{
    ULONG outLen = ioc->Parameters.DeviceIoControl.OutputBufferLength;
    PBYTE buf = static_cast<PBYTE>(irp->AssociatedIrp.SystemBuffer);
    if (!buf) goto fail;

    {
        TPMS_TAGGED_PROPERTY props[] = {
            { SwapU32(TPM_PT_FAMILY_INDICATOR), SwapU32(0x322E3000) },
            { SwapU32(TPM_PT_LEVEL),            0 },
            { SwapU32(TPM_PT_REVISION),         SwapU32(138) },
            { SwapU32(TPM_PT_MANUFACTURER),     SwapU32(0x494E5443) },
            { SwapU32(TPM_PT_FIRMWARE_VERSION_1), SwapU32(0x00070003) },
            { SwapU32(TPM_PT_FIRMWARE_VERSION_2), SwapU32(0x00050003) },
        };
        UINT32 count = sizeof(props) / sizeof(props[0]);
        ULONG capDataSz = 1 + 4 + 4 + count * sizeof(TPMS_TAGGED_PROPERTY);
        ULONG total = sizeof(TPM2_RSP_HDR) + capDataSz;
        if (outLen < total) goto fail;

        PBYTE p = buf + sizeof(TPM2_RSP_HDR);
        *p++ = 0;
        UINT32 cap = SwapU32(TPM_CAP_TPM_PROPERTIES);
        RtlCopyMemory(p, &cap, 4); p += 4;
        UINT32 cnt = SwapU32(count);
        RtlCopyMemory(p, &cnt, 4); p += 4;
        RtlCopyMemory(p, props, count * sizeof(TPMS_TAGGED_PROPERTY));

        BuildSuccessRsp(buf, outLen, capDataSz);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = total;
        IofCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
fail:
    irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
    irp->IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_BUFFER_TOO_SMALL;
}

static UINT16 GetHashSize(UINT16 algBE)
{
    switch (SwapU16(algBE)) {
    case 0x0004: return SHA1_DIGEST_SIZE;
    case 0x000B: return SHA256_DIGEST_SIZE;
    case 0x000C: return SHA384_DIGEST_SIZE;
    case 0x000D: return SHA512_DIGEST_SIZE;
    default:     return SHA256_DIGEST_SIZE;
    }
}

static NTSTATUS HandlePCRRead(PIRP irp, PIO_STACK_LOCATION ioc)
{
    ULONG outLen = ioc->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG inLen  = ioc->Parameters.DeviceIoControl.InputBufferLength;
    PBYTE buf    = static_cast<PBYTE>(irp->AssociatedIrp.SystemBuffer);
    if (!buf) goto fail;

    BYTE cmd[512] = {};
    ULONG cpLen = inLen < sizeof(cmd) ? inLen : sizeof(cmd);
    RtlCopyMemory(cmd, buf, cpLen);

    if (cpLen < sizeof(TPM2_CMD_HDR) + 4) goto fail;

    {
        PBYTE p   = cmd + sizeof(TPM2_CMD_HDR);
        PBYTE end = cmd + cpLen;

        if (p + 4 > end) goto fail;
        UINT32 selCount; RtlCopyMemory(&selCount, p, 4); p += 4;
        selCount = SwapU32(selCount);
        if (selCount > 8) selCount = 8;

        struct BankSel { UINT16 hash; UINT8 szSel; BYTE sel[4]; } banks[8] = {};
        UINT32 nBanks = 0;
        for (UINT32 i = 0; i < selCount; i++) {
            if (p + 3 > end) break;
            UINT16 h; RtlCopyMemory(&h, p, 2); p += 2;
            UINT8  s = *p++; if (s > 4) s = 4;
            if (p + s > end) break;
            banks[nBanks].hash  = h;
            banks[nBanks].szSel = s;
            RtlCopyMemory(banks[nBanks].sel, p, s);
            p += s;
            nBanks++;
        }

        UINT32 total = 0;
        for (UINT32 i = 0; i < nBanks && total < 8; i++)
            for (UINT8 b = 0; b < banks[i].szSel && total < 8; b++)
                for (int bit = 0; bit < 8 && total < 8; bit++)
                    if (banks[i].sel[b] & (1u << bit)) total++;

        PBYTE rp = buf + sizeof(TPM2_RSP_HDR);

        UINT32 ctr = SwapU32(1); RtlCopyMemory(rp, &ctr, 4); rp += 4;

        UINT32 nb = SwapU32(nBanks); RtlCopyMemory(rp, &nb, 4); rp += 4;
        for (UINT32 i = 0; i < nBanks; i++) {
            RtlCopyMemory(rp, &banks[i].hash, 2); rp += 2;
            *rp++ = banks[i].szSel;
            RtlCopyMemory(rp, banks[i].sel, banks[i].szSel); rp += banks[i].szSel;
        }

        UINT32 dc = SwapU32(total); RtlCopyMemory(rp, &dc, 4); rp += 4;
        for (UINT32 i = 0; i < nBanks; i++) {
            UINT16 dsz = GetHashSize(banks[i].hash);
            for (UINT8 b = 0; b < banks[i].szSel; b++) {
                for (int bit = 0; bit < 8; bit++) {
                    if (!(banks[i].sel[b] & (1u << bit))) continue;
                    UINT16 dszBE = SwapU16(dsz);
                    if ((ULONG)(rp + 2 + dsz - buf) > outLen) goto fail;
                    RtlCopyMemory(rp, &dszBE, 2); rp += 2;
                    RtlZeroMemory(rp, dsz);       rp += dsz;
                }
            }
        }

        ULONG payloadSz = (ULONG)(rp - (buf + sizeof(TPM2_RSP_HDR)));
        ULONG written = BuildSuccessRsp(buf, outLen, payloadSz);
        if (!written) goto fail;

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = written;
        IofCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
fail:
    irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
    irp->IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_BUFFER_TOO_SMALL;
}

static NTSTATUS HandlePCRMutate(PIRP irp, PIO_STACK_LOCATION ioc)
{
    ULONG outLen = ioc->Parameters.DeviceIoControl.OutputBufferLength;
    PBYTE buf    = static_cast<PBYTE>(irp->AssociatedIrp.SystemBuffer);
    if (!buf) goto fail;

    {
        UINT16 cmdTagBE = 0;
        if (ioc->Parameters.DeviceIoControl.InputBufferLength >= 2)
            RtlCopyMemory(&cmdTagBE, buf, 2);
        bool hasSessions = (SwapU16(cmdTagBE) == (UINT16)TPM_ST_SESSIONS);

        ULONG payloadSz = hasSessions ? 4 : 0;
        ULONG total = sizeof(TPM2_RSP_HDR) + payloadSz;
        if (outLen < total) goto fail;

        TPM2_RSP_HDR* h = reinterpret_cast<TPM2_RSP_HDR*>(buf);
        h->tag  = hasSessions ? SwapU16((UINT16)TPM_ST_SESSIONS)
                              : SwapU16((UINT16)TPM_ST_NO_SESSIONS);
        h->size = SwapU32(total);
        h->rc   = 0;
        if (hasSessions) {
            UINT32 zero = 0;
            RtlCopyMemory(buf + sizeof(TPM2_RSP_HDR), &zero, 4);
        }

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = total;
        IofCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
fail:
    irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
    irp->IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_BUFFER_TOO_SMALL;
}

static NTSTATUS HandleReadPublic(PIRP irp, PIO_STACK_LOCATION ioc)
{
    ULONG outLen = ioc->Parameters.DeviceIoControl.OutputBufferLength;
    PBYTE buf = static_cast<PBYTE>(irp->AssociatedIrp.SystemBuffer);
    if (!buf || Hook::generatedKey.size == 0) goto passthrough;

    {
        ULONG keyPayloadSz = 2 + Hook::generatedKey.size;
        ULONG total = sizeof(TPM2_RSP_HDR) + keyPayloadSz;
        if (outLen < total) goto passthrough;

        PBYTE p = buf + sizeof(TPM2_RSP_HDR);
        UINT16 keySz = SwapU16(Hook::generatedKey.size);
        RtlCopyMemory(p, &keySz, 2); p += 2;
        RtlCopyMemory(p, Hook::generatedKey.buffer, Hook::generatedKey.size);

        BuildSuccessRsp(buf, outLen, keyPayloadSz);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = total;
        IofCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
passthrough:
    return Hook::originalDispatch(ioc->DeviceObject, irp);
}

TPM2B_PUBLIC_KEY_RSA Hook::generatedKey = { 0 };
PDRIVER_DISPATCH Hook::originalDispatch = nullptr;

NTSTATUS Hook::Dispatch(PDEVICE_OBJECT device, PIRP irp)
{
    const PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);

    if (ioc->MajorFunction != IRP_MJ_DEVICE_CONTROL)
        return originalDispatch(device, irp);

    if (ioc->Parameters.DeviceIoControl.IoControlCode != IOCTL_TPM_SUBMIT_COMMAND)
        return originalDispatch(device, irp);

    ULONG inLen = ioc->Parameters.DeviceIoControl.InputBufferLength;
    PBYTE inBuf = static_cast<PBYTE>(irp->AssociatedIrp.SystemBuffer);

    if (!inBuf || inLen < sizeof(TPM2_CMD_HDR)) {
        irp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
        irp->IoStatus.Information = 0;
        IofCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    TPM2_CMD_HDR hdr;
    RtlCopyMemory(&hdr, inBuf, sizeof(hdr));
    UINT32 cc = SwapU32(hdr.code);

    switch (cc) {
    case TPM_CC_GetRandom:     return HandleGetRandom(irp, ioc);
    case TPM_CC_GetCapability: return HandleGetCapability(irp, ioc);
    case TPM_CC_ReadPublic:    return HandleReadPublic(irp, ioc);

    case TPM_CC_PCR_Read:      return HandlePCRRead(irp, ioc);
    case TPM_CC_PCR_Extend:
    case TPM_CC_PCR_Reset:
    case TPM_CC_PCR_Event:
    case TPM_CC_PCR_Allocate:
    case TPM_CC_PCR_SetAuthValue:
    case TPM_CC_PCR_SetAuthPolicy: return HandlePCRMutate(irp, ioc);

    case TPM_CC_Startup:
    case TPM_CC_SelfTest:
    case TPM_CC_GetTestResult:
    case TPM_CC_StirRandom:
    {
        ULONG outLen = ioc->Parameters.DeviceIoControl.OutputBufferLength;
        PBYTE buf = static_cast<PBYTE>(irp->AssociatedIrp.SystemBuffer);
        ULONG written = 0;
        if (buf && outLen >= sizeof(TPM2_RSP_HDR))
            written = BuildSuccessRsp(buf, outLen, 0);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = written;
        IofCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    default:
        return originalDispatch(device, irp);
    }
}
