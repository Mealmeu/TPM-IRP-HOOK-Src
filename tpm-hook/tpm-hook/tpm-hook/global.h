#pragma once

#include <ntifs.h>
#include <minwindef.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include <bcrypt.h>
#include <stddef.h>
#include "tpm20.h"
#include "tpm_defines.h"
#include "utils.h"
#include "hook.h"

#define Log(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[TpmHook] " fmt "\n", ##__VA_ARGS__)
