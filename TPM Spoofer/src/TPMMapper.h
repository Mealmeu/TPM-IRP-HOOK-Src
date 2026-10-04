#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "Crypt32.lib")

using namespace std;

static string ComputeSHA256(const unsigned char* data, size_t size)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    string result;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return {};
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); return {};
    }
    if (!CryptHashData(hHash, data, static_cast<DWORD>(size), 0)) {
        CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return {};
    }

    BYTE hash[32]; DWORD hashLen = 32;
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        char hex[65];
        for (int i = 0; i < 32; i++)
            sprintf_s(hex + i * 2, 3, "%02x", hash[i]);
        result = hex;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

static bool DropBinary(const string& path, const unsigned char* data, size_t size,
                       const char* expectedSha256)
{
    string actual = ComputeSHA256(data, size);
    if (actual != expectedSha256) {
        cerr << "[-] Integrity check failed for " << path << endl;
        return false;
    }

    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "[-] CreateFile failed for " << path << " err=" << GetLastError() << endl;
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, data, static_cast<DWORD>(size), &written, nullptr);
    CloseHandle(hFile);

    if (!ok || written != static_cast<DWORD>(size)) {
        cerr << "[-] WriteFile failed for " << path << endl;
        return false;
    }
    return true;
}

void TPMMapper(const string& downloadPath)
{
#if __has_include("embedded_bins.h")
#  include "embedded_bins.h"

    string mapperPath = downloadPath + "\\Mapper.exe";
    string tpmPath    = downloadPath + "\\tpm.sys";

    if (!DropBinary(mapperPath, g_mapper_data, g_mapper_data_size, g_mapper_data_sha256)) return;
    if (!DropBinary(tpmPath,    g_tpm_sys_data, g_tpm_sys_data_size, g_tpm_sys_data_sha256)) return;

    string execCmd = "\"" + mapperPath + "\" \"" + tpmPath + "\"";
    system(execCmd.c_str());

    DeleteFileA(mapperPath.c_str());
    DeleteFileA(tpmPath.c_str());
#else
#  pragma message("WARNING: embedded_bins.h not found. Run gen_embedded.py to embed binaries.")
    cerr << "[-] embedded_bins.h not found. Run gen_embedded.py first." << endl;
#endif
}
