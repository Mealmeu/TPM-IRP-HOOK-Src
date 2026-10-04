#!/usr/bin/env python3
"""
Run this script once to embed Mapper.exe and TpmSpoofer.sys into embedded_bins.h.
Place the script next to the src/ directory and run:
    python gen_embedded.py
"""

import hashlib
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT  = os.path.dirname(SCRIPT_DIR)

FILES = [
    (
        os.path.join(REPO_ROOT, "kdmapper", "kdmapper", "x64", "Debug", "Mapper.exe"),
        "g_mapper_data",
    ),
    (
        os.path.join(REPO_ROOT, "tpm-hook", "tpm-hook", "tpm-hook", "x64", "TpmSpoofer.sys"),
        "g_tpm_sys_data",
    ),
]

OUTPUT = os.path.join(SCRIPT_DIR, "src", "embedded_bins.h")

def to_c_array(path, varname):
    with open(path, "rb") as f:
        data = f.read()
    sha256 = hashlib.sha256(data).hexdigest()
    size   = len(data)

    lines = [
        f"// {os.path.basename(path)}  SHA-256: {sha256}",
        f"static const unsigned char {varname}[] = {{",
    ]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
    lines += [
        "};",
        f"static const size_t {varname}_size = {size};",
        f'static const char   {varname}_sha256[] = "{sha256}";',
        "",
    ]
    return "\n".join(lines)

def main():
    parts = [
        "#pragma once",
        "#include <stddef.h>",
        "",
    ]
    for path, varname in FILES:
        if not os.path.exists(path):
            print(f"ERROR: {path} not found", file=sys.stderr)
            sys.exit(1)
        print(f"Embedding {path} ...")
        parts.append(to_c_array(path, varname))

    with open(OUTPUT, "w") as f:
        f.write("\n".join(parts))
    print(f"Written: {OUTPUT}")

if __name__ == "__main__":
    main()
