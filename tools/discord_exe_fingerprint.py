#!/usr/bin/env python3
"""
Discord Native Executable Fingerprint Extractor, Synthesizer & Decryptor
=========================================================================
Exact bit-for-bit Python port of Discord's native anti-fraud module (`discord_utils.node`):
  - `sub_a3990` (RVA 0xA3990): PE64 header/section parser & SHA-256collector
  - `sub_a3890` (RVA 0xA3890): Registry reader for HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid
  - `sub_a3f60` (RVA 0xA3F60): Hardware binding SHA256(MachineGuid || userId)
  - `sub_a4120` (RVA 0xA4120): WinVerifyTrust + CryptQueryObject + CertGetNameStringW + CryptHashPublicKeyInfo
  - `sub_a35c0` (RVA 0xA35C0): XOR key derivation SHA256(userId + "https://discord.com/careers")
  - `sub_1350`  (RVA 0x01350): 146-byte (0x92) binary packet packer & stream XOR cipher
  - `sub_116790`(RVA 0x116790): 196-character Base64 encoder

Usage:
  python discord_exe_fingerprint.py --exe "C:\\Windows\\explorer.exe" --user-id 123456789012345678
  python discord_exe_fingerprint.py --synthesize "D:\\Games\\CS2\\game\\bin\\win64\\cs2.exe" --publisher "Valve Corp." --user-id 123456789012345678
  python discord_exe_fingerprint.py --decrypt "<196-char-base64>" --user-id 123456789012345678
"""

from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json
import os
import struct
import sys
from typing import Optional

DISCORD_CAREERS_SALT = "https://discord.com/careers"
PACKET_SIZE = 0x92  # 146 bytes -> 196 Base64 chars

# Real Authenticode SubjectPublicKeyInfo SHA-256 digests extracted via WinVerifyTrust + CryptHashPublicKeyInfo (sub_a4120)
REAL_PUBLISHER_SPKI_SHA256: dict[str, str] = {
    "Valve Corp.": "371a0623e9c19d00bbb1e738b4733455dc76db156b54396d0ea258d3fcd0cbb2",
    "Microsoft Corporation": "8d79b51d140a92816a138dcba36f41720b3ce5063718cfbc4ad77efde8315a4d",
    "Epic Games Inc.": "2793b500911bdee5ff0ebdcb308122751a50bacd6dfecd462a2ff0d6f1d980eb",
    "Epic Games, Inc.": "2793b500911bdee5ff0ebdcb308122751a50bacd6dfecd462a2ff0d6f1d980eb",
    "Grinding Gear Games Limited": "4a7d34305a2f2d4d80468c26c2a577c12b7c0f75fa259831e437d2dca4db1e26",
    "BATTLESTATE GAMES LIMITED": "9f2bb2c2b8be0d67edbd1d8ef7c1975b01b167240532992803a1db5d11630271",
    "BattlEye Innovations e.K.": "1bfadddd1286fda141b960b44981fab55f9fe19c47330ea65821b8a6ae6e04d1",
    "Unity Technologies SF": "9a77d26b6e94916aab4e95449b74ef791b018c9f23c24fd6d1359a92d439427d",
    "Discord Inc.": "019f6eae63414925d0d85965c4f4af0eabec52dfb171c39d253ba5f19498c095",
}

# Real signed PE64 binary header/section profiles extracted via sub_a3990
REAL_PE_PROFILES: dict[str, dict] = {
    "win64/cs2.exe": {
        "publisher_cn": "Valve Corp.",
        "file_size": 2968216,
        "time_date_stamp": 1780353039,
        "size_of_image": 4399104,
        "hdr_sha256": "70ee27820eb88028bd01c71ab6ad481845b0f986e279e180a73348c1eb4ccdbd",
        "sec_sha256": "e4753bcf81bbf6e588a138f9de2754d750bd5f8f6306ef971456ed67288ea0de",
    },
    "path of exile/pathofexilesteam.exe": {
        "publisher_cn": "Grinding Gear Games Limited",
        "file_size": 79345496,
        "time_date_stamp": 1788480744,
        "size_of_image": 81326080,
        "hdr_sha256": "701cd4cc5340283e472bb3bb8c533c93437e63d2e416720d82fcb7606d915df1",
        "sec_sha256": "8587c9700969c5d30caf6fd7dda44975f252a6a8a055d07b1a6e563bacab9a2d",
    },
    "arena/escapefromtarkovarena.exe": {
        "publisher_cn": "BATTLESTATE GAMES LIMITED",
        "file_size": 3243360,
        "time_date_stamp": 1778746394,
        "size_of_image": 684032,
        "hdr_sha256": "e809d7e33272567b5d2525f324cf5bd33555471e080b46df8c58d26590e21883",
        "sec_sha256": "c602de1c1277db5de20b3753cd0074071fedc69bdca6f5f0a4b8b1661d3d7d9b",
    },
    "age of empires iv/gpuburner.exe": {
        "publisher_cn": "Microsoft Corporation",
        "file_size": 51616064,
        "time_date_stamp": 1784151922,
        "size_of_image": 62803968,
        "hdr_sha256": "c602ddeb51b4a9da0a13019ab812b6e6db1454ebf0777ec227e3a3e8c5e12852",
        "sec_sha256": "91b3b7032e0a9d3a1cb476092213ca1cbf323617e344b3e0d9dff4ec686a7f69",
    },
    "age of empires iv/essenceeditor.exe": {
        "publisher_cn": "Microsoft Corporation",
        "file_size": 10231608,
        "time_date_stamp": 3813183688,
        "size_of_image": 10231808,
        "hdr_sha256": "a25ba2a7621664f67ea7f861471098150dea3e874ff2f5fa875d2d3708cdf925",
        "sec_sha256": "52b2292823de3571a3d64eba977f923a30e7bd16b9b003c6beec694a2c4778e2",
    },
    "win64/vconsole2.exe": {
        "publisher_cn": "Valve Corp.",
        "file_size": 4901016,
        "time_date_stamp": 1760055276,
        "size_of_image": 5709824,
        "hdr_sha256": "cda2926ecca1eb1b53a0b1421c1969b461d08748d900c2e7c1fda332086c3556",
        "sec_sha256": "5ae151258e7abe392da4ecef7855e6a51c1d9422a88b6ccd352f50835458e743",
    },
    "steam/steam.exe": {
        "publisher_cn": "Valve Corp.",
        "file_size": 5823128,
        "time_date_stamp": 1792617103,
        "size_of_image": 7430144,
        "hdr_sha256": "e8bcb8fce00b9a29b1d5fca5e01607cdd06ba30329bc605994dced5d0741c196",
        "sec_sha256": "476550e4d464edbaf9bdd27f609247f699e72e8db60b37fbf5b72f192b06062b",
    },
}


# ============================================================================
# Windows CryptoAPI / WinTrust ctypes definitions (for exact sub_a4120 port)
# ============================================================================
if sys.platform == "win32":
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(GUID)),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    class CRYPTOAPI_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    class CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
        _fields_ = [
            ("pszObjId", ctypes.c_char_p),
            ("Parameters", CRYPTOAPI_BLOB),
        ]

    class CRYPT_BIT_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
            ("cUnusedBits", wintypes.DWORD),
        ]

    class CERT_PUBLIC_KEY_INFO(ctypes.Structure):
        _fields_ = [
            ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("PublicKey", CRYPT_BIT_BLOB),
        ]

    class FILETIME(ctypes.Structure):
        _fields_ = [
            ("dwLowDateTime", wintypes.DWORD),
            ("dwHighDateTime", wintypes.DWORD),
        ]

    class CERT_INFO(ctypes.Structure):
        _fields_ = [
            ("dwVersion", wintypes.DWORD),
            ("SerialNumber", CRYPTOAPI_BLOB),
            ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("Issuer", CRYPTOAPI_BLOB),
            ("NotBefore", FILETIME),
            ("NotAfter", FILETIME),
            ("Subject", CRYPTOAPI_BLOB),
            ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
            ("IssuerUniqueId", CRYPT_BIT_BLOB),
            ("SubjectUniqueId", CRYPT_BIT_BLOB),
            ("cExtension", wintypes.DWORD),
            ("rgExtension", ctypes.c_void_p),
        ]

    class CERT_CONTEXT(ctypes.Structure):
        _fields_ = [
            ("dwCertEncodingType", wintypes.DWORD),
            ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
            ("cbCertEncoded", wintypes.DWORD),
            ("pCertInfo", ctypes.POINTER(CERT_INFO)),
            ("hCertStore", ctypes.c_void_p),
        ]

    class CMSG_SIGNER_INFO(ctypes.Structure):
        _fields_ = [
            ("dwVersion", wintypes.DWORD),
            ("Issuer", CRYPTOAPI_BLOB),
            ("SerialNumber", CRYPTOAPI_BLOB),
            ("HashAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("HashEncryptionAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("EncryptedHash", CRYPTOAPI_BLOB),
            ("AuthAttrs", ctypes.c_ubyte * 16),
            ("UnauthAttrs", ctypes.c_ubyte * 16),
        ]


@dataclass
class AuthenticodeResult:
    is_signed: bool
    publisher_cn: str
    spki_sha256: str
    cert_sha256: bytes


@dataclass
class DecryptedFingerprint:
    version: int
    flags: int
    is_signed: bool
    is_pe64: bool
    file_size: int
    time_date_stamp: int
    compile_time_utc: str
    size_of_image: int
    hdr_sha256: str
    hw_sha256: str
    sec_sha256: str
    cert_sha256: str
    hw_matches_local_machine: Optional[bool]


def get_machine_guid() -> str:
    """Port of sub_a3890: Reads HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid."""
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "MachineGuid")
                if isinstance(val, str) and val.strip():
                    return val.strip()
        except Exception:
            pass
    return "a1b2c3d4-e5f6-4789-abcd-ef0123456789"


def derive_xor_key(user_id: str) -> bytes:
    """Port of sub_a35c0: SHA256(userId + 'https://discord.com/careers')."""
    return hashlib.sha256((str(user_id) + DISCORD_CAREERS_SALT).encode("utf-8")).digest()


def compute_hw_sha256(machine_guid: str, user_id: str) -> bytes:
    """Port of sub_a3f60: SHA256(MachineGuid + userId)."""
    if not machine_guid:
        return b"\x00" * 32
    return hashlib.sha256((machine_guid + str(user_id)).encode("utf-8")).digest()


def extract_authenticode_win32(exe_path: str) -> AuthenticodeResult:
    """
    Exact port of sub_a4120 (RVA 0xA4120 in discord_utils.node):
      1. WinVerifyTrust(NULL, &WINTRUST_ACTION_GENERIC_VERIFY_V2, &wtd) with WTD_CACHE_ONLY_URL_RETRIEVAL (0x1000)
      2. CryptQueryObject(CERT_QUERY_OBJECT_FILE, exe_path, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, ...)
      3. CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM=6, 0, ...)
      4. CertFindCertificateInStore(hStore, 0x10001, 0, CERT_FIND_SUBJECT_CERT=0xB0000, &certInfo, NULL)
      5. CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE=4, 0, NULL, ...)
      6. CryptHashPublicKeyInfo(NULL, CALG_SHA_256=0x800c, 0, 0x10001, &pCertInfo->SubjectPublicKeyInfo, ...)
      7. SHA256(UTF8(Publisher_CN) || SPKI_SHA256)
    """
    if sys.platform != "win32" or not os.path.isfile(exe_path):
        return AuthenticodeResult(False, "", "", b"\x00" * 32)

    abs_path = os.path.abspath(exe_path)

    # Step 1: WinVerifyTrust (0x1800a41a0..0x1800a4242)
    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = abs_path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    wtd = WINTRUST_DATA()
    wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wtd.dwUIChoice = 2               # WTD_UI_NONE
    wtd.fdwRevocationChecks = 0      # WTD_REVOKE_NONE
    wtd.dwUnionChoice = 1            # WTD_CHOICE_FILE
    wtd.pFile = ctypes.pointer(file_info)
    wtd.dwStateAction = 0            # WTD_STATEACTION_IGNORE
    wtd.dwProvFlags = 0x1000         # WTD_CACHE_ONLY_URL_RETRIEVAL

    status = wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wtd))
    if status != 0:
        return AuthenticodeResult(False, "", "", b"\x00" * 32)

    # Step 2: CryptQueryObject (0x1800a4349..0x1800a4365)
    hStore = ctypes.c_void_p()
    hMsg = ctypes.c_void_p()
    dwEncoding = wintypes.DWORD()
    dwContentType = wintypes.DWORD()
    dwFormatType = wintypes.DWORD()

    ok = crypt32.CryptQueryObject(
        1,       # CERT_QUERY_OBJECT_FILE
        ctypes.c_wchar_p(abs_path),
        0x400,   # CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED
        2,       # CERT_QUERY_FORMAT_FLAG_BINARY
        0,
        ctypes.byref(dwEncoding),
        ctypes.byref(dwContentType),
        ctypes.byref(dwFormatType),
        ctypes.byref(hStore),
        ctypes.byref(hMsg),
        None,
    )
    if not ok or not hMsg.value or not hStore.value:
        return AuthenticodeResult(False, "", "", b"\x00" * 32)

    pCertContext_ptr = None
    try:
        # Step 3: CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM=6)
        cbSignerInfo = wintypes.DWORD(0)
        if not crypt32.CryptMsgGetParam(hMsg, 6, 0, None, ctypes.byref(cbSignerInfo)) or cbSignerInfo.value == 0:
            return AuthenticodeResult(False, "", "", b"\x00" * 32)

        signer_buf = (ctypes.c_ubyte * cbSignerInfo.value)()
        if not crypt32.CryptMsgGetParam(hMsg, 6, 0, signer_buf, ctypes.byref(cbSignerInfo)):
            return AuthenticodeResult(False, "", "", b"\x00" * 32)

        signer_info = ctypes.cast(signer_buf, ctypes.POINTER(CMSG_SIGNER_INFO)).contents

        # Step 4: CertFindCertificateInStore(hStore, 0x10001, 0, CERT_FIND_SUBJECT_CERT=0xB0000, &cert_info, NULL)
        lookup_cert = CERT_INFO()
        lookup_cert.Issuer = signer_info.Issuer
        lookup_cert.SerialNumber = signer_info.SerialNumber

        crypt32.CertFindCertificateInStore.restype = ctypes.POINTER(CERT_CONTEXT)
        pCertContext_ptr = crypt32.CertFindCertificateInStore(
            hStore,
            0x10001,   # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
            0,
            0xB0000,   # CERT_FIND_SUBJECT_CERT
            ctypes.byref(lookup_cert),
            None,
        )
        if not pCertContext_ptr:
            return AuthenticodeResult(False, "", "", b"\x00" * 32)

        # At 0x1800a44b9: byte ptr [rsi] = 1 (is_signed = 1)
        is_signed = True

        # Step 5: CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE=4, 0, NULL, ...)
        cchName = crypt32.CertGetNameStringW(pCertContext_ptr, 4, 0, None, None, 0)
        if cchName == 0:
            return AuthenticodeResult(is_signed, "", "", b"\x00" * 32)

        name_buf = ctypes.create_unicode_buffer(cchName)
        crypt32.CertGetNameStringW(pCertContext_ptr, 4, 0, None, name_buf, cchName)
        publisher_cn = name_buf.value
        publisher_utf8 = publisher_cn.encode("utf-8")

        # Step 6: CryptHashPublicKeyInfo(NULL, CALG_SHA_256=0x800c, 0, 0x10001, &pCertInfo->SubjectPublicKeyInfo, ...)
        spki_hash = (ctypes.c_ubyte * 32)()
        spki_len = wintypes.DWORD(32)
        cert_info_ptr = pCertContext_ptr.contents.pCertInfo
        crypt32.CryptHashPublicKeyInfo(
            None,
            0x800C,    # CALG_SHA_256
            0,
            0x10001,   # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
            ctypes.byref(cert_info_ptr.contents.SubjectPublicKeyInfo),
            spki_hash,
            ctypes.byref(spki_len),
        )
        spki_bytes = bytes(spki_hash[:32])

        # Step 7: SHA256(UTF8(Publisher_CN) || SPKI_SHA256) (0x1800a45e6..0x1800a4616)
        cert_sha256 = hashlib.sha256(publisher_utf8 + spki_bytes).digest()
        return AuthenticodeResult(True, publisher_cn, spki_bytes.hex(), cert_sha256)
    finally:
        if pCertContext_ptr:
            crypt32.CertFreeCertificateContext(pCertContext_ptr)
        if hStore.value:
            crypt32.CertCloseStore(hStore, 0)
        if hMsg.value:
            crypt32.CryptMsgClose(hMsg)


def pack_and_encrypt_sub_1350(
    *,
    is_signed: bool,
    is_pe64: bool,
    file_size: int,
    time_date_stamp: int,
    size_of_image: int,
    hdr_sha256: bytes,
    hw_sha256: bytes,
    sec_sha256: bytes,
    cert_sha256: bytes,
    user_id: str,
) -> str:
    """
    Exact port of sub_1350 (RVA 0x01350) + sub_116790 (RVA 0x116790):
    Packs the 146-byte (0x92) buffer, XORs bytes [1..145] with SHA256(userId + "https://discord.com/careers"),
    and returns the 196-character Base64 string.
    """
    packet = bytearray(PACKET_SIZE)
    packet[0x00] = 1  # Version 1 (unencrypted)
    flags = (1 if is_signed else 0) | (2 if is_pe64 else 0)
    packet[0x01] = flags
    struct.pack_into("<QII", packet, 0x02, file_size & 0xFFFFFFFFFFFFFFFF, time_date_stamp & 0xFFFFFFFF, size_of_image & 0xFFFFFFFF)
    packet[0x12:0x32] = hdr_sha256[:32].ljust(32, b"\x00")
    packet[0x32:0x52] = hw_sha256[:32].ljust(32, b"\x00")
    packet[0x52:0x72] = sec_sha256[:32].ljust(32, b"\x00")
    packet[0x72:0x92] = cert_sha256[:32].ljust(32, b"\x00")

    xor_key = derive_xor_key(user_id)
    for i in range(1, PACKET_SIZE):
        packet[i] ^= xor_key[(i - 1) & 0x1F]

    return base64.b64encode(bytes(packet)).decode("ascii")


def generate_from_exe(
    exe_path: str,
    user_id: str,
    machine_guid: Optional[str] = None,
    force_signed_publisher: Optional[str] = None,
) -> tuple[str, dict]:
    """
    Exact port of sub_a3990:
    Reads a real .exe from disk, parses PE headers/sections, verifies Authenticode via sub_a4120,
    and produces the exact 196-char Base64 executableFingerprint.
    """
    if not os.path.isfile(exe_path):
        raise FileNotFoundError(f"Executable not found: {exe_path}")

    file_size = os.path.getsize(exe_path)
    read_len = min(file_size, 0x10000)
    with open(exe_path, "rb") as f:
        buf = f.read(read_len)

    if len(buf) < 0x40 or struct.unpack_from("<H", buf, 0)[0] != 0x5A4D:
        raise ValueError(f"Not a valid MZ executable: {exe_path}")

    e_lfanew = struct.unpack_from("<i", buf, 0x3C)[0]
    if e_lfanew < 0 or e_lfanew + 0x108 > len(buf):
        raise ValueError("Invalid e_lfanew offset in PE header")

    pe_sig = struct.unpack_from("<I", buf, e_lfanew)[0]
    if pe_sig != 0x00004550:
        raise ValueError("Missing PE\\0\\0 signature")

    num_sections = struct.unpack_from("<H", buf, e_lfanew + 6)[0]
    time_date_stamp = struct.unpack_from("<I", buf, e_lfanew + 8)[0]
    size_of_opt_hdr = struct.unpack_from("<H", buf, e_lfanew + 0x14)[0]
    opt_magic = struct.unpack_from("<H", buf, e_lfanew + 0x18)[0]
    size_of_image = struct.unpack_from("<I", buf, e_lfanew + 0x50)[0]
    is_pe64 = opt_magic == 0x020B

    # 0x1800a3cb3..0x1800a3cd2: hdr_sha256
    hdr_end = min(len(buf), e_lfanew + 0x18 + size_of_opt_hdr)
    hdr_sha256 = hashlib.sha256(buf[:hdr_end]).digest()

    # 0x1800a3cd7..0x1800a3d16: sec_sha256
    sec_start = e_lfanew + 0x18 + size_of_opt_hdr
    sec_end = sec_start + num_sections * 40
    if sec_end <= len(buf):
        sec_sha256 = hashlib.sha256(buf[sec_start:sec_end]).digest()
    else:
        sec_sha256 = b"\x00" * 32

    m_guid = machine_guid if machine_guid is not None else get_machine_guid()
    hw_sha256 = compute_hw_sha256(m_guid, user_id)

    auth = extract_authenticode_win32(exe_path)
    if force_signed_publisher and not auth.is_signed:
        known_spki = REAL_PUBLISHER_SPKI_SHA256.get(force_signed_publisher)
        spki_bytes = (
            bytes.fromhex(known_spki)
            if known_spki
            else hashlib.sha256(f"AUTHENTICODE_SPKI_RSA4096:{force_signed_publisher}".encode("utf-8")).digest()
        )
        cert_raw_cn = "Epic Games Inc." if force_signed_publisher == "Epic Games, Inc." else force_signed_publisher
        cert_sha256 = hashlib.sha256(cert_raw_cn.encode("utf-8") + spki_bytes).digest()
        auth = AuthenticodeResult(True, cert_raw_cn, spki_bytes.hex(), cert_sha256)

    fp_b64 = pack_and_encrypt_sub_1350(
        is_signed=auth.is_signed,
        is_pe64=is_pe64,
        file_size=file_size,
        time_date_stamp=time_date_stamp,
        size_of_image=size_of_image,
        hdr_sha256=hdr_sha256,
        hw_sha256=hw_sha256,
        sec_sha256=sec_sha256,
        cert_sha256=auth.cert_sha256,
        user_id=user_id,
    )
    meta = {
        "exe_path": os.path.abspath(exe_path),
        "quest_executable_path": format_quest_executable_path(exe_path),
        "is_signed": auth.is_signed,
        "publisher_cn": auth.publisher_cn,
        "spki_sha256": auth.spki_sha256,
        "is_pe64": is_pe64,
        "file_size": file_size,
        "time_date_stamp": time_date_stamp,
        "size_of_image": size_of_image,
        "hdr_sha256": hdr_sha256.hex(),
        "hw_sha256": hw_sha256.hex(),
        "sec_sha256": sec_sha256.hex(),
        "cert_sha256": auth.cert_sha256.hex(),
        "executable_fingerprint": fp_b64,
    }
    return fp_b64, meta


def synthesize_fingerprint(
    exe_path: str,
    user_id: str,
    publisher_cn: str = "Valve Corp.",
    machine_guid: Optional[str] = None,
) -> tuple[str, dict]:
    """
    Synthesizes a deterministic, cryptographically valid 196-char signed PE64 executableFingerprint
    using real WinVerifyTrust Authenticode SPKI/cert digests and real PE profiles when available.
    """
    quest_path = format_quest_executable_path(exe_path)
    profile = REAL_PE_PROFILES.get(quest_path)
    if profile:
        publisher_cn = profile["publisher_cn"]
        file_size = profile["file_size"]
        time_date_stamp = profile["time_date_stamp"]
        size_of_image = profile["size_of_image"]
        hdr_sha256 = bytes.fromhex(profile["hdr_sha256"])
        sec_sha256 = bytes.fromhex(profile["sec_sha256"])
    else:
        norm_seed = f"{exe_path.lower()}|{publisher_cn}"
        seed_hash = hashlib.sha256(norm_seed.encode("utf-8")).digest()
        s0, s1, s2, s3 = struct.unpack_from("<IIII", seed_hash, 0)

        base_mb = 48 + (s0 % 92)
        extra_bytes = (s1 % 1024) * 512
        file_size = base_mb * 1024 * 1024 + extra_bytes
        time_date_stamp = (1704067200 + (s2 % 55000000)) & 0xFFFFFFFF
        pages = 0x3800 + ((s3 & 0xFFFF) % 0x4000)
        size_of_image = (pages * 0x1000) & 0xFFFFFFFF

        hdr_sha256 = hashlib.sha256(f"PE_HEADERS_V1:{norm_seed}:{time_date_stamp}:{size_of_image}".encode("utf-8")).digest()
        sec_sha256 = hashlib.sha256(f"PE_SECTIONS_V1:{norm_seed}:{size_of_image}".encode("utf-8")).digest()

    m_guid = machine_guid if machine_guid is not None else get_machine_guid()
    hw_sha256 = compute_hw_sha256(m_guid, user_id)

    known_spki = REAL_PUBLISHER_SPKI_SHA256.get(publisher_cn)
    spki_sha256 = (
        bytes.fromhex(known_spki)
        if known_spki
        else hashlib.sha256(f"AUTHENTICODE_SPKI_RSA4096:{publisher_cn}".encode("utf-8")).digest()
    )
    cert_raw_cn = "Epic Games Inc." if publisher_cn == "Epic Games, Inc." else publisher_cn
    cert_sha256 = hashlib.sha256(cert_raw_cn.encode("utf-8") + spki_sha256).digest()

    fp_b64 = pack_and_encrypt_sub_1350(
        is_signed=True,
        is_pe64=True,
        file_size=file_size,
        time_date_stamp=time_date_stamp,
        size_of_image=size_of_image,
        hdr_sha256=hdr_sha256,
        hw_sha256=hw_sha256,
        sec_sha256=sec_sha256,
        cert_sha256=cert_sha256,
        user_id=user_id,
    )
    meta = {
        "exe_path": exe_path,
        "quest_executable_path": format_quest_executable_path(exe_path),
        "is_signed": True,
        "publisher_cn": publisher_cn,
        "spki_sha256": spki_sha256.hex(),
        "is_pe64": True,
        "file_size": file_size,
        "time_date_stamp": time_date_stamp,
        "size_of_image": size_of_image,
        "hdr_sha256": hdr_sha256.hex(),
        "hw_sha256": hw_sha256.hex(),
        "sec_sha256": sec_sha256.hex(),
        "cert_sha256": cert_sha256.hex(),
        "executable_fingerprint": fp_b64,
    }
    return fp_b64, meta


def decrypt_executable_fingerprint(
    fp_b64: str,
    user_id: str,
    machine_guid: Optional[str] = None,
) -> DecryptedFingerprint:
    """
    Decrypts any 196-character Discord executableFingerprint back into its 146-byte (0x92) struct fields.
    """
    raw = base64.b64decode(fp_b64)
    if len(raw) != PACKET_SIZE:
        raise ValueError(f"Expected {PACKET_SIZE} bytes (0x92), got {len(raw)} bytes")

    version = raw[0]
    xor_key = derive_xor_key(user_id)
    dec = bytearray(raw)
    for i in range(1, PACKET_SIZE):
        dec[i] ^= xor_key[(i - 1) & 0x1F]

    flags = dec[0x01]
    is_signed = bool(flags & 0x01)
    is_pe64 = bool(flags & 0x02)
    file_size, time_date_stamp, size_of_image = struct.unpack_from("<QII", dec, 0x02)
    hdr_sha256 = bytes(dec[0x12:0x32]).hex()
    hw_sha256 = bytes(dec[0x32:0x52]).hex()
    sec_sha256 = bytes(dec[0x52:0x72]).hex()
    cert_sha256 = bytes(dec[0x72:0x92]).hex()

    compile_dt = datetime.fromtimestamp(time_date_stamp, tz=timezone.utc).isoformat()
    m_guid = machine_guid if machine_guid is not None else get_machine_guid()
    expected_hw = compute_hw_sha256(m_guid, user_id).hex() if m_guid else None

    return DecryptedFingerprint(
        version=version,
        flags=flags,
        is_signed=is_signed,
        is_pe64=is_pe64,
        file_size=file_size,
        time_date_stamp=time_date_stamp,
        compile_time_utc=compile_dt,
        size_of_image=size_of_image,
        hdr_sha256=hdr_sha256,
        hw_sha256=hw_sha256,
        sec_sha256=sec_sha256,
        cert_sha256=cert_sha256,
        hw_matches_local_machine=(hw_sha256 == expected_hw) if expected_hw else None,
    )


def format_quest_executable_path(exe_path: str) -> str:
    """
    Port of Module 973522 `o.Ic(exePath)`:
    Normalizes slashes to '/', lowercases, strips trailing '/', and returns the last 2 segments.
    Example: 'C:\\Program Files\\Steam\\steamapps\\common\\CS2\\win64\\cs2.exe' -> 'win64/cs2.exe'
    """
    norm = exe_path.replace("\\", "/").lower().rstrip("/")
    parts = [p for p in norm.split("/") if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else norm


def main() -> None:
    parser = argparse.ArgumentParser(description="Discord sub_a3990 / sub_1350 executableFingerprint tool")
    parser.add_argument("--exe", help="Path to a real .exe file on disk to extract & sign")
    parser.add_argument("--synthesize", help="Virtual path of a game .exe to synthesize without disk binary")
    parser.add_argument("--publisher", default="Valve Corp.", help="Publisher CN for synthesis (default: 'Valve Corp.')")
    parser.add_argument("--decrypt", help="196-character Base64 executableFingerprint to decrypt and inspect")
    parser.add_argument("--user-id", default="123456789012345678", help="Discord Snowflake User ID")
    parser.add_argument("--machine-guid", default=None, help="Override Windows MachineGuid")
    parser.add_argument("--self-test", action="store_true", help="Run round-trip sub_1350 encryption/decryption self-test")
    args = parser.parse_args()

    if args.self_test:
        test_exe = r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe"
        fp, meta = synthesize_fingerprint(test_exe, args.user_id, args.publisher, args.machine_guid)
        dec = decrypt_executable_fingerprint(fp, args.user_id, args.machine_guid)
        assert len(fp) == 196, f"Expected 196-char Base64, got {len(fp)}"
        assert dec.version == 1, f"Expected un-XORed version=1 at [0x00], got {dec.version}"
        assert dec.flags == 0x03 and dec.is_signed and dec.is_pe64, f"Expected flags=0x03, got {dec.flags:#x}"
        assert dec.file_size == meta["file_size"], "file_size mismatch"
        assert dec.time_date_stamp == meta["time_date_stamp"], "time_date_stamp mismatch"
        assert dec.size_of_image == meta["size_of_image"], "size_of_image mismatch"
        assert dec.hdr_sha256 == meta["hdr_sha256"], "hdr_sha256 [0x12..0x31] mismatch"
        assert dec.hw_sha256 == meta["hw_sha256"], "hw_sha256 [0x32..0x51] mismatch"
        assert dec.sec_sha256 == meta["sec_sha256"], "sec_sha256 [0x52..0x71] mismatch"
        assert dec.cert_sha256 == meta["cert_sha256"], "cert_sha256 [0x72..0x91] mismatch"
        assert dec.hw_matches_local_machine is True, "hw_matches_local_machine failed"
        assert meta["quest_executable_path"] == "win64/cs2.exe", f"Unexpected quest path: {meta['quest_executable_path']}"
        print(json.dumps({"self_test": "PASSED", "executable_fingerprint": fp, "decrypted": asdict(dec)}, indent=2))
        return

    if args.decrypt:
        res = decrypt_executable_fingerprint(args.decrypt, args.user_id, args.machine_guid)
        print(json.dumps(asdict(res), indent=2))
        return

    if args.exe:
        fp, meta = generate_from_exe(args.exe, args.user_id, args.machine_guid)
        dec = decrypt_executable_fingerprint(fp, args.user_id, args.machine_guid)
        print(json.dumps({"generated": meta, "decrypted_verification": asdict(dec)}, indent=2))
        return

    if args.synthesize:
        fp, meta = synthesize_fingerprint(args.synthesize, args.user_id, args.publisher, args.machine_guid)
        dec = decrypt_executable_fingerprint(fp, args.user_id, args.machine_guid)
        print(json.dumps({"synthesized": meta, "decrypted_verification": asdict(dec)}, indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
